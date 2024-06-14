#include <iostream>
#include <string>
#include <random>
#include <filesystem>
#include <fstream>
#include <cstdint>
#include <chrono>
#include <sstream>
#include <numeric>
#include "utils.h"
#include "DES.h"
#include "c_DES.cuh"
using namespace constants;
using namespace std;
using namespace chrono;

int main() {
    string wordsPath = R"(C:\Users\franc\CLionProjects\DES\words.txt)";

    auto t = std::time(nullptr);
    auto tm = *std::localtime(&t);

    std::ostringstream ss;
    ss << std::put_time(&tm, "%Y%m%d-%H%M%S");
    auto str = ss.str();


    string resultsPath = R"(C:\Users\franc\CLionProjects\DES\results\results-)" + ss.str() + ".txt"; // results files have a timestamp

    bool overwrite = false;
    bool saveResults = false;
    int N = 1000000;
    int length = 8;
    int nCrack = 10;
    int nTests = 1;

    uint64_t key = toUint64_T("aof3Ecp7");

    if (filesystem::exists(wordsPath) && !overwrite) {

        ifstream wordsFile(wordsPath);

        // create a vector with all the words in the specified file
        string pwd;
        int pwdCount = 0;
        auto *pwdList = new uint64_t [N];
        while (getline(wordsFile, pwd) && pwdCount < N) {   // read file line by line
            pwdList[pwdCount] = toUint64_T(pwd);
            pwdCount++;
        }
        wordsFile.close();

        random_device rd;  // a seed source for the random number engine
        mt19937 gen(rd()); // mersenne_twister_engine seeded with rd()
        //gen.seed(42);
        uniform_int_distribution<> distrib(0, N);

        vector<uint64_t*> tests;
        for(int idTest = 0; idTest < nTests; idTest++){
            auto test = new uint64_t[nCrack];
            for (int i = 0; i < nCrack; i++){
                test[i] = pwdList[distrib(gen)];
            }
            tests.push_back(test);

        }


        cout << "------------------ Experiments parameters ------------------";
        cout << "\nSearch space: " << N;
        cout << "\nPasswords lengths: " << length;
        cout << "\nNumber of passwords to crack: " << nCrack;
        cout << "\nNumber of tests for each experiment: " << nTests;
        cout << "\n------------------ Sequential Experiment ------------------\n";


        vector<double> sTimes = {};
        for (auto &test: tests) {
            cout << "Cracking password " << endl;
            auto start = system_clock::now();
            for (int i = 0; i < nCrack; i++){
                auto toCrack = desEncrypt(key, test[i]);
                for (int j = 0; j < N; j++){
                    if (toCrack == desEncrypt(key, pwdList[j]))
                        break;
                }
            }
            auto end = system_clock::now();
            auto seqElapsed = duration_cast<milliseconds>(end - start);
            sTimes.push_back((double)seqElapsed.count());
            cout << "Password cracked (" << sTimes.back() << " ms)" <<  endl;
        }
        double sAvg = accumulate(sTimes.begin(), sTimes.end(), 0.0) / (double)sTimes.size();
        cout << "Average time per experiment (ms): " << sAvg << endl;


        cout << "\n------------------ Parallel Experiment ------------------\n";
        int blockSize = 256;

        cout << "Block size: " << blockSize;

        for (auto &test: tests) {
            parallelCrack(pwdList, N, test, nCrack, key, blockSize);
        }


        if (saveResults){
            ofstream resultsFile(resultsPath);  // creates and/or opens results file
            resultsFile << "------------------ Experiments parameters ------------------";
            resultsFile << "\nSearch space: " << N;
            resultsFile << "\nPasswords lengths: " << length;
            resultsFile << "\nNumber of passwords to crack: " << nCrack;
            resultsFile << "\nNumber of tests for each experiment: " << nTests;
            resultsFile << "\n------------------ Sequential Experiment ------------------";
            //resultsFile << "\nAverage time per experiment (ms): " << sAvg;
            resultsFile << "\n------------------ Parallel Experiment ------------------";
        }
        free(pwdList);
        //free(pwdToCrack);
    } else {
        vector<string> words = wordsGeneration(N, length);
        ofstream wordsFile(wordsPath);

        for(const auto& word : words){
            wordsFile << word << "\n";
        }
        wordsFile.close();
        cout << "New word file created" << endl;

    }


    return 0;
}
