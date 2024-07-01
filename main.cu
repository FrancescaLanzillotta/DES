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
#include "d_DES.cuh"
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
    bool saveResults = true;
    int N = 1000000;
    int length = 8;
    vector<int> blockSizes = {32, 64, 128, 256};
    int nCrack = 1000;
    int nTests = 10;

    uint64_t key = toUint64_T("a2kvt8rz");

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
        uniform_int_distribution<> distrib(0, N);



        vector<uint64_t*> tests;
        for(int idTest = 0; idTest < nTests; idTest++){
            auto test = new uint64_t[nCrack];
            for (int i = 0; i < nCrack; i++){
                test[i] = desEncrypt(key, pwdList[distrib(gen)]);
            }
            tests.push_back(test);

        }


        cout << "------------------ Experiments parameters ------------------";
        cout << "\nSearch space: " << N;
        cout << "\nPasswords lengths: " << length;
        cout << "\nNumber of passwords to crack: " << nCrack;
        cout << "\nBlock sizes to test: " << toString<int>(blockSizes);
        cout << "\nNumber of tests for each experiment: " << nTests;
        cout << "\n------------------ Sequential Experiment ------------------\n";


        vector<double> sTimes = {};
        for (auto &pwdToCrack: tests) {
            cout << "Test started " << endl;
            auto start = system_clock::now();

            for (int i = 0; i < nCrack; i++){
                for (int j = 0; j < N; j++){
                    if (pwdToCrack[i] == desEncrypt(key, pwdList[j]))
                        break;
                }
            }

            auto end = system_clock::now();
            auto seqElapsed = duration_cast<milliseconds>(end - start);
            sTimes.push_back((double)seqElapsed.count());
            printf("Passwords cracked ( %f ms)\n", sTimes.back());
        }
        double sAvg = accumulate(sTimes.begin(), sTimes.end(), 0.0) / (double)sTimes.size();
        printf("Average time per experiment (ms): %4.2f\n", sAvg);


        cout << "\n------------------ Parallel Experiment ------------------\n";


        vector<double> pAvg = {};
        vector<double> speedUps = {};
        for (auto &blockSize: blockSizes) {
            printf("Block size: %d\n", blockSize);
            vector<double> pTimes = {};
            for (auto &test: tests) {
                cout << "Test started" << endl;
                bool *found;
                auto start = system_clock::now();
                found = parallelCrack(pwdList, N, test, nCrack, key, blockSize);
                auto end = system_clock::now();
                auto parElapsed = duration_cast<milliseconds>(end - start);
                pTimes.push_back((double)parElapsed.count());
                printf("Passwords cracked ( %f ms)\n", pTimes.back());
                for(int i = 0; i < nCrack; i++){
                    if (!found[i])
                        printf("Error occurred");
                }
                free(found);
            }
            pAvg.push_back(accumulate(pTimes.begin(), pTimes.end(), 0.0) / (double)pTimes.size());
            speedUps.push_back(sAvg / pAvg.back());
            printf("\nAverage time per block size = %d: %4.2f \n", blockSize, pAvg.back());
            printf("\nSpeedup: %4.2fx\n", speedUps.back());

        }

        cout << "\nAverage time per experiments (ms): " << toString<double>(pAvg);
        cout << "\nSpeedups: " << toString<double>(speedUps);


        if (saveResults){
            ofstream resultsFile(resultsPath);  // creates and/or opens results file
            resultsFile << "------------------ Experiments parameters ------------------";
            resultsFile << "\nSearch space: " << N;
            resultsFile << "\nPasswords lengths: " << length;
            resultsFile << "\nNumber of passwords to crack: " << nCrack;
            resultsFile << "\nNumber of tests for each experiment: " << nTests;
            resultsFile << "\n------------------ Sequential Experiment ------------------";
            resultsFile << "\nAverage time per experiment (ms): " << sAvg;
            resultsFile << "\n------------------ Parallel Experiment ------------------";
            resultsFile << "\nBlock sizes tested: " << toString(blockSizes);
            resultsFile << "\nAverage time per experiments (ms): " << toString(pAvg);
            resultsFile << "\nSpeedups: " << toString(speedUps);
        }
        free(pwdList);
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
