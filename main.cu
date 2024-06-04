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
    int N= 1000000;
    int length = 8;
    int nCrack = 1;
    int nTests = 5;

    uint64_t key = toUint64_T("aof3Ecp7");

    if (filesystem::exists(wordsPath) && !overwrite) {

        ifstream wordsFile(wordsPath);

        // create a vector with all the words in the specified file
        string pwd;
        vector<uint64_t> pwdList = {};
        while (getline(wordsFile, pwd)) {   // read file line by line
            pwdList.push_back(toUint64_T(pwd));

        }
        wordsFile.close();

        random_device rd;  // a seed source for the random number engine
        mt19937 gen(rd()); // mersenne_twister_engine seeded with rd()
        uniform_int_distribution<> distrib(0, static_cast<int>(pwdList.size()));

        vector<uint64_t> pwdToCrack = {};

        while (pwdToCrack.size() < nCrack * nTests){
            uint64_t toCrack =  pwdList[distrib(gen)];    // choose randomly from pwdList nCrack passwords to crack
            if(find(pwdToCrack.begin(), pwdToCrack.end(), toCrack) == pwdToCrack.end())
                pwdToCrack.push_back(toCrack);       // adds random pwd only if it's not already in the vector
        }

        cout << "------------------ Experiments parameters ------------------";
        cout << "\nSearch space: " << N;
        cout << "\nPasswords lengths: " << length;
        cout << "\nNumber of passwords to crack: " << nCrack;
        cout << "\nNumber of tests for each experiment: " << nTests;
        cout << "\n------------------ Sequential Experiment ------------------\n";


        vector<double> sTimes = {};
        for( int i = 0; i < nTests; i++){
            cout << "Cracking password " << endl;
            auto start = system_clock::now();
            sequentialCrack(vector<uint64_t>(pwdToCrack.begin() + i * nCrack, pwdToCrack.begin() + (i + 1) * nCrack),
                            pwdList, key);
            auto end = system_clock::now();
            auto seqElapsed = duration_cast<milliseconds>(end - start);
            sTimes.push_back((double)seqElapsed.count());
            cout << "Password cracked (" << sTimes.back() << " ms)" <<  endl;
        }

        double sAvg = accumulate(sTimes.begin(), sTimes.end(), 0.0) / (double)sTimes.size();
        cout << "Average time per experiment (ms): " << sAvg << endl;


    if (saveResults){
        ofstream resultsFile(resultsPath);  // creates and/or opens results file
        resultsFile << "------------------ Experiments parameters ------------------";
        resultsFile << "\nSearch space: " << N;
        resultsFile << "\nPasswords lengths: " << length;
        resultsFile << "\nNumber of passwords to crack: " << nCrack;
        resultsFile << "\nNumber of tests for each experiment: " << nTests;
        resultsFile << "\n------------------ Sequential Experiment ------------------";
        resultsFile << "\nAverage time per experiment (ms): " << sAvg;
    }
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
