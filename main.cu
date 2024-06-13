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
    int N = 1000000;
    int length = 8;
    int nCrack = 1;
    int nTests = 10;

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

        auto *pwdToCrack = new uint64_t[nCrack * nTests];

        for (int i = 0; i < nCrack * nTests; i++){
            pwdToCrack[i] =  pwdList[distrib(gen)];    // choose randomly from pwdList nCrack * nTests passwords to crack
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
            for(int idCrack = i * nCrack; idCrack < (i + 1) * nCrack; idCrack++){
                auto toCrack = desEncrypt(key, pwdToCrack[idCrack]);
                for(int j = 0; j < N; j++){
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
//        int blockSize = 1024;
//        uint64_t *d_pwdList = new uint64_t[N];
//        for (int i = 0; i < N; i++){
//            d_pwdList[i] = pwdList[i];
//        }
//
//        uint64_t *d_pwdToCrack = new uint64_t[nCrack];
//        for (int i = 0; i < nCrack; i++){
//            d_pwdToCrack[i] = pwdToCrack[i];
//        }
//
//        float f = 0.5;
//        float *h_f = new float [5];
//
//        float boh[5] = {0.1, 0.2, 0.3, 0.4, 0.5};
//        for(int i = 0; i < 5; i++){
//            h_f[i] = i + 0.5;
//        }
//
//
//        const int mmm[64] = {58, 50, 42, 34, 26, 18, 10, 2,
//                                        60, 52, 44, 36, 28, 20, 12, 4,
//                                        62, 54, 46, 38, 30, 22, 14, 6,
//                                        64, 56, 48, 40, 32, 24, 16, 8,
//                                        57, 49, 41, 33, 25, 17, 9, 1,
//                                        59, 51, 43, 35, 27, 19, 11, 3,
//                                        61, 53, 45, 37, 29, 21, 13, 5,
//                                        63, 55, 47, 39, 31, 23, 15, 7};
//
//        cudaMemcpyToSymbol(const_array, initialPerm, sizeof(int) * 5, 0, cudaMemcpyHostToDevice);
//
//        uint64_t *d_f;
//        cudaMalloc((void **)&d_f, sizeof(uint64_t)*5);
//        cudaMemcpy(d_f, d_pwdToCrack, sizeof(uint64_t )*5, cudaMemcpyHostToDevice);
//
//
//        // test_array<<<1, 5>>>(d_f, 5);
//
//        uint64_t *d_pwdL;
//        uint64_t *d_toCrack;
//        cudaMalloc((void **) &d_pwdL, sizeof(uint64_t) * 8);
//        cudaMalloc((void **) &d_toCrack, sizeof(uint64_t) * nCrack);
//
//        cudaMemcpy(d_pwdL, d_pwdToCrack, sizeof(uint64_t) * 8, cudaMemcpyHostToDevice);
//        cudaMemcpy(d_toCrack, d_toCrack, sizeof(uint64_t) * nCrack, cudaMemcpyHostToDevice);
//
//        parallelCrack(key, N, nCrack, blockSize);
//        crackPswd<<<1, 1>>>(d_f, d_f[0], key, N);
//
//        cudaDeviceSynchronize();


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
        free(pwdToCrack);
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
