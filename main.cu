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

__constant__ int d_initialPerm[BLOCK];
__constant__ int d_finalPerm[BLOCK];
__constant__ int d_expansion[ROUND_KEY];
__constant__ int d_hS1[BLOCK];
__constant__ int d_hS2[BLOCK];
__constant__ int d_hS3[BLOCK];
__constant__ int d_hS4[BLOCK];
__constant__ int d_hS5[BLOCK];
__constant__ int d_hS6[BLOCK];
__constant__ int d_hS7[BLOCK];
__constant__ int d_hS8[BLOCK];
__constant__ int *d_hS[8] = {
        d_hS1, d_hS2, d_hS3, d_hS4, d_hS5, d_hS6, d_hS7, d_hS8};
__constant__ int d_permutation[HALF_BLOCK];
__constant__ int d_permutedChoice1[56];
__constant__ int d_permutedChoice2[ROUND_KEY];
__constant__ int d_keyShiftArray[ROUNDS];

template<size_t FROM, size_t TO>
__device__ static auto d_permute(uint64_t source, const int* table) -> uint64_t{
    uint64_t  p = 0;
    for(size_t i = 0; i < TO; i++)
        p |= ( (source >> (FROM-table[i])) & 1) << (TO-1-i);
    return p;
}

__device__ __forceinline__
uint64_t d_feistelFunction(uint64_t subkey, uint64_t bits){
    // Expansion
    uint64_t exp = d_permute<HALF_BLOCK, ROUND_KEY>(bits, d_expansion);
    // Key mixing
    subkey = subkey ^ exp;
    // Substitution
    exp = 0;
    for(int j = 8-1; j >= 0; j--)
    {
        uint8_t block = (subkey >> (j) * 6);
        auto row = ((block & 0b100000) >> 4) | (block & 1);
        auto col = (block & 0b011110) >> 1;
        exp |= uint32_t(d_hS[8 - 1 - j][row * 16 + col]) << ((j) * 4);
    }

    return d_permute<HALF_BLOCK, HALF_BLOCK>(exp, d_permutation);;
}


__device__ __forceinline__
uint64_t d_desEncrypt(uint64_t key56, uint64_t message){
    // Initial permutation
    uint64_t ip = d_permute<BLOCK, BLOCK>(message, d_initialPerm);

    // Split in two halves
    uint32_t lhs = (ip >> HALF_BLOCK),
            rhs = ip;


    // Rounds, with subkey generation
    key56 = d_permute<BLOCK, 56>(key56, d_permutedChoice1);

    uint32_t lhs_rk = (key56 >> 28) & 0xfffffff;
    uint32_t rhs_rk = (key56) & 0xfffffff;

    for(int shift : d_keyShiftArray){

        lhs_rk = (lhs_rk << shift) | (lhs_rk >> (28 - shift));
        rhs_rk = (rhs_rk << shift) | (rhs_rk >> (28 - shift));
        lhs_rk &= 0xfffffff;
        rhs_rk &= 0xfffffff;

        uint64_t roundKey = (uint64_t(lhs_rk) << 28) | rhs_rk;

        roundKey = d_permute<56, ROUND_KEY>(roundKey, d_permutedChoice2);


        uint64_t feistel = d_feistelFunction(roundKey, rhs);

        auto old_lhs = lhs;
        lhs = rhs;
        rhs = old_lhs ^ feistel;

    }

    message = (uint64_t(rhs) << HALF_BLOCK) | lhs;
    // Final permutation
    ip = d_permute<BLOCK, BLOCK>(message, d_finalPerm);
    return ip;
}

__global__
void kernelCrack(const uint64_t *pwdList, int nPwd, const uint64_t *pwdToCrack, int nCrack, uint64_t key){
    int tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid < nPwd){
        uint64_t e = d_desEncrypt(key, pwdList[tid]);
        for(int i = 0; i < nCrack; i++){
            uint64_t c = d_desEncrypt(key, pwdToCrack[i]);
            if (e == c)
                printf("Thread-%d found password %d\n", tid, i);
        }
    }
}
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
    int nCrack = 5;
    int nTests = 5;

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
//        auto *pwdToCrack = new uint64_t[nCrack * nTests];
//
//        for (int i = 0; i < nCrack * nTests; i++){
//            pwdToCrack[i] =  pwdList[distrib(gen)];    // choose randomly from pwdList nCrack * nTests passwords to crack
//        }

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

//        for( int i = 0; i < nTests; i++){
//            cout << "Cracking password " << endl;
//            auto start = system_clock::now();
//            for(int idCrack = i * nCrack; idCrack < (i + 1) * nCrack; idCrack++){
//                auto toCrack = desEncrypt(key, pwdToCrack[idCrack]);
//                for(int j = 0; j < N; j++){
//                    if (toCrack == desEncrypt(key, pwdList[j]))
//                        break;
//                }
//            }
//            auto end = system_clock::now();
//            auto seqElapsed = duration_cast<milliseconds>(end - start);
//            sTimes.push_back((double)seqElapsed.count());
//            cout << "Password cracked (" << sTimes.back() << " ms)" <<  endl;
//        }
//
//        double sAvg = accumulate(sTimes.begin(), sTimes.end(), 0.0) / (double)sTimes.size();
//        cout << "Average time per experiment (ms): " << sAvg << endl;

        cout << "\n------------------ Parallel Experiment ------------------\n";

        // copy all the permutation tables to constant memory in the device
        cudaMemcpyToSymbol(d_initialPerm, initialPerm, sizeof(int) * BLOCK);
        cudaMemcpyToSymbol(d_finalPerm, finalPerm, sizeof(int) * BLOCK);
        cudaMemcpyToSymbol(d_expansion, expansion, sizeof(int) * ROUND_KEY);
        cudaMemcpyToSymbol(d_hS1, hS1, sizeof(int) * BLOCK);
        cudaMemcpyToSymbol(d_hS2, hS2, sizeof(int) * BLOCK);
        cudaMemcpyToSymbol(d_hS3, hS3, sizeof(int) * BLOCK);
        cudaMemcpyToSymbol(d_hS4, hS4, sizeof(int) * BLOCK);
        cudaMemcpyToSymbol(d_hS5, hS5, sizeof(int) * BLOCK);
        cudaMemcpyToSymbol(d_hS6, hS6, sizeof(int) * BLOCK);
        cudaMemcpyToSymbol(d_hS7, hS7, sizeof(int) * BLOCK);
        cudaMemcpyToSymbol(d_hS8, hS8, sizeof(int) * BLOCK);
        cudaMemcpyToSymbol(d_permutation, permutation, sizeof(int) * HALF_BLOCK);
        cudaMemcpyToSymbol(d_permutedChoice1, permutedChoice1, sizeof(int) * 56);
        cudaMemcpyToSymbol(d_permutedChoice2, permutedChoice2, sizeof(int) * ROUND_KEY);
        cudaMemcpyToSymbol(d_keyShiftArray, keyShiftArray, sizeof(int) * ROUNDS);

        // allocate memory and copy the passwords' arrays on the device
        uint64_t *d_pwdList;
        cudaMalloc((void **)&d_pwdList, N * sizeof(uint64_t));
        cudaMemcpy(d_pwdList, pwdList, N*sizeof(uint64_t), cudaMemcpyHostToDevice);
        //cudaMalloc((void **)&d_pwdToCrack, nCrack * nTests * sizeof(uint64_t));

        //cudaMemcpy(d_pwdToCrack, pwdToCrack, nCrack*sizeof(uint64_t), cudaMemcpyHostToDevice);

        int blockSize = 256;

        for (auto &test: tests) {
            uint64_t *d_pwdToCrack;
            cudaMalloc((void **) &d_pwdToCrack, nCrack * sizeof(uint64_t));
            cudaMemcpy(d_pwdToCrack, test, nCrack * sizeof(uint64_t), cudaMemcpyHostToDevice);
            cout << "Cracking password " << endl;
            kernelCrack<<<(N + blockSize - 1) / blockSize, blockSize>>>(d_pwdList, N, d_pwdToCrack, nCrack, key);
            cudaFree(d_pwdToCrack);
        }



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
