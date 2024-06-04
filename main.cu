#include <iostream>
#include <string>
#include <random>
#include <filesystem>
#include <fstream>
#include <cstdint>
#include "utils.h"
#include "DES.h"
using namespace constants;
using namespace std;






int main() {
    string wordsPath = R"(C:\Users\franc\CLionProjects\DES\words.txt)";
    bool overwrite = false;

    int N= 100;
    int length = 8;

    uint64_t key = toUint64_T("key");

    if (filesystem::exists(wordsPath) && !overwrite) {

        ifstream wordsFile(wordsPath);

        // create a vector with all the words in the specified file
        string pwd;
        vector<string> pwdList = {};
        while (getline(wordsFile, pwd)) {   // read file line by line
            pwdList.push_back(pwd);

        }

        string toCrack = pwdList[5];
        uint64_t uintoCrack = toUint64_T(toCrack);
        auto enc = des_encrypt_56(key, uintoCrack);
        cout << "To crack: " << toCrack << " (" << uintoCrack << ") -> " << enc << endl;
        for (auto &p : pwdList){
            uint64_t toCheck = toUint64_T(p);
            toCheck = des_encrypt_56(key, toCheck);
            if (enc == toCheck){
                cout << "Pwd cracked: " << enc << " == " << toCheck << endl;
                break;
            } else
                cout << "No matching password found" << endl;

        }










//        auto *key = new unsigned int[BLOCK];
//        auto *roundKeys = new unsigned int[ROUND_KEY * ROUNDS];
//
//
//
//        string binKey = toUint64_T("abcdefhi");
//
//        for (int i = 0; i < binKey.size(); i++){
//            key[i] = static_cast<int>(binKey[i]);
//        }
//
//        auto inPerm = c_permute(key, permutedChoice1, BLOCK, 56);
//        // auto finPerm = c_permute(inPerm, finalPerm, BLOCK, BLOCK);
//
//
//
//        cout << toString(key, BLOCK) << endl;
//        cout << toString(inPerm, 56) << endl;
//
//        delete [] inPerm;
//        delete[] key;
//        delete[] roundKeys;
//
//
//
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
