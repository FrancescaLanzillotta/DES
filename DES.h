//
// Created by franc on 04/06/2024.
//

#ifndef DES_DES_H
#define DES_DES_H
#include <cstdint>
#include <string>
#include <vector>

using namespace std;
template<size_t FROM, size_t TO>
static auto permute(uint64_t source, const int* table) -> uint64_t {
    uint64_t p = 0;
    for (size_t i = 0; i < TO; i++)
        p |= ((source >> (FROM - table[i])) & 1) << (TO - 1 - i);
    return p;
}

uint64_t feistelFunction(uint64_t subkey, uint64_t bits);
uint64_t desEncrypt(uint64_t key56, uint64_t message);

#endif //DES_DES_H
