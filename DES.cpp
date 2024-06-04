//
// Created by franc on 04/06/2024.
//

#include "DES.h"
#include "utils.h"
using namespace constants;

uint64_t feistel_function(uint64_t subkey, uint64_t bits){
    // Expansion
    uint64_t exp = permute<HALF_BLOCK, ROUND_KEY>(bits, expansion);
    // Key mixing
    subkey = subkey ^ exp;
    // Substitution
    exp = 0;
    for(int j = 8-1; j >= 0; j--)
    {
        uint8_t block = (subkey >> (j) * 6);
        auto row = ((block & 0b100000) >> 4) | (block & 1);
        auto col = (block & 0b011110) >> 1;
        exp |= uint32_t(hS[8 - 1 - j][row * 16 + col]) << ((j) * 4);
    }

    return permute<HALF_BLOCK, HALF_BLOCK>(exp, permutation);;
}


uint64_t des_encrypt_56(uint64_t key56, uint64_t message){
    // Initial permutation
    uint64_t ip = permute<BLOCK, BLOCK>(message, initialPerm);

    // Split in two halves
    uint32_t lhs = (ip >> HALF_BLOCK),
            rhs = ip;


    // Rounds, with subkey generation
    key56 = permute<BLOCK, 56>(key56, permutedChoice1);

    uint32_t lhs_rk = (key56 >> 28) & 0xfffffff;
    uint32_t rhs_rk = (key56) & 0xfffffff;

    for(int shift : keyShiftArray){

        lhs_rk = (lhs_rk << shift) | (lhs_rk >> (28 - shift));
        rhs_rk = (rhs_rk << shift) | (rhs_rk >> (28 - shift));
        lhs_rk &= 0xfffffff;
        rhs_rk &= 0xfffffff;

        uint64_t roundKey = (uint64_t(lhs_rk) << 28) | rhs_rk;

        roundKey = permute<56, ROUND_KEY>(roundKey, permutedChoice2);


        uint64_t feistel = feistel_function(roundKey, rhs);

        auto old_lhs = lhs;
        lhs = rhs;
        rhs = old_lhs ^ feistel;

    }

    message = (uint64_t(rhs) << HALF_BLOCK) | lhs;
    // Final permutation
    ip = permute<BLOCK, BLOCK>(message, finalPerm);
    return ip;
}