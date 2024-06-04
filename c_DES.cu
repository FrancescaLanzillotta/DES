//
// Created by franc on 03/06/2024.
//

#include "c_DES.cuh"


// calls to cudaMemcpyToSymbol() have to reside in the same file where the constant data is defined.
__constant__ int c_initialPerm[BLOCK];
__constant__ int c_finalPerm[BLOCK];
__constant__ int c_expansion[ROUND_KEY];
__constant__ int c_hS1[BLOCK];
__constant__ int c_hS2[BLOCK];
__constant__ int c_hS3[BLOCK];
__constant__ int c_hS4[BLOCK];
__constant__ int c_hS5[BLOCK];
__constant__ int c_hS6[BLOCK];
__constant__ int c_hS7[BLOCK];
__constant__ int c_hS8[BLOCK];
__constant__ int *c_hS[8] = {
        c_hS1, c_hS2, c_hS3, c_hS4, c_hS5, c_hS6, c_hS7, c_hS8};
__constant__ int c_permutation[HALF_BLOCK];
__constant__ int c_permutedChoice1[56];
__constant__ int c_permutedChoice2[ROUND_KEY];
__constant__ int c_keyShiftArray[ROUNDS];


auto CUDA_DES(){
    cudaMemcpyToSymbol(c_initialPerm, initialPerm, sizeof(int)*BLOCK);
    cudaMemcpyToSymbol(c_finalPerm, finalPerm, sizeof(int)*BLOCK);
    cudaMemcpyToSymbol(c_expansion, expansion, sizeof(int)*ROUND_KEY);
    cudaMemcpyToSymbol(c_hS1, hS1, sizeof(int)*BLOCK);
    cudaMemcpyToSymbol(c_hS2, hS2, sizeof(int)*BLOCK);
    cudaMemcpyToSymbol(c_hS3, hS3, sizeof(int)*BLOCK);
    cudaMemcpyToSymbol(c_hS4, hS4, sizeof(int)*BLOCK);
    cudaMemcpyToSymbol(c_hS5, hS5, sizeof(int)*BLOCK);
    cudaMemcpyToSymbol(c_hS6, hS6, sizeof(int)*BLOCK);
    cudaMemcpyToSymbol(c_hS7, hS7, sizeof(int)*BLOCK);
    cudaMemcpyToSymbol(c_hS8, hS8, sizeof(int)*BLOCK);
    cudaMemcpyToSymbol(c_permutation, permutation, sizeof(int)*HALF_BLOCK);
    cudaMemcpyToSymbol(c_permutedChoice1, permutedChoice1, sizeof(int)*56);
    cudaMemcpyToSymbol(c_permutedChoice2, permutedChoice2, sizeof(int)*ROUND_KEY);
    cudaMemcpyToSymbol(c_keyShiftArray, keyShiftArray, sizeof(int)*ROUNDS);


}


__device__ __forceinline__
uint64_t feistel_function(uint64_t subkey, uint64_t bits){
    // Expansion
    uint64_t exp = c_permute<HALF_BLOCK, ROUND_KEY>(bits, c_expansion);
    // Key mixing
    subkey = subkey ^ exp;
    // Substitution
    exp = 0;
    for(int j = 8-1; j >= 0; j--)
    {
        uint8_t block = (subkey >> (j) * 6);
        auto row = ((block & 0b100000) >> 4) | (block & 1);
        auto col = (block & 0b011110) >> 1;
        exp |= uint32_t(c_hS[8 - 1 - j][row * 16 + col]) << ((j) * 4);
    }

    return c_permute<HALF_BLOCK, HALF_BLOCK>(exp, c_permutation);;
}


__device__ __forceinline__
uint64_t des_encrypt_56(uint64_t key56, uint64_t message){
    // Initial permutation
    uint64_t ip = c_permute<BLOCK, BLOCK>(message, c_initialPerm);

    // Split in two halves
    uint32_t lhs = (ip >> HALF_BLOCK),
            rhs = ip;


    // Rounds, with subkey generation
    key56 = c_permute<BLOCK, 56>(key56, c_permutedChoice1);

    uint32_t lhs_rk = (key56 >> 28) & 0xfffffff;
    uint32_t rhs_rk = (key56) & 0xfffffff;

    for(int shift : keyShiftArray){

        lhs_rk = (lhs_rk << shift) | (lhs_rk >> (28 - shift));
        rhs_rk = (rhs_rk << shift) | (rhs_rk >> (28 - shift));
        lhs_rk &= 0xfffffff;
        rhs_rk &= 0xfffffff;

        uint64_t roundKey = (uint64_t(lhs_rk) << 28) | rhs_rk;

        roundKey = c_permute<56, ROUND_KEY>(roundKey, c_permutedChoice2);


        uint64_t feistel = feistel_function(roundKey, rhs);

        auto old_lhs = lhs;
        lhs = rhs;
        rhs = old_lhs ^ feistel;

    }

    message = (uint64_t(rhs) << HALF_BLOCK) | lhs;
    // Final permutation
    ip = c_permute<BLOCK, BLOCK>(message, c_finalPerm);
    return ip;
}

