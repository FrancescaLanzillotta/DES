//
// Created by franc on 03/06/2024.
//

#ifndef DES_D_DES_CUH
#define DES_D_DES_CUH


#include "utils.h"
using namespace constants;

template<int FROM, int TO>
__device__
auto d_permute(const uint64_t source,const int *table) -> uint64_t{
    uint64_t  p = 0;
    for(int i = 0; i < TO; i++){
        p |= ( (source >> (FROM-table[i])) & 1) << (TO-1-i);
    }
    return p;
}
__host__
int* parallelCrack(uint64_t *pwdList, int N, uint64_t *pwdToCrack, int nCrack, uint64_t key, int blockSize);
__device__
uint64_t d_feistelFunction(uint64_t subkey, uint64_t bits);
__device__
uint64_t d_desEncrypt(uint64_t key56, uint64_t message);
__global__
void kernelCrack(const uint64_t *pwdList, int nPwd, const uint64_t *pwdToCrack, int nCrack, int *foundBy, uint64_t key);
#endif //DES_D_DES_CUH
