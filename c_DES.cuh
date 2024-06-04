//
// Created by franc on 03/06/2024.
//

#ifndef DES_C_DES_CUH
#define DES_C_DES_CUH


#include "utils.h"
using namespace constants;

auto CUDA_DES();
template<size_t FROM, size_t TO>
__device__ static auto c_permute(uint64_t source, const int* table) -> uint64_t{
    uint64_t  p = 0;
    for(size_t i = 0; i < TO; i++)
        p |= ( (source >> (FROM-table[i])) & 1) << (TO-1-i);
    return p;
}
#endif //DES_C_DES_CUH
