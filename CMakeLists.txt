cmake_minimum_required(VERSION 3.28)
project(DES LANGUAGES C CXX CUDA)
find_package(CUDAToolkit REQUIRED)
include_directories(C:/Program Files/NVIDIA GPU Computing Toolkit/CUDA/v12.5/include)
set(CMAKE_CUDA_STANDARD 17)

add_executable(DES main.cu
        utils.h
        d_DES.cu
        d_DES.cuh
        DES.cpp
        DES.h
)

set_target_properties(DES PROPERTIES
        CUDA_SEPARABLE_COMPILATION OFF)

set(CMAKE_CUDA_FLAGS "${CMAKE_CUDA_FLAGS} --ptxas-options=-v")

