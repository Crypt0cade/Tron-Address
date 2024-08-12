cmake_minimum_required(VERSION 3.10)
project(keccak256_library)

add_library(keccak256 STATIC Keccak256.cpp)
target_include_directories(keccak256 PUBLIC include)