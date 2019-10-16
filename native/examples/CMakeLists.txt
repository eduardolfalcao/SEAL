cmake_minimum_required(VERSION 3.10)
project(LRSeal VERSION 1.0)
add_executable(lrseal lr_seal.cpp)

find_package(SEAL)
target_link_libraries(lrseal SEAL::seal)
