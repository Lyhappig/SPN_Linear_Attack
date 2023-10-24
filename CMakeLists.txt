cmake_minimum_required(VERSION 3.24)
project(linear_attack)

set(CMAKE_CXX_STANDARD 17)

add_executable(linear_attack main.cpp cipher.cpp)
