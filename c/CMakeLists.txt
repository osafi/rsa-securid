cmake_minimum_required(VERSION 3.5)
project(RSASecurID)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
set(SOURCE_FILES securid.c aes.c aes.h securid.h)

add_executable(RSASecurID ${SOURCE_FILES})
