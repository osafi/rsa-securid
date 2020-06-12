cmake_minimum_required(VERSION 3.5)
project(rsa-token)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -Wextra")
set(CMAKE_CXX_FLAGS_DEBUG "-g")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")

set(SOURCE_FILES securid.c aes.c aes.h securid.h)

add_executable(rsa-token ${SOURCE_FILES})

install(TARGETS rsa-token DESTINATION bin)
