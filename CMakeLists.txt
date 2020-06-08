cmake_minimum_required(VERSION 3.10)
project(untitled1)

set(CMAKE_CXX_STANDARD 14)
set(SOURCE_FILES main.cpp)

INCLUDE_DIRECTORIES(bls/src)
LINK_DIRECTORIES(bls/build/src)

#INCLUDE_DIRECTORIES(salticidae/include)
#LINK_DIRECTORIES(salticidae/CMakeFiles/salticidae.dir/src)
#LINK_DIRECTORIES(salticidae)

LINK_DIRECTORIES(bls/build/contrib/relic/lib)
INCLUDE_DIRECTORIES(bls/build/contrib/relic/include)
INCLUDE_DIRECTORIES(bls/contrib/relic/include)

add_executable(untitled1 ${SOURCE_FILES})
TARGET_LINK_LIBRARIES(untitled1 blstmp relic_s pthread)
