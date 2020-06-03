cmake_minimum_required(VERSION 3.17)
project(blsbench2)

set(CMAKE_CXX_STANDARD 14)
set(SOURCE_FILES test.cpp)

INCLUDE_DIRECTORIES(../../Documents/IdeaProjects/bls-signatures/src)
LINK_DIRECTORIES(../../Documents/IdeaProjects/bls-signatures/build/src)

LINK_DIRECTORIES(../../Documents/IdeaProjects/bls-signatures/build/contrib/relic/lib)
INCLUDE_DIRECTORIES(../../Documents/IdeaProjects/bls-signatures/build/contrib/relic/include)
INCLUDE_DIRECTORIES(../../Documents/IdeaProjects/bls-signatures/contrib/relic/include)

add_executable(blsbench2 ${SOURCE_FILES})

TARGET_LINK_LIBRARIES(blsbench2 blstmp relic_s pthread)


