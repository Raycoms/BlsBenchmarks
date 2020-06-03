# Install script for directory: /home/ray/Documents/IdeaProjects/bls-signatures/src

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "RELEASE")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "0")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/chiabls" TYPE FILE FILES
    "/home/ray/Documents/IdeaProjects/bls-signatures/src/aggregationinfo.hpp"
    "/home/ray/Documents/IdeaProjects/bls-signatures/src/bls.hpp"
    "/home/ray/Documents/IdeaProjects/bls-signatures/src/chaincode.hpp"
    "/home/ray/Documents/IdeaProjects/bls-signatures/src/extendedprivatekey.hpp"
    "/home/ray/Documents/IdeaProjects/bls-signatures/src/extendedpublickey.hpp"
    "/home/ray/Documents/IdeaProjects/bls-signatures/src/privatekey.hpp"
    "/home/ray/Documents/IdeaProjects/bls-signatures/src/publickey.hpp"
    "/home/ray/Documents/IdeaProjects/bls-signatures/src/signature.hpp"
    "/home/ray/Documents/IdeaProjects/bls-signatures/src/test-utils.hpp"
    "/home/ray/Documents/IdeaProjects/bls-signatures/src/threshold.hpp"
    "/home/ray/Documents/IdeaProjects/bls-signatures/src/util.hpp"
    )
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE FILE FILES "/home/ray/Documents/IdeaProjects/bls-signatures/build/libbls.a")
endif()

