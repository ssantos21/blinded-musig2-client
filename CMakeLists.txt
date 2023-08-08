cmake_minimum_required(VERSION 3.10)

project(Secp256k1Build)

include(ExternalProject)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(SECP256K1_DIR "${CMAKE_BINARY_DIR}/_deps/src/secp256k1")

# Fetch the libcpr/cpr content
include(FetchContent)
FetchContent_Declare(cpr 
    GIT_REPOSITORY https://github.com/libcpr/cpr.git
    GIT_TAG 2553fc41450301cd09a9271c8d2c3e0cf3546b73)
FetchContent_MakeAvailable(cpr)

ExternalProject_Add(
    secp256k1
    GIT_REPOSITORY https://github.com/ElementsProject/secp256k1-zkp.git
    GIT_TAG master
    UPDATE_COMMAND ""
    
    PREFIX ${CMAKE_BINARY_DIR}/_deps
    SOURCE_DIR ${SECP256K1_DIR}
    
    CONFIGURE_COMMAND <SOURCE_DIR>/autogen.sh COMMAND <SOURCE_DIR>/configure --enable-module-schnorrsig --enable-experimental --enable-module-musig --enable-benchmark=no --enable-tests=no --enable-exhaustive-tests=no
    BUILD_COMMAND $(MAKE)
    INSTALL_COMMAND ""
    
    BUILD_IN_SOURCE 1
)

# Wait for secp256k1 to be built before compiling main.cpp
add_executable(client main.cpp utils/strencodings.cpp)
add_dependencies(client secp256k1)

target_link_libraries(
    client 
    ${SECP256K1_DIR}/.libs/libsecp256k1.a
    cpr::cpr)
target_include_directories(client PRIVATE ${SECP256K1_DIR}/include)
set_property(TARGET client PROPERTY CXX_STANDARD 20)
