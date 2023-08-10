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

FetchContent_Declare(
    sqlite3
    URL "https://www.sqlite.org/2023/sqlite-amalgamation-3420000.zip"
)
FetchContent_MakeAvailable(sqlite3)

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
add_executable(client main.cpp utils/strencodings.cpp utils/lib.cpp)
add_dependencies(client secp256k1)

# Create a static library for sqlite3
add_library(sqlite3_static STATIC ${sqlite3_SOURCE_DIR}/sqlite3.c)
target_include_directories(sqlite3_static PRIVATE ${sqlite3_SOURCE_DIR})
target_compile_definitions(sqlite3_static PRIVATE SQLITE_API=)

target_link_libraries(
    client 
    PRIVATE ${SECP256K1_DIR}/.libs/libsecp256k1.a
    PRIVATE cpr::cpr
    PRIVATE sqlite3_static)
    
target_include_directories(
    client 
    PRIVATE ${SECP256K1_DIR}/include 
    PRIVATE ${sqlite3_SOURCE_DIR})

set_property(TARGET client PROPERTY CXX_STANDARD 20)
