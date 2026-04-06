cmake_minimum_required(VERSION 3.15)
project(tests)

set(CMAKE_CXX_STANDARD 20)

add_executable(tests main.cpp examples_util.h
        hmac_256.cpp
        sha_256.cpp
        hkdf.cpp
        ecdh.cpp)

# OpenSSL
find_package(OpenSSL REQUIRED)
target_link_libraries(tests OpenSSL::Crypto)

# secp256k1
find_library(SECP256K1_LIB secp256k1 HINTS /usr/local/lib)
find_path(SECP256K1_INCLUDE secp256k1.h HINTS /usr/local/include)
include_directories(${SECP256K1_INCLUDE})
target_link_libraries(tests ${SECP256K1_LIB})

# Standalone Asio (включи заголовки)
target_include_directories(tests PRIVATE /path/to/asio/include)
target_compile_definitions(tests PRIVATE ASIO_STANDALONE)
