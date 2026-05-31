cmake_minimum_required(VERSION 3.16)
project(Crypto VERSION 1.1.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)

set(CRYPTO_SOURCES
    src/main.cpp
    src/cli/cli.cpp
    src/cli/protect.cpp
    src/utils/file_util.cpp
    src/utils/compress.cpp
    src/encode/encoder.cpp
    src/encode/base64.cpp
    src/encode/base32.cpp
    src/encode/base85.cpp
    src/encode/ascii85.cpp
    src/encode/hexcode.cpp
    src/encode/xorcode.cpp
    src/crypto/cipher.cpp
    src/crypto/aes.cpp
    src/crypto/chacha20.cpp
    src/vm/vm_compile.cpp
    src/vm/vm_stub.cpp
    src/obfuscate/anti_debug.cpp
    src/obfuscate/rename.cpp
    src/obfuscate/flow_flatten.cpp
    src/obfuscate/junk.cpp
    src/obfuscate/xor_gen.cpp
    src/obfuscate/obfuscate.cpp
)

add_executable(crypto ${CRYPTO_SOURCES})

target_include_directories(crypto PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(crypto PRIVATE OpenSSL::Crypto ZLIB::ZLIB)

option(CRYPTO_BUILD_TESTS "Build unit tests" ON)

if(CRYPTO_BUILD_TESTS)
    add_executable(test_crypto
        tests/test_all.cpp
        tests/test_vm.cpp
        tests/test_obfuscate.cpp
    src/utils/file_util.cpp
    src/utils/compress.cpp
        src/encode/base64.cpp
        src/encode/base32.cpp
        src/encode/base85.cpp
        src/encode/ascii85.cpp
        src/encode/hexcode.cpp
        src/encode/xorcode.cpp
        src/crypto/aes.cpp
        src/crypto/chacha20.cpp
        src/vm/vm_compile.cpp
        src/vm/vm_stub.cpp
        src/obfuscate/anti_debug.cpp
        src/obfuscate/rename.cpp
        src/obfuscate/flow_flatten.cpp
        src/obfuscate/junk.cpp
        src/obfuscate/xor_gen.cpp
        src/obfuscate/obfuscate.cpp
    )

    target_include_directories(test_crypto PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}
        ${OPENSSL_INCLUDE_DIR}
    )

    target_link_libraries(test_crypto PRIVATE OpenSSL::Crypto)

    include(CTest)
    add_test(NAME test_crypto COMMAND test_crypto)
endif()
