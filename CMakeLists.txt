cmake_minimum_required(VERSION 3.16)
project(Crypto VERSION 1.1.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)
find_package(BZip2 REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(BROTLI REQUIRED libbrotlienc libbrotlidec)

# LZMA: use system liblzma.so.5 (headers bundled in lib/lzma)
find_library(LZMA_LIBRARY liblzma.so.5
    PATHS /usr/lib/x86_64-linux-gnu /usr/lib /usr/local/lib
    REQUIRED)

set(LZ4_SOURCES
    lib/lz4/lz4.c
    lib/lz4/lz4hc.c
    lib/lz4/lz4frame.c
    lib/lz4/xxhash.c
)

set(SNAPPY_SOURCES
    lib/snappy/snappy.cc
    lib/snappy/snappy-c.cc
    lib/snappy/snappy-sinksource.cc
    lib/snappy/snappy-stubs-internal.cc
)

set_source_files_properties(
    lib/snappy/snappy.cc
    PROPERTIES COMPILE_FLAGS "-msse4.2"
)

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
    src/crypto/chacha20_poly1305.cpp
    src/crypto/xchacha20_poly1305.cpp
    src/vm/vm_compile.cpp
    src/vm/vm_stub.cpp
    src/vm/isa_expand.cpp
    src/vm/obfcond.cpp
    src/vm/spill.cpp
    src/vm/smc.cpp
    src/vm/vlencode.cpp
    src/vm/cfi.cpp
    src/vm/code_schedule.cpp
    src/obfuscate/anti_debug.cpp
    src/obfuscate/rename.cpp
    src/obfuscate/flow_flatten.cpp
    src/obfuscate/junk.cpp
    src/obfuscate/xor_gen.cpp
    src/obfuscate/obfuscate.cpp
    ${LZ4_SOURCES}
    ${SNAPPY_SOURCES}
)

add_executable(crypto ${CRYPTO_SOURCES})

target_include_directories(crypto PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/lib/lz4
    ${CMAKE_SOURCE_DIR}/lib/snappy
    ${CMAKE_SOURCE_DIR}/lib/lzma
    ${OPENSSL_INCLUDE_DIR}
    ${BROTLI_INCLUDE_DIRS}
)

target_compile_definitions(crypto PRIVATE HAVE_CONFIG_H)

target_link_libraries(crypto PRIVATE
    OpenSSL::Crypto
    ZLIB::ZLIB
    BZip2::BZip2
    ${LZMA_LIBRARY}
    ${BROTLI_LIBRARIES}
)

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
        src/crypto/chacha20_poly1305.cpp
        src/crypto/xchacha20_poly1305.cpp
        src/vm/vm_compile.cpp
        src/vm/vm_stub.cpp
        src/vm/isa_expand.cpp
        src/vm/obfcond.cpp
        src/vm/spill.cpp
        src/vm/smc.cpp
        src/vm/vlencode.cpp
        src/vm/cfi.cpp
        src/vm/code_schedule.cpp
        src/obfuscate/anti_debug.cpp
        src/obfuscate/rename.cpp
        src/obfuscate/flow_flatten.cpp
        src/obfuscate/junk.cpp
        src/obfuscate/xor_gen.cpp
        src/obfuscate/obfuscate.cpp
        ${LZ4_SOURCES}
        ${SNAPPY_SOURCES}
    )

    target_include_directories(test_crypto PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/lib/lz4
        ${CMAKE_SOURCE_DIR}/lib/snappy
        ${CMAKE_SOURCE_DIR}/lib/lzma
        ${OPENSSL_INCLUDE_DIR}
        ${BROTLI_INCLUDE_DIRS}
    )

    target_compile_definitions(test_crypto PRIVATE HAVE_CONFIG_H)

    target_link_libraries(test_crypto PRIVATE
        OpenSSL::Crypto
        ZLIB::ZLIB
        BZip2::BZip2
        ${LZMA_LIBRARY}
        ${BROTLI_LIBRARIES}
    )

    include(CTest)
    add_test(NAME test_crypto COMMAND test_crypto)
endif()
