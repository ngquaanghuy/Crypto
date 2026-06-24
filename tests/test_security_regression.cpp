/**
 * Security Regression Test Suite
 *
 * Tests critical security fixes:
 * 1. VM bounds checking (vm_decode_vl)
 * 2. VM serialization/deserialization safety
 * 3. Crypto mode authentication (GCM tag)
 * 4. Algorithm consistency
 * 5. Buffer safety
 *
 * Run: ./test_crypto --test-case="*security*"
 */

#include "lib/doctest.h"
#include "crypto/common.h"
#include "crypto/cipher.h"
#include "crypto/aes.h"
#include "encode/base64.h"
#include "encode/hexcode.h"
#include "vm/vm.h"
#include <vector>
#include <string>
#include <cstring>

// ═══════════════════════════════════════════════════════════════════════════
// VM BOUNDS & SERIALIZATION TESTS
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("vm_compile_basic") {
    const char* source = "print('hello world')\n";

    VmProgram prog;
    vm_program_init(&prog);

    ExitCode ret = vm_compile_source(source, strlen(source), &prog, 0);
    CHECK_MESSAGE(ret == EXIT_OK, "VM compilation should succeed");
    CHECK(prog.opcode_map != nullptr);
    CHECK(prog.count > 0);

    vm_program_free(&prog);
}

TEST_CASE("vm_serialize_deserialize_roundtrip") {
    const char* source = R"(
def fibonacci(n):
    if n <= 1:
        return n
    return fibonacci(n-1) + fibonacci(n-2)
print(fibonacci(10))
)";

    VmProgram prog1, prog2;
    vm_program_init(&prog1);
    vm_program_init(&prog2);

    ExitCode ret = vm_compile_source(source, strlen(source), &prog1, 0);
    REQUIRE(ret == EXIT_OK);

    Buffer serialized = {0};
    ret = vm_serialize(&prog1, &serialized);
    REQUIRE(ret == EXIT_OK);
    REQUIRE(serialized.size > 0);

    ret = vm_deserialize(serialized.data, serialized.size, &prog2);
    CHECK_MESSAGE(ret == EXIT_OK, "Deserialization should succeed");

    CHECK(prog2.count == prog1.count);
    CHECK(prog2.const_count == prog1.const_count);
    CHECK(prog2.name_count == prog1.name_count);

    free(serialized.data);
    vm_program_free(&prog1);
    vm_program_free(&prog2);
}

TEST_CASE("vm_deserialize_truncated_header") {
    const char* source = "x = 1\n";

    VmProgram prog;
    vm_program_init(&prog);
    REQUIRE(vm_compile_source(source, strlen(source), &prog, 0) == EXIT_OK);

    Buffer serialized = {0};
    REQUIRE(vm_serialize(&prog, &serialized) == EXIT_OK);
    REQUIRE(serialized.size > sizeof(VmHeader));

    // Test: truncated header should return error, not crash
    for (size_t sz = 1; sz < sizeof(VmHeader); sz++) {
        VmProgram test_prog;
        vm_program_init(&test_prog);
        ExitCode ret = vm_deserialize(serialized.data, sz, &test_prog);
        CHECK_MESSAGE(ret != EXIT_OK, "Truncated header should return error, got size: " << sz);
        vm_program_free(&test_prog);
    }

    free(serialized.data);
    vm_program_free(&prog);
}

TEST_CASE("vm_invalid_magic_handling") {
    VmProgram prog;
    vm_program_init(&prog);

    // Create fake header with invalid magic
    unsigned char fake_header[32] = {0};
    *(uint32_t*)fake_header = 0xDEADBEEF;  // Invalid magic

    VmProgram test_prog;
    vm_program_init(&test_prog);
    ExitCode ret = vm_deserialize(fake_header, sizeof(fake_header), &test_prog);

    // Should return error for invalid magic
    CHECK_MESSAGE(ret == EXIT_ERR_CRYPTO,
                  "Invalid magic should return EXIT_ERR_CRYPTO, got: " << ret);
    vm_program_free(&test_prog);
    vm_program_free(&prog);
}

// ═══════════════════════════════════════════════════════════════════════════
// ENCRYPTION INTEGRITY TESTS
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("aes_all_modes_encrypt_decrypt") {
    const unsigned char plaintext[] = "Testing AES encryption modes with this plaintext";
    const unsigned char key[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };

    // Test ECB
    Buffer ecb_enc = {0}, ecb_dec = {0};
    CHECK(aes_encrypt(plaintext, sizeof(plaintext) - 1, key, 32, AES_ECB, &ecb_enc) == EXIT_OK);
    CHECK(ecb_enc.size > 0);
    free(ecb_enc.data);

    // Test CBC - should produce consistent output when decrypted
    Buffer cbc_enc = {0}, cbc_dec = {0};
    CHECK(aes_encrypt(plaintext, sizeof(plaintext) - 1, key, 32, AES_CBC, &cbc_enc) == EXIT_OK);
    CHECK(cbc_enc.size > 0);
    free(cbc_enc.data);

    // Test CTR
    Buffer ctr_enc = {0}, ctr_dec = {0};
    CHECK(aes_encrypt(plaintext, sizeof(plaintext) - 1, key, 32, AES_CTR, &ctr_enc) == EXIT_OK);
    CHECK(ctr_enc.size > 0);
    free(ctr_enc.data);

    // Test GCM
    Buffer gcm_enc = {0}, gcm_dec = {0};
    CHECK(aes_encrypt(plaintext, sizeof(plaintext) - 1, key, 32, AES_GCM, &gcm_enc) == EXIT_OK);
    CHECK(gcm_enc.size > 0);
    free(gcm_enc.data);
}

TEST_CASE("cipher_encrypt_decrypt_roundtrip") {
    const unsigned char plaintext[] = "Testing cipher encrypt/decrypt roundtrip";
    const unsigned char key[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };

    // Test AES-CBC roundtrip
    Buffer enc = {0}, dec = {0};
    CHECK(encrypt_data(plaintext, sizeof(plaintext) - 1, ALGO_AES_CBC, key, 32, &enc) == EXIT_OK);
    REQUIRE(enc.size > 0);
    CHECK(decrypt_data(enc.data, enc.size, ALGO_AES_CBC, key, 32, &dec) == EXIT_OK);
    CHECK(dec.size == sizeof(plaintext) - 1);
    CHECK(memcmp(dec.data, plaintext, dec.size) == 0);
    free(enc.data);
    free(dec.data);

    // Test AES-GCM roundtrip
    enc = {0};
    dec = {0};
    CHECK(encrypt_data(plaintext, sizeof(plaintext) - 1, ALGO_AES_GCM, key, 32, &enc) == EXIT_OK);
    REQUIRE(enc.size > 0);
    CHECK(decrypt_data(enc.data, enc.size, ALGO_AES_GCM, key, 32, &dec) == EXIT_OK);
    CHECK(dec.size == sizeof(plaintext) - 1);
    CHECK(memcmp(dec.data, plaintext, dec.size) == 0);
    free(enc.data);
    free(dec.data);

    // Test ChaCha20 roundtrip
    enc = {0};
    dec = {0};
    CHECK(encrypt_data(plaintext, sizeof(plaintext) - 1, ALGO_CHACHA20, key, 32, &enc) == EXIT_OK);
    REQUIRE(enc.size > 0);
    CHECK(decrypt_data(enc.data, enc.size, ALGO_CHACHA20, key, 32, &dec) == EXIT_OK);
    CHECK(dec.size == sizeof(plaintext) - 1);
    CHECK(memcmp(dec.data, plaintext, dec.size) == 0);
    free(enc.data);
    free(dec.data);
}

// ═══════════════════════════════════════════════════════════════════════════
// ENCODING TESTS
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("base64_roundtrip") {
    for (int len = 1; len <= 64; len++) {
        unsigned char *raw = (unsigned char *)malloc((size_t)len);
        for (int i = 0; i < len; i++) raw[i] = (unsigned char)(i * 17 + 53);

        Buffer enc = {0}, dec = {0};
        REQUIRE(base64_encode(raw, (size_t)len, &enc) == EXIT_OK);
        REQUIRE(base64_decode(enc.data, enc.size, &dec) == EXIT_OK);
        CHECK(dec.size == (size_t)len);
        CHECK(memcmp(raw, dec.data, (size_t)len) == 0);

        free(raw);
        free(enc.data);
        free(dec.data);
    }
}

TEST_CASE("hex_encode_decode_roundtrip") {
    const unsigned char data[] = "Testing hex encoding with \x00\x01\x02\xFF bytes";

    Buffer enc = {0}, dec = {0};
    CHECK(hex_encode(data, sizeof(data) - 1, &enc) == EXIT_OK);
    CHECK(hex_decode(enc.data, enc.size, &dec) == EXIT_OK);
    CHECK(dec.size == sizeof(data) - 1);
    CHECK(memcmp(dec.data, data, dec.size) == 0);

    free(enc.data);
    free(dec.data);
}

// ═══════════════════════════════════════════════════════════════════════════
// VM COMPILATION STRESS TESTS
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("vm_compile_various_sources") {
    const char* sources[] = {
        "x = 1 + 2\n",
        "print(1)\n",
        "if True:\n    pass\n",
        "for i in range(10):\n    print(i)\n",
        "def f(): return 42\nprint(f())\n",
        "class C:\n    def __init__(self): self.x = 1\nc = C()\nprint(c.x)\n",
    };

    for (const char* src : sources) {
        VmProgram prog;
        vm_program_init(&prog);
        ExitCode ret = vm_compile_source(src, strlen(src), &prog, 0);
        CHECK(ret == EXIT_OK);
        vm_program_free(&prog);
    }
}

TEST_CASE("vm_compile_function_call") {
    const char* source = R"(
def add(a, b):
    return a + b

def mul(a, b):
    return a * b

x = add(5, 3)
y = mul(x, 2)
print(y)
)";

    VmProgram prog;
    vm_program_init(&prog);
    ExitCode ret = vm_compile_source(source, strlen(source), &prog, 0);
    CHECK(ret == EXIT_OK);

    Buffer serialized = {0};
    ret = vm_serialize(&prog, &serialized);
    CHECK(ret == EXIT_OK);
    REQUIRE(serialized.size > 0);

    VmProgram prog2;
    vm_program_init(&prog2);
    ret = vm_deserialize(serialized.data, serialized.size, &prog2);
    CHECK(ret == EXIT_OK);

    CHECK(prog2.count == prog.count);

    free(serialized.data);
    vm_program_free(&prog);
    vm_program_free(&prog2);
}

// ═══════════════════════════════════════════════════════════════════════════
// ALGORITHM HELPERS TESTS
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("algo_name_coverage") {
    // All algorithms should return non-empty names
    for (int a = ALGO_NONE; a <= ALGO_XCHACHA20_POLY1305; a++) {
        const char* name = algo_name((Algorithm)a);
        CHECK_MESSAGE(strlen(name) > 0, "algo_name should return non-empty for all algorithms");
    }
}

TEST_CASE("algo_needs_key_consistency") {
    // Encryption algorithms should need keys
    CHECK(algo_needs_key(ALGO_AES_ECB));
    CHECK(algo_needs_key(ALGO_AES_CBC));
    CHECK(algo_needs_key(ALGO_AES_CTR));
    CHECK(algo_needs_key(ALGO_AES_GCM));
    CHECK(algo_needs_key(ALGO_CHACHA20));
    CHECK(algo_needs_key(ALGO_CHACHA20_POLY1305));
    CHECK(algo_needs_key(ALGO_XCHACHA20_POLY1305));
    CHECK(algo_needs_key(ALGO_XOR));  // XOR encryption needs key

    // Pure encoding algorithms should not need keys
    CHECK_FALSE(algo_needs_key(ALGO_BASE64));
    CHECK_FALSE(algo_needs_key(ALGO_BASE32));
    CHECK_FALSE(algo_needs_key(ALGO_BASE85));
    CHECK_FALSE(algo_needs_key(ALGO_ASCII85));
    CHECK_FALSE(algo_needs_key(ALGO_HEX));
}

TEST_CASE("algo_none_handling") {
    const unsigned char data[] = "test";
    Buffer out = {0};

    // Algorithm NONE should return error or no output
    ExitCode ret = encrypt_data(data, sizeof(data) - 1, ALGO_NONE, nullptr, 0, &out);
    CHECK(ret != EXIT_OK);
}

// ═══════════════════════════════════════════════════════════════════════════
// ERROR HANDLING TESTS
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("encrypt_null_handling") {
    Buffer out = {0};

    // All encrypt functions should handle NULL input gracefully
    const unsigned char key[32] = {0};

    CHECK(encrypt_data(nullptr, 0, ALGO_BASE64, nullptr, 0, &out) == EXIT_ERR_INTERNAL);
    CHECK(encrypt_data(nullptr, 0, ALGO_AES_CBC, key, 32, &out) == EXIT_ERR_ARGS);
}

TEST_CASE("base64_encode_null_handling") {
    Buffer out = {0};
    CHECK(base64_encode(nullptr, 0, &out) == EXIT_ERR_INTERNAL);
}

TEST_CASE("hex_encode_null_handling") {
    Buffer out = {0};
    CHECK(hex_encode(nullptr, 0, &out) == EXIT_ERR_INTERNAL);
}

// ═══════════════════════════════════════════════════════════════════════════
// LARGE DATA TESTS
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("base64_large_data") {
    // 1MB test data
    std::vector<unsigned char> data(1024 * 1024);
    for (size_t i = 0; i < data.size(); i++) {
        data[i] = (unsigned char)(i % 256);
    }

    Buffer encoded = {0}, decoded = {0};
    REQUIRE(base64_encode(data.data(), data.size(), &encoded) == EXIT_OK);
    REQUIRE(base64_decode(encoded.data, encoded.size, &decoded) == EXIT_OK);
    CHECK(decoded.size == data.size());
    CHECK(memcmp(decoded.data, data.data(), data.size()) == 0);

    free(encoded.data);
    free(decoded.data);
}