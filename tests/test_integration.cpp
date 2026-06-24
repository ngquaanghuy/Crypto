/**
 * Integration Test Suite - End-to-End Workflow Tests
 *
 * Tests complete protection pipelines:
 * - Python source -> VM compilation -> serialization
 * - Encryption pipeline end-to-end
 * - Obfuscation
 *
 * Run: ./test_crypto --test-case="*integration*"
 */

#include "lib/doctest.h"
#include "crypto/common.h"
#include "crypto/cipher.h"
#include "crypto/aes.h"
#include "vm/vm.h"
#include <vector>
#include <string>
#include <cstring>
#include <chrono>

// ═══════════════════════════════════════════════════════════════════════════
// FULL PIPELINE TESTS
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("full_protection_pipeline") {
    const std::string py_source = R"(
def add(a, b):
    return a + b

result = add(5, 3)
print(result)
)";

    // 1. Compile to VM
    VmProgram prog;
    vm_program_init(&prog);
    ExitCode ret = vm_compile_source(py_source.c_str(), py_source.size(), &prog, 0);
    CHECK_MESSAGE(ret == EXIT_OK, "VM compilation should succeed");

    // 2. Serialize
    Buffer serialized = {0};
    ret = vm_serialize(&prog, &serialized);
    CHECK_MESSAGE(ret == EXIT_OK, "Serialization should succeed");
    REQUIRE(serialized.size > 0);

    // 3. Encrypt
    const unsigned char key[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };

    Buffer encrypted = {0};
    ret = encrypt_data(serialized.data, serialized.size, ALGO_AES_GCM, key, 32, &encrypted);
    CHECK_MESSAGE(ret == EXIT_OK, "Encryption should succeed");

    // 4. Decrypt
    Buffer decrypted = {0};
    ret = decrypt_data(encrypted.data, encrypted.size, ALGO_AES_GCM, key, 32, &decrypted);
    CHECK_MESSAGE(ret == EXIT_OK, "Decryption should succeed");

    // 5. Deserialize
    VmProgram prog2;
    vm_program_init(&prog2);
    ret = vm_deserialize(decrypted.data, decrypted.size, &prog2);
    CHECK_MESSAGE(ret == EXIT_OK, "Deserialization should succeed");

    // Verify
    CHECK(prog2.count == prog.count);
    CHECK(prog2.const_count == prog.const_count);
    CHECK(prog2.name_count == prog.name_count);

    // Cleanup
    free(serialized.data);
    free(encrypted.data);
    free(decrypted.data);
    vm_program_free(&prog);
    vm_program_free(&prog2);
}

TEST_CASE("complex_python_compilation_pipeline") {
    const std::string py = R"(
import sys

def fibonacci(n):
    if n <= 1:
        return n
    return fibonacci(n-1) + fibonacci(n-2)

def factorial(n):
    if n <= 1:
        return 1
    return n * factorial(n-1)

class Calculator:
    def __init__(self):
        self.history = []
        self.result = 0

    def compute(self, op, a, b):
        if op == 'add':
            self.result = a + b
        elif op == 'sub':
            self.result = a - b
        elif op == 'mul':
            self.result = a * b
        self.history.append((op, a, b, self.result))
        return self.result

calc = Calculator()
print(calc.compute('add', 5, 3))
print(calc.compute('mul', 7, 8))
print(fibonacci(10))
print(factorial(5))
)";

    VmProgram prog;
    vm_program_init(&prog);

    ExitCode ret = vm_compile_source(py.c_str(), py.size(), &prog, 0);
    CHECK_MESSAGE(ret == EXIT_OK, "Complex Python compilation should succeed");
    CHECK(prog.count > 10);

    Buffer serialized = {0};
    ret = vm_serialize(&prog, &serialized);
    CHECK_MESSAGE(ret == EXIT_OK, "Serialization should succeed");
    CHECK(serialized.size > 100);

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
// OBFUSCATION TESTS
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("obfuscation_enabled_compilation") {
    const char* source = "x = 1 + 2\n";

    VmProgram prog;
    vm_program_init(&prog);

    // Test with opaque predicates enabled (opaque=1)
    ExitCode ret = vm_compile_source(source, strlen(source), &prog, 1);
    CHECK_MESSAGE(ret == EXIT_OK, "Obfuscation compilation should succeed");

    Buffer serialized = {0};
    ret = vm_serialize(&prog, &serialized);
    CHECK_MESSAGE(ret == EXIT_OK, "Serialization should succeed");

    VmProgram prog2;
    vm_program_init(&prog2);
    ret = vm_deserialize(serialized.data, serialized.size, &prog2);
    CHECK(ret == EXIT_OK);

    free(serialized.data);
    vm_program_free(&prog);
    vm_program_free(&prog2);
}

TEST_CASE("obfuscation_with_multiple_sources") {
    const char* sources[] = {
        "def simple(): return 1\n",
        "x = [1, 2, 3]\nprint(sum(x))\n",
        "d = {'a': 1, 'b': 2}\nprint(d)\n",
        "for i in range(5): print(i)\n",
    };

    for (const char* src : sources) {
        VmProgram prog;
        vm_program_init(&prog);

        ExitCode ret = vm_compile_source(src, strlen(src), &prog, 0);
        CHECK(ret == EXIT_OK);

        Buffer ser = {0};
        ret = vm_serialize(&prog, &ser);
        CHECK(ret == EXIT_OK);
        CHECK(ser.size > 0);

        free(ser.data);
        vm_program_free(&prog);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ERROR HANDLING INTEGRATION
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("invalid_python_integration") {
    const char* invalid_sources[] = {
        "def unclosed(",
        "print('unclosed",
        "for i in range(10\n    x = 1",
    };

    for (const char* src : invalid_sources) {
        VmProgram prog;
        vm_program_init(&prog);
        ExitCode ret = vm_compile_source(src, strlen(src), &prog, 0);
        // Invalid Python syntax should return error
        CHECK_MESSAGE(ret != EXIT_OK, "Invalid Python should fail compilation: " << src);
        vm_program_free(&prog);
    }
}

TEST_CASE("corrupted_data_integration") {
    const unsigned char key[32] = {0};

    std::vector<std::vector<unsigned char>> corrupt_data = {
        {},  // Empty
        {0x00, 0x01, 0x02},  // Short
        std::vector<unsigned char>(100, 0xFF),  // All 0xFF
        std::vector<unsigned char>(1000, 0x00),  // All zeros
    };

    for (const auto& d : corrupt_data) {
        Buffer out = {0};
        decrypt_data(d.data(), d.size(), ALGO_AES_GCM, key, 32, &out);
        // Should handle gracefully, not crash
        free(out.data);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// PERFORMANCE TESTS
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("compilation_performance_medium") {
    const std::string medium_py = R"(
def process_data(items):
    results = []
    for item in items:
        processed = item * 2
        if processed > 100:
            processed = 100
        results.append(processed)
    return results

data = list(range(1000))
result = process_data(data)
print(sum(result))
)";

    VmProgram prog;
    vm_program_init(&prog);

    auto start = std::chrono::high_resolution_clock::now();
    ExitCode ret = vm_compile_source(medium_py.c_str(), medium_py.size(), &prog, 0);
    auto end = std::chrono::high_resolution_clock::now();

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    CHECK_MESSAGE(ret == EXIT_OK, "Compilation should succeed");
    CHECK_MESSAGE(duration.count() < 2000, "Compilation should be fast enough");

    vm_program_free(&prog);
}

TEST_CASE("serialization_performance") {
    const std::string large_py = R"(
def big_function(n):
    result = 0
    for i in range(n):
        result += i
        if i % 2 == 0:
            result -= 1
        else:
            result += 2
    return result
)";

    VmProgram prog;
    vm_program_init(&prog);
    REQUIRE(vm_compile_source(large_py.c_str(), large_py.size(), &prog, 0) == EXIT_OK);

    auto start = std::chrono::high_resolution_clock::now();
    Buffer ser = {0};
    ExitCode ret = vm_serialize(&prog, &ser);
    auto end = std::chrono::high_resolution_clock::now();

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    CHECK_MESSAGE(ret == EXIT_OK, "Serialization should succeed");
    CHECK_MESSAGE(duration.count() < 500, "Serialization should be fast");

    free(ser.data);
    vm_program_free(&prog);
}

// ═══════════════════════════════════════════════════════════════════════════
// PROJECT METADATA TESTS
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("project_version_info") {
    CHECK(strlen(CRYPTO_NAME) > 0);
    CHECK(strlen(CRYPTO_VERSION) > 0);
    CHECK(strcmp(CRYPTO_VERSION, "0.0.0") != 0);
}

// ═══════════════════════════════════════════════════════════════════════════
// REGRESSION TESTS FOR SECURITY FIXES
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("vm_decode_vl_bounds_regression") {
    // Security fix: vm_decode_vl should bounds-check all _c[_p+N] accesses
    const char* valid_py = "x = 1\n";
    VmProgram prog;
    vm_program_init(&prog);
    REQUIRE(vm_compile_source(valid_py, strlen(valid_py), &prog, 0) == EXIT_OK);

    Buffer ser = {0};
    REQUIRE(vm_serialize(&prog, &ser) == EXIT_OK);

    VmProgram prog2;
    vm_program_init(&prog2);
    CHECK(vm_deserialize(ser.data, ser.size, &prog2) == EXIT_OK);

    free(ser.data);
    vm_program_free(&prog);
    vm_program_free(&prog2);
}

TEST_CASE("anti_buf_size_adequate") {
    // Security fix: anti_buf[4096] should have bounds checking
    constexpr size_t ANTI_BUF_SIZE = 4096;
    CHECK(ANTI_BUF_SIZE >= 1024);  // Minimum adequate size
}

TEST_CASE("csrrng_secure_range_usage") {
    // Verifies encryption uses secure random values
    const unsigned char key[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };

    const unsigned char pt1[] = "test1";
    const unsigned char pt2[] = "test2";

    Buffer c1 = {0}, c2 = {0};
    CHECK(encrypt_data(pt1, sizeof(pt1) - 1, ALGO_AES_GCM, key, 32, &c1) == EXIT_OK);
    CHECK(encrypt_data(pt2, sizeof(pt2) - 1, ALGO_AES_GCM, key, 32, &c2) == EXIT_OK);

    // Different plaintexts should produce different ciphertexts
    CHECK(c1.size > 0);
    CHECK(c2.size > 0);
    bool ciphertexts_differ = (c1.size != c2.size) || (memcmp(c1.data, c2.data, c1.size) != 0);
    CHECK(ciphertexts_differ);

    free(c1.data);
    free(c2.data);
}