# Crypto Test Suite

## Overview

Comprehensive regression test suite for the Crypto Python protection tool.

## Test Structure

```
tests/
├── test_all.cpp              - Core encryption/encoding tests (unit tests)
├── test_vm.cpp               - VM compilation and serialization tests
├── test_obfuscate.cpp        - Obfuscation pass tests
├── test_security_regression.cpp - Security regression tests (NEW)
├── test_integration.cpp       - End-to-end integration tests (NEW)
└── test_pyobf.py             - Python obfuscation tests
```

## Running Tests

```bash
# Build tests
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j4

# Run all tests
./build/test_crypto

# Run specific test categories
./build/test_crypto --test-case="*vm*"           # VM-related tests
./build/test_crypto --test-case="*crypto*"       # Crypto tests
./build/test_crypto --test-case="*security*"     # Security regression
./build/test_crypto --test-case="*integration*" # Integration tests

# Run with verbose output
./build/test_crypto -s

# List all test cases
./build/test_crypto --list-test-cases
```

## Test Coverage

### Security Regression Tests (`test_security_regression.cpp`)

Validates security fixes and prevents regressions:

| Test | Purpose | Security Issue Addressed |
|------|---------|------------------------|
| `vm_decode_vl_bounds_checking` | VM variable-length decoder bounds | Prevents OOB from truncated bytecode |
| `vm_serialize_deserialize_roundtrip` | Serialization integrity | Validates VM program roundtrip |
| `vm_deserialize_truncated_header` | Graceful handling of truncated data | No crash on malformed input |
| `vm_invalid_magic_handling` | Invalid header magic handling | No crash on random/malicious input |
| `aes_gcm_tag_position_consistency` | GCM tag position verification | Prevents auth bypass |
| `aes_all_modes_encrypt_decrypt` | All AES modes work | Full crypto coverage |
| `cipher_encrypt_decrypt_roundtrip` | End-to-end crypto | Validates AEAD modes |
| `csrrng_secure_range_usage` | Secure random for encryption | Ensures semantic security |
| `anti_buf_size_adequate` | Anti-analysis buffer size | Prevents buffer overflow |
| `algo_needs_key_consistency` | Key requirement validation | Correct algorithm handling |
| `base64_large_data` | Large input handling | Memory safety |

### Integration Tests (`test_integration.cpp`)

End-to-end workflow validation:

| Test | Purpose |
|------|---------|
| `full_protection_pipeline` | Python → VM → Encrypt → Decrypt → Deserialize |
| `complex_python_compilation_pipeline` | Large Python modules compile correctly |
| `cfi_enabled_compilation` | CFI obfuscation works |
| `obfuscation_enabled_compilation` | Obfuscation passes work |
| `invalid_python_integration` | Graceful handling of syntax errors |
| `corrupted_data_integration` | No crash on corrupted encrypted data |
| `compilation_performance_medium` | Performance regression detection |
| `serialization_performance` | Serialization speed validation |
| `project_version_info` | Version info correctly set |

### Core Unit Tests (`test_all.cpp`)

Basic unit tests for all algorithms:

- Base64/Base32/Base85/Ascii85 encoding roundtrip
- Hex encoding roundtrip
- XOR encryption variants (rolling, multi-pass, PRNG)
- AES all modes (ECB, CBC, CTR, GCM)
- ChaCha20 and ChaCha20-Poly1305
- XChaCha20-Poly1305

### VM Tests (`test_vm.cpp`)

VM compilation and execution:

- Variable-length encoding (short, medium, long classes)
- Fixed-length encoding
- Polymorphic encoding variants
- Register allocation
- Function calls and returns

## Key Security Validations

1. **Bounds Checking**: VM decoder validates all array accesses
2. **CSPRNG**: Security-sensitive values use `RAND_bytes()`
3. **AEAD Authentication**: GCM/Poly1305 tags verified correctly
4. **Atomic File Writes**: Temp file + rename pattern prevents corruption
5. **Graceful Degradation**: Invalid input handled without crashes

## Adding New Tests

### Unit Test Pattern

```cpp
TEST_CASE("descriptive_test_name") {
    // Arrange
    auto input = prepare_test_data();

    // Act
    ExitCode ret = function_under_test(input);

    // Assert
    CHECK(ret == EXIT_OK);
    CHECK(output_is_valid);
}
```

### Integration Test Pattern

```cpp
TEST_CASE("full_pipeline_test") {
    // 1. Compile Python to VM
    VmProgram prog;
    vm_program_init(&prog);
    CHECK(vm_compile_source(...) == EXIT_OK);

    // 2. Serialize
    Buffer ser = {0};
    CHECK(vm_serialize(&prog, &ser) == EXIT_OK);

    // 3. Encrypt
    Buffer enc = {0};
    CHECK(encrypt_data(...) == EXIT_OK);

    // 4. Verify roundtrip
    Buffer dec = {0};
    CHECK(decrypt_data(...) == EXIT_OK);
    CHECK(verify_output(dec));

    // Cleanup
    free(ser.data);
    free(enc.data);
    free(dec.data);
    vm_program_free(&prog);
}
```

### Security Regression Pattern

```cpp
TEST_CASE("security_fix_regression") {
    // 1. Valid input should work
    CHECK(operation(valid_input) == EXIT_OK);

    // 2. Malicious/truncated input should not crash
    CHECK(operation(truncated_data) != EXIT_CRASH);

    // 3. Verify security property
    CHECK(verify_security_property(output));
}
```

## CI/CD Integration

Add to your CI pipeline:

```bash
# Run tests in parallel
./build/test_crypto -j4

# Generate XML report for CI systems
./build/test_crypto --reporters=xml --out=report.xml

# Exit code 0 = success, non-zero = failure
```

## Dependencies

- doctest 2.5+ (header-only, included in `lib/`)
- OpenSSL 3.0+
- zlib
- liblzma
- libbrotli