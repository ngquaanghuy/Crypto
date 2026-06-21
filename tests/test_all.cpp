#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "lib/doctest.h"

#include "crypto/common.h"
#include "encode/base64.h"
#include "encode/base32.h"
#include "encode/base85.h"
#include "encode/ascii85.h"
#include "encode/hexcode.h"
#include "encode/xorcode.h"
#include "crypto/aes.h"
#include "crypto/chacha20.h"
#include "crypto/chacha20_poly1305.h"
#include "crypto/xchacha20_poly1305.h"

#include <string.h>
#include <stdlib.h>

static int buf_eq(const Buffer *a, const Buffer *b) {
    if (a->size != b->size) return 0;
    return memcmp(a->data, b->data, a->size) == 0;
}

// ─── Base64 ──────────────────────────────────────────────────────────────────

TEST_CASE("base64 encode/decode") {
    const char *input = "hello crypto";
    size_t ilen = strlen(input);

    Buffer enc = {0}, dec = {0};
    CHECK(base64_encode((const unsigned char *)input, ilen, &enc) == EXIT_OK);
    CHECK(enc.size > 0);
    CHECK(enc.data[enc.size] == '\0');

    CHECK(base64_decode(enc.data, enc.size, &dec) == EXIT_OK);
    CHECK(dec.size == ilen);
    CHECK(memcmp(dec.data, input, ilen) == 0);

    free(enc.data); free(dec.data);
}

TEST_CASE("base64 various sizes") {
    for (int len = 1; len <= 64; len++) {
        unsigned char *raw = (unsigned char *)malloc((size_t)len);
        for (int i = 0; i < len; i++) raw[i] = (unsigned char)(i * 17 + 53);

        Buffer enc = {0}, dec = {0};
        REQUIRE(base64_encode(raw, (size_t)len, &enc) == EXIT_OK);
        REQUIRE(base64_decode(enc.data, enc.size, &dec) == EXIT_OK);
        CHECK(dec.size == (size_t)len);
        CHECK(memcmp(raw, dec.data, (size_t)len) == 0);

        free(raw); free(enc.data); free(dec.data);
    }
}

TEST_CASE("base64 empty input") {
    Buffer out = {0};
    CHECK(base64_encode(NULL, 0, &out) == EXIT_ERR_INTERNAL);
}

// ─── Base32 ──────────────────────────────────────────────────────────────────

TEST_CASE("base32 roundtrip") {
    const char *input = "hello crypto base32";
    size_t ilen = strlen(input);

    Buffer enc = {0}, dec = {0};
    CHECK(base32_encode((const unsigned char *)input, ilen, &enc) == EXIT_OK);
    CHECK(base32_decode(enc.data, enc.size, &dec) == EXIT_OK);
    CHECK(dec.size == ilen);
    CHECK(memcmp(dec.data, input, ilen) == 0);

    free(enc.data); free(dec.data);
}

TEST_CASE("base32 various sizes") {
    for (int len = 1; len <= 33; len++) {
        unsigned char *raw = (unsigned char *)malloc((size_t)len);
        for (int i = 0; i < len; i++) raw[i] = (unsigned char)(i * 7 + 11);

        Buffer enc = {0}, dec = {0};
        REQUIRE(base32_encode(raw, (size_t)len, &enc) == EXIT_OK);
        REQUIRE(base32_decode(enc.data, enc.size, &dec) == EXIT_OK);
        CHECK(dec.size == (size_t)len);
        CHECK(memcmp(raw, dec.data, (size_t)len) == 0);

        free(raw); free(enc.data); free(dec.data);
    }
}

// ─── Base85 ──────────────────────────────────────────────────────────────────

TEST_CASE("base85 roundtrip") {
    const char *input = "hello base85!";
    size_t ilen = strlen(input);

    Buffer enc = {0}, dec = {0};
    CHECK(base85_encode((const unsigned char *)input, ilen, &enc) == EXIT_OK);
    CHECK(base85_decode(enc.data, enc.size, &dec) == EXIT_OK);
    CHECK(dec.size == ilen);
    CHECK(memcmp(dec.data, input, ilen) == 0);

    free(enc.data); free(dec.data);
}

TEST_CASE("base85 all-zero encoding") {
    unsigned char raw[4] = {0, 0, 0, 0};
    Buffer enc = {0}, dec = {0};
    CHECK(base85_encode(raw, 4, &enc) == EXIT_OK);
    CHECK(enc.data[0] == '0');
    CHECK(enc.data[1] == '0');
    CHECK(enc.data[2] == '0');
    CHECK(enc.data[3] == '0');
    CHECK(enc.data[4] == '0');
    CHECK(base85_decode(enc.data, enc.size, &dec) == EXIT_OK);
    CHECK(dec.size == 4);
    CHECK(memcmp(raw, dec.data, 4) == 0);
    free(enc.data); free(dec.data);
}

TEST_CASE("base85 partial groups") {
    for (int len = 1; len <= 10; len++) {
        unsigned char *raw = (unsigned char *)malloc((size_t)len);
        for (int i = 0; i < len; i++) raw[i] = (unsigned char)(i * 13 + 7);

        Buffer enc = {0}, dec = {0};
        REQUIRE(base85_encode(raw, (size_t)len, &enc) == EXIT_OK);
        REQUIRE(base85_decode(enc.data, enc.size, &dec) == EXIT_OK);
        CHECK(dec.size == (size_t)len);
        CHECK(memcmp(raw, dec.data, (size_t)len) == 0);

        free(raw); free(enc.data); free(dec.data);
    }
}

// ─── Ascii85 ─────────────────────────────────────────────────────────────────

TEST_CASE("ascii85 roundtrip") {
    const char *input = "hello ascii85! @#$%";
    size_t ilen = strlen(input);

    Buffer enc = {0}, dec = {0};
    CHECK(ascii85_encode((const unsigned char *)input, ilen, &enc) == EXIT_OK);
    CHECK(enc.data[0] == '<');
    CHECK(enc.data[1] == '~');
    CHECK(enc.data[enc.size - 2] == '~');
    CHECK(enc.data[enc.size - 1] == '>');

    CHECK(ascii85_decode(enc.data, enc.size, &dec) == EXIT_OK);
    CHECK(dec.size == ilen);
    CHECK(memcmp(dec.data, input, ilen) == 0);

    free(enc.data); free(dec.data);
}

// ─── Hex ─────────────────────────────────────────────────────────────────────

TEST_CASE("hex encode/decode") {
    const char *input = "hex test 123!";
    size_t ilen = strlen(input);

    Buffer enc = {0}, dec = {0};
    CHECK(hex_encode((const unsigned char *)input, ilen, &enc) == EXIT_OK);
    CHECK(enc.size == ilen * 2);

    CHECK(hex_decode(enc.data, enc.size, &dec) == EXIT_OK);
    CHECK(dec.size == ilen);
    CHECK(memcmp(dec.data, input, ilen) == 0);

    free(enc.data); free(dec.data);
}

TEST_CASE("hex invalid input") {
    Buffer out = {0};
    CHECK(hex_decode((const unsigned char *)"abc", 3, &out) == EXIT_ERR_CRYPTO);
    CHECK(hex_decode((const unsigned char *)"xy", 2, &out) == EXIT_ERR_CRYPTO);
}

// ─── XOR ─────────────────────────────────────────────────────────────────────

TEST_CASE("xor transform") {
    const char *input = "xor test data here!";
    size_t ilen = strlen(input);
    const char *key = "mykey";

    Buffer out = {0};
    CHECK(xor_transform((const unsigned char *)input, ilen,
                        (const unsigned char *)key, strlen(key), &out) == EXIT_OK);
    CHECK(out.size == ilen);

    Buffer back = {0};
    CHECK(xor_transform(out.data, out.size,
                        (const unsigned char *)key, strlen(key), &back) == EXIT_OK);
    CHECK(back.size == ilen);
    CHECK(memcmp(input, back.data, ilen) == 0);

    free(out.data); free(back.data);
}

TEST_CASE("xor empty key fails") {
    Buffer out = {0};
    CHECK(xor_transform((const unsigned char *)"test", 4,
                        (const unsigned char *)"", 0, &out) == EXIT_ERR_ARGS);
}

// ─── AES (all modes) ─────────────────────────────────────────────────────────

TEST_CASE("aes-ecb encrypt/decrypt") {
    const char *input = "aes ecb secret data 123!";
    size_t ilen = strlen(input);
    const char *pass = "mypassword";

    Buffer enc = {0}, dec = {0};
    CHECK(aes_encrypt((const unsigned char *)input, ilen,
                      (const unsigned char *)pass, strlen(pass), AES_ECB, &enc) == EXIT_OK);
    CHECK(enc.size > ilen + 16);

    CHECK(aes_decrypt(enc.data, enc.size,
                      (const unsigned char *)pass, strlen(pass), AES_ECB, &dec) == EXIT_OK);
    CHECK(dec.size == ilen);
    CHECK(memcmp(input, dec.data, ilen) == 0);

    free(enc.data); free(dec.data);
}

TEST_CASE("aes-cbc encrypt/decrypt") {
    const char *input = "aes cbc secret data 123!";
    size_t ilen = strlen(input);
    const char *pass = "mypassword";

    Buffer enc = {0}, dec = {0};
    CHECK(aes_encrypt((const unsigned char *)input, ilen,
                      (const unsigned char *)pass, strlen(pass), AES_CBC, &enc) == EXIT_OK);
    CHECK(enc.size > ilen + 16);

    CHECK(aes_decrypt(enc.data, enc.size,
                      (const unsigned char *)pass, strlen(pass), AES_CBC, &dec) == EXIT_OK);
    CHECK(dec.size == ilen);
    CHECK(memcmp(input, dec.data, ilen) == 0);

    free(enc.data); free(dec.data);
}

TEST_CASE("aes-ctr encrypt/decrypt") {
    const char *input = "aes ctr secret data 123!";
    size_t ilen = strlen(input);
    const char *pass = "mypassword";

    Buffer enc = {0}, dec = {0};
    CHECK(aes_encrypt((const unsigned char *)input, ilen,
                      (const unsigned char *)pass, strlen(pass), AES_CTR, &enc) == EXIT_OK);
    CHECK(enc.size > ilen + 16);

    CHECK(aes_decrypt(enc.data, enc.size,
                      (const unsigned char *)pass, strlen(pass), AES_CTR, &dec) == EXIT_OK);
    CHECK(dec.size == ilen);
    CHECK(memcmp(input, dec.data, ilen) == 0);

    free(enc.data); free(dec.data);
}

TEST_CASE("aes-gcm encrypt/decrypt") {
    const char *input = "aes gcm secret data 123!";
    size_t ilen = strlen(input);
    const char *pass = "mypassword";

    Buffer enc = {0}, dec = {0};
    CHECK(aes_encrypt((const unsigned char *)input, ilen,
                      (const unsigned char *)pass, strlen(pass), AES_GCM, &enc) == EXIT_OK);
    CHECK(enc.size > ilen + 16);

    CHECK(aes_decrypt(enc.data, enc.size,
                      (const unsigned char *)pass, strlen(pass), AES_GCM, &dec) == EXIT_OK);
    CHECK(dec.size == ilen);
    CHECK(memcmp(input, dec.data, ilen) == 0);

    free(enc.data); free(dec.data);
}

TEST_CASE("aes wrong key fails") {
    const char *input = "test data here";
    size_t ilen = strlen(input);

    Buffer enc = {0}, dec = {0};
    REQUIRE(aes_encrypt((const unsigned char *)input, ilen,
                        (const unsigned char *)"right", 5, AES_GCM, &enc) == EXIT_OK);
    CHECK(aes_decrypt(enc.data, enc.size,
                      (const unsigned char *)"wrong", 5, AES_GCM, &dec) == EXIT_ERR_CRYPTO);

    free(enc.data);
}

TEST_CASE("aes corrupted data fails") {
    const char *input = "test data for corruption check";
    size_t ilen = strlen(input);

    Buffer enc = {0}, dec = {0};
    /* AES-GCM has built-in authentication tag, so corruption is always detected */
    REQUIRE(aes_encrypt((const unsigned char *)input, ilen,
                        (const unsigned char *)"pw", 2, AES_GCM, &enc) == EXIT_OK);
    if (enc.size > 20) enc.data[20] ^= 0xFF;
    CHECK(aes_decrypt(enc.data, enc.size,
                      (const unsigned char *)"pw", 2, AES_GCM, &dec) == EXIT_ERR_CRYPTO);

    free(enc.data);
}

TEST_CASE("aes empty key fails") {
    Buffer out = {0};
    CHECK(aes_encrypt((const unsigned char *)"t", 1,
                      (const unsigned char *)"", 0, AES_GCM, &out) == EXIT_ERR_ARGS);
}

TEST_CASE("aes all modes roundtrip various sizes") {
    const char *pass = "testkey";
    AesMode modes[] = {AES_ECB, AES_CBC, AES_CTR, AES_GCM};
    int sizes[] = {1, 3, 15, 16, 17, 31, 32, 33, 64, 65536};

    for (int m = 0; m < 4; m++) {
        for (int si = 0; si < 10; si++) {
            int len = sizes[si];
            unsigned char *raw = (unsigned char *)malloc((size_t)len);
            for (int i = 0; i < len; i++) raw[i] = (unsigned char)(i * 13 + len);

            Buffer enc = {0}, dec = {0};
            REQUIRE(aes_encrypt(raw, (size_t)len,
                                (const unsigned char *)pass, strlen(pass),
                                modes[m], &enc) == EXIT_OK);
            REQUIRE(aes_decrypt(enc.data, enc.size,
                                (const unsigned char *)pass, strlen(pass),
                                modes[m], &dec) == EXIT_OK);
            CHECK(dec.size == (size_t)len);
            CHECK(memcmp(raw, dec.data, (size_t)len) == 0);

            free(raw); free(enc.data); free(dec.data);
        }
    }
}

// ─── ChaCha20 ────────────────────────────────────────────────────────────────

TEST_CASE("chacha20 encrypt/decrypt") {
    const char *input = "chacha20 secret data! test 123";
    size_t ilen = strlen(input);
    const char *pass = "mypassword";

    Buffer enc = {0}, dec = {0};
    CHECK(chacha20_encrypt((const unsigned char *)input, ilen,
                           (const unsigned char *)pass, strlen(pass), &enc) == EXIT_OK);

    CHECK(chacha20_decrypt(enc.data, enc.size,
                           (const unsigned char *)pass, strlen(pass), &dec) == EXIT_OK);
    CHECK(dec.size == ilen);
    CHECK(memcmp(input, dec.data, ilen) == 0);

    free(enc.data); free(dec.data);
}

TEST_CASE("chacha20 wrong key fails (hmac)") {
    const char *input = "test data";
    size_t ilen = strlen(input);

    Buffer enc = {0}, dec = {0};
    REQUIRE(chacha20_encrypt((const unsigned char *)input, ilen,
                             (const unsigned char *)"right", 5, &enc) == EXIT_OK);
    CHECK(chacha20_decrypt(enc.data, enc.size,
                           (const unsigned char *)"wrong", 5, &dec) == EXIT_ERR_CRYPTO);

    free(enc.data);
}

TEST_CASE("chacha20 corrupted data fails") {
    const char *input = "corruption test for chacha";
    size_t ilen = strlen(input);

    Buffer enc = {0}, dec = {0};
    REQUIRE(chacha20_encrypt((const unsigned char *)input, ilen,
                             (const unsigned char *)"pw", 2, &enc) == EXIT_OK);
    if (enc.size > 20) enc.data[20] ^= 0xFF;
    CHECK(chacha20_decrypt(enc.data, enc.size,
                           (const unsigned char *)"pw", 2, &dec) == EXIT_ERR_CRYPTO);

    free(enc.data);
}

// ─── Large data ──────────────────────────────────────────────────────────────

TEST_CASE("large buffer roundtrip (64KB)") {
    size_t size = 65536;
    unsigned char *raw = (unsigned char *)malloc(size);
    for (size_t i = 0; i < size; i++) raw[i] = (unsigned char)(i * 31);

    SUBCASE("base64") {
        Buffer enc = {0}, dec = {0};
        REQUIRE(base64_encode(raw, size, &enc) == EXIT_OK);
        REQUIRE(base64_decode(enc.data, enc.size, &dec) == EXIT_OK);
        CHECK(dec.size == size);
        CHECK(memcmp(raw, dec.data, size) == 0);
        free(enc.data); free(dec.data);
    }

    SUBCASE("aes-gcm") {
        Buffer enc = {0}, dec = {0};
        REQUIRE(aes_encrypt(raw, size, (const unsigned char *)"largekey", 8, AES_GCM, &enc) == EXIT_OK);
        REQUIRE(aes_decrypt(enc.data, enc.size, (const unsigned char *)"largekey", 8, AES_GCM, &dec) == EXIT_OK);
        CHECK(dec.size == size);
        CHECK(memcmp(raw, dec.data, size) == 0);
        free(enc.data); free(dec.data);
    }

    free(raw);
}

// ─── ChaCha20-Poly1305 ────────────────────────────────────────────────────────────

TEST_CASE("chacha20-poly1305 encrypt/decrypt") {
    const char *input = "chacha20-poly1305 secret data! test 123";
    size_t ilen = strlen(input);
    const char *pass = "mypassword";

    Buffer enc = {0}, dec = {0};
    CHECK(chacha20_poly1305_encrypt((const unsigned char *)input, ilen,
                                     (const unsigned char *)pass, strlen(pass), &enc) == EXIT_OK);
    CHECK(enc.size > ilen + 16);

    CHECK(chacha20_poly1305_decrypt(enc.data, enc.size,
                                     (const unsigned char *)pass, strlen(pass), &dec) == EXIT_OK);
    CHECK(dec.size == ilen);
    CHECK(memcmp(input, dec.data, ilen) == 0);

    free(enc.data); free(dec.data);
}

TEST_CASE("chacha20-poly1305 wrong key fails") {
    const char *input = "test data";
    size_t ilen = strlen(input);

    Buffer enc = {0}, dec = {0};
    REQUIRE(chacha20_poly1305_encrypt((const unsigned char *)input, ilen,
                                       (const unsigned char *)"right", 5, &enc) == EXIT_OK);
    CHECK(chacha20_poly1305_decrypt(enc.data, enc.size,
                                     (const unsigned char *)"wrong", 5, &dec) == EXIT_ERR_CRYPTO);

    free(enc.data);
}

TEST_CASE("chacha20-poly1305 corrupted data fails") {
    const char *input = "corruption test for chacha20-poly1305";
    size_t ilen = strlen(input);

    Buffer enc = {0}, dec = {0};
    REQUIRE(chacha20_poly1305_encrypt((const unsigned char *)input, ilen,
                                       (const unsigned char *)"pw", 2, &enc) == EXIT_OK);
    if (enc.size > 20) enc.data[20] ^= 0xFF;
    CHECK(chacha20_poly1305_decrypt(enc.data, enc.size,
                                     (const unsigned char *)"pw", 2, &dec) == EXIT_ERR_CRYPTO);

    free(enc.data);
}

TEST_CASE("chacha20-poly1305 empty key fails") {
    Buffer out = {0};
    CHECK(chacha20_poly1305_encrypt((const unsigned char *)"t", 1,
                                     (const unsigned char *)"", 0, &out) == EXIT_ERR_ARGS);
}

// ─── XChaCha20-Poly1305 ───────────────────────────────────────────────────────────

TEST_CASE("xchacha20-poly1305 encrypt/decrypt") {
    const char *input = "xchacha20-poly1305 secret data! test 456";
    size_t ilen = strlen(input);
    const char *pass = "mypassword";

    Buffer enc = {0}, dec = {0};
    CHECK(xchacha20_poly1305_encrypt((const unsigned char *)input, ilen,
                                      (const unsigned char *)pass, strlen(pass), &enc) == EXIT_OK);
    CHECK(enc.size > ilen + 16);

    CHECK(xchacha20_poly1305_decrypt(enc.data, enc.size,
                                      (const unsigned char *)pass, strlen(pass), &dec) == EXIT_OK);
    CHECK(dec.size == ilen);
    CHECK(memcmp(input, dec.data, ilen) == 0);

    free(enc.data); free(dec.data);
}

TEST_CASE("xchacha20-poly1305 wrong key fails") {
    const char *input = "test data";
    size_t ilen = strlen(input);

    Buffer enc = {0}, dec = {0};
    REQUIRE(xchacha20_poly1305_encrypt((const unsigned char *)input, ilen,
                                        (const unsigned char *)"right", 5, &enc) == EXIT_OK);
    CHECK(xchacha20_poly1305_decrypt(enc.data, enc.size,
                                      (const unsigned char *)"wrong", 5, &dec) == EXIT_ERR_CRYPTO);

    free(enc.data);
}

TEST_CASE("xchacha20-poly1305 corrupted data fails") {
    const char *input = "corruption test for xchacha20-poly1305";
    size_t ilen = strlen(input);

    Buffer enc = {0}, dec = {0};
    REQUIRE(xchacha20_poly1305_encrypt((const unsigned char *)input, ilen,
                                        (const unsigned char *)"pw", 2, &enc) == EXIT_OK);
    if (enc.size > 20) enc.data[20] ^= 0xFF;
    CHECK(xchacha20_poly1305_decrypt(enc.data, enc.size,
                                      (const unsigned char *)"pw", 2, &dec) == EXIT_ERR_CRYPTO);

    free(enc.data);
}

TEST_CASE("xchacha20-poly1305 empty key fails") {
    Buffer out = {0};
    CHECK(xchacha20_poly1305_encrypt((const unsigned char *)"t", 1,
                                      (const unsigned char *)"", 0, &out) == EXIT_ERR_ARGS);
}

// ─── Rolling XOR ─────────────────────────────────────────────────────────────────

TEST_CASE("rolling-xor roundtrip") {
    const char *input = "rolling xor secret data!";
    size_t ilen = strlen(input);
    const char *key = "rollkey";

    Buffer enc = {0}, dec = {0};
    CHECK(rolling_xor_encrypt((const unsigned char *)input, ilen,
                             (const unsigned char *)key, strlen(key), &enc) == EXIT_OK);
    CHECK(enc.size == ilen);

    CHECK(rolling_xor_decrypt(enc.data, enc.size,
                             (const unsigned char *)key, strlen(key), &dec) == EXIT_OK);
    CHECK(dec.size == ilen);
    CHECK(memcmp(input, dec.data, ilen) == 0);

    free(enc.data); free(dec.data);
}

// ─── Multi-pass XOR ──────────────────────────────────────────────────────────────

TEST_CASE("multi-pass-xor roundtrip") {
    const char *input = "multi-pass xor secret data!";
    size_t ilen = strlen(input);
    const char *key = "multipass";
    int passes[] = {1, 3, 5, 10};

    for (int p : passes) {
        Buffer enc = {0}, dec = {0};
        REQUIRE(multi_pass_xor_encrypt((const unsigned char *)input, ilen,
                                      (const unsigned char *)key, strlen(key), p, &enc) == EXIT_OK);
        REQUIRE(multi_pass_xor_decrypt(enc.data, enc.size,
                                      (const unsigned char *)key, strlen(key), p, &dec) == EXIT_OK);
        CHECK(dec.size == ilen);
        CHECK(memcmp(input, dec.data, ilen) == 0);
        free(enc.data); free(dec.data);
    }
}

// ─── PRNG XOR ────────────────────────────────────────────────────────────────────

TEST_CASE("prng-xor roundtrip") {
    const char *input = "prng xor secret data!";
    size_t ilen = strlen(input);
    const char *key = "prngkey";

    Buffer enc = {0}, dec = {0};
    CHECK(prng_xor_encrypt((const unsigned char *)input, ilen,
                          (const unsigned char *)key, strlen(key), &enc) == EXIT_OK);
    CHECK(enc.size > ilen);

    CHECK(prng_xor_decrypt(enc.data, enc.size,
                          (const unsigned char *)key, strlen(key), &dec) == EXIT_OK);
    CHECK(dec.size == ilen);
    CHECK(memcmp(input, dec.data, ilen) == 0);

    free(enc.data); free(dec.data);
}
