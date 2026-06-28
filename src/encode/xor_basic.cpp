#include "encode/xorcode.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <stdint.h>

#define XOR_PBKDF2_ITER  100000
#define XOR_DERIVED_SIZE (XOR_KEY_SIZE + XOR_HMAC_SIZE)

ExitCode xor_transform(const unsigned char *in, size_t in_size,
                        const unsigned char *key, size_t key_size,
                        Buffer *out) {
    if (!in || !out || in_size == 0) return EXIT_ERR_INTERNAL;
    if (!key || key_size == 0) {
        fprintf(stderr, "error: XOR requires a non-empty key\n");
        return EXIT_ERR_ARGS;
    }

    out->data = (unsigned char *)malloc(in_size);
    if (!out->data) return EXIT_ERR_CRYPTO;

    for (size_t i = 0; i < in_size; i++)
        out->data[i] = in[i] ^ key[i % key_size];

    out->size = in_size;
    return EXIT_OK;
}

// Authenticated XOR transform: uses salt + HMAC for integrity
// Output format: salt(16) + ciphertext(N) + HMAC(32)
ExitCode xor_transform_auth(const unsigned char *in, size_t in_size,
                            const unsigned char *key, size_t key_size,
                            Buffer *out) {
    if (!in || !out || in_size == 0) return EXIT_ERR_INTERNAL;
    if (!key || key_size == 0) {
        fprintf(stderr, "error: XOR requires a non-empty key\n");
        return EXIT_ERR_ARGS;
    }

    unsigned char salt[XOR_SALT_SIZE];
    if (RAND_bytes(salt, XOR_SALT_SIZE) != 1) {
        fprintf(stderr, "error: failed to generate random salt\n");
        return EXIT_ERR_CRYPTO;
    }

    unsigned char derived[XOR_KEY_SIZE + XOR_HMAC_SIZE];
    if (PKCS5_PBKDF2_HMAC((const char *)key, (int)key_size,
                           salt, XOR_SALT_SIZE,
                           XOR_PBKDF2_ITER, EVP_sha256(),
                           sizeof(derived), derived) != 1) {
        fprintf(stderr, "error: PBKDF2 key derivation failed\n");
        return EXIT_ERR_CRYPTO;
    }

    size_t max_out = XOR_SALT_SIZE + in_size + XOR_HMAC_SIZE;
    out->data = (unsigned char *)malloc(max_out);
    if (!out->data) return EXIT_ERR_CRYPTO;

    memcpy(out->data, salt, XOR_SALT_SIZE);
    unsigned char *cipher = out->data + XOR_SALT_SIZE;

    for (size_t i = 0; i < in_size; i++)
        cipher[i] = in[i] ^ derived[i % XOR_KEY_SIZE];

    HMAC(EVP_sha256(), derived + XOR_KEY_SIZE, XOR_HMAC_SIZE,
         cipher, in_size, cipher + in_size, NULL);

    out->size = max_out;
    return EXIT_OK;
}

// Decrypt authenticated XOR: verifies HMAC before decryption
ExitCode xor_decrypt_auth(const unsigned char *in, size_t in_size,
                           const unsigned char *key, size_t key_size,
                           Buffer *out) {
    if (!in || !out || in_size == 0) return EXIT_ERR_INTERNAL;
    if (!key || key_size == 0) {
        fprintf(stderr, "error: XOR requires a non-empty key\n");
        return EXIT_ERR_ARGS;
    }
    if (in_size <= XOR_SALT_SIZE + XOR_HMAC_SIZE) {
        fprintf(stderr, "error: corrupted data (too short)\n");
        return EXIT_ERR_CRYPTO;
    }

    const unsigned char *salt = in;
    const unsigned char *cipher = in + XOR_SALT_SIZE;
    size_t cipher_size = in_size - XOR_SALT_SIZE - XOR_HMAC_SIZE;
    const unsigned char *stored_hmac = in + in_size - XOR_HMAC_SIZE;

    unsigned char derived[XOR_KEY_SIZE + XOR_HMAC_SIZE];
    if (PKCS5_PBKDF2_HMAC((const char *)key, (int)key_size,
                           salt, XOR_SALT_SIZE,
                           XOR_PBKDF2_ITER, EVP_sha256(),
                           sizeof(derived), derived) != 1) {
        fprintf(stderr, "error: PBKDF2 key derivation failed\n");
        return EXIT_ERR_CRYPTO;
    }

    unsigned char computed_hmac[XOR_HMAC_SIZE];
    HMAC(EVP_sha256(), derived + XOR_KEY_SIZE, XOR_HMAC_SIZE,
         cipher, cipher_size, computed_hmac, NULL);

    if (CRYPTO_memcmp(computed_hmac, stored_hmac, XOR_HMAC_SIZE) != 0) {
        fprintf(stderr, "error: integrity check failed (wrong key or corrupted data)\n");
        return EXIT_ERR_CRYPTO;
    }

    out->data = (unsigned char *)malloc(cipher_size);
    if (!out->data) return EXIT_ERR_CRYPTO;

    for (size_t i = 0; i < cipher_size; i++)
        out->data[i] = cipher[i] ^ derived[i % XOR_KEY_SIZE];

    out->size = cipher_size;
    return EXIT_OK;
}

static inline unsigned char rotl8(unsigned char val, int shift) {
    return (val << shift) | (val >> (8 - shift));
}

static inline unsigned char rotr8(unsigned char val, int shift) {
    return (val >> shift) | (val << (8 - shift));
}

ExitCode rolling_xor_encrypt(const unsigned char *in, size_t in_size,
                             const unsigned char *key, size_t key_size,
                             Buffer *out) {
    if (!in || !out || in_size == 0) return EXIT_ERR_INTERNAL;
    if (!key || key_size == 0) {
        fprintf(stderr, "error: Rolling XOR requires a non-empty key\n");
        return EXIT_ERR_ARGS;
    }

    out->data = (unsigned char *)malloc(in_size);
    if (!out->data) return EXIT_ERR_CRYPTO;

    unsigned char state = key[0];
    for (size_t i = 0; i < in_size; i++) {
        out->data[i] = in[i] ^ state;
        state = rotl8(out->data[i] ^ key[(i + 1) % key_size], 3) ^ 0x5A;
    }

    out->size = in_size;
    return EXIT_OK;
}

ExitCode rolling_xor_decrypt(const unsigned char *in, size_t in_size,
                                 const unsigned char *key, size_t key_size,
                                 Buffer *out) {
    if (!in || !out || in_size == 0) return EXIT_ERR_INTERNAL;
    if (!key || key_size == 0) {
        fprintf(stderr, "error: Rolling XOR requires a non-empty key\n");
        return EXIT_ERR_ARGS;
    }

    out->data = (unsigned char *)malloc(in_size);
    if (!out->data) return EXIT_ERR_CRYPTO;

    unsigned char state = key[0];
    for (size_t i = 0; i < in_size; i++) {
        out->data[i] = in[i] ^ state;
        state = rotl8(in[i] ^ key[(i + 1) % key_size], 3) ^ 0x5A;
    }

    out->size = in_size;
    return EXIT_OK;
}

ExitCode xor_bit_rotation_encrypt(const unsigned char *in, size_t in_size,
                                  const unsigned char *key, size_t key_size,
                                  Buffer *out) {
    if (!in || !out || in_size == 0) return EXIT_ERR_INTERNAL;
    if (!key || key_size == 0) return EXIT_ERR_ARGS;

    out->data = (unsigned char *)malloc(in_size);
    if (!out->data) return EXIT_ERR_CRYPTO;

    for (size_t i = 0; i < in_size; i++) {
        unsigned char xored = in[i] ^ key[i % key_size];
        out->data[i] = rotl8(xored, 3);
    }

    out->size = in_size;
    return EXIT_OK;
}

ExitCode xor_bit_rotation_decrypt(const unsigned char *in, size_t in_size,
                                  const unsigned char *key, size_t key_size,
                                  Buffer *out) {
    if (!in || !out || in_size == 0) return EXIT_ERR_INTERNAL;
    if (!key || key_size == 0) return EXIT_ERR_ARGS;

    out->data = (unsigned char *)malloc(in_size);
    if (!out->data) return EXIT_ERR_CRYPTO;

    for (size_t i = 0; i < in_size; i++) {
        unsigned char rotated = rotr8(in[i], 3);
        out->data[i] = rotated ^ key[i % key_size];
    }

    out->size = in_size;
    return EXIT_OK;
}
