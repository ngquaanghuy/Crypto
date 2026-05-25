#include "encode/xorcode.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

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

ExitCode xor_encrypt_protect(const unsigned char *in, size_t in_size,
                              const unsigned char *pass, size_t pass_len,
                              Buffer *out) {
    if (!in || !out || in_size == 0) return EXIT_ERR_INTERNAL;
    if (!pass || pass_len == 0) {
        fprintf(stderr, "error: XOR protect requires a non-empty key\n");
        return EXIT_ERR_ARGS;
    }

    unsigned char salt[XOR_SALT_SIZE];
    if (RAND_bytes(salt, XOR_SALT_SIZE) != 1) {
        fprintf(stderr, "error: failed to generate random salt\n");
        return EXIT_ERR_CRYPTO;
    }

    unsigned char derived[XOR_DERIVED_SIZE];
    if (PKCS5_PBKDF2_HMAC((const char *)pass, (int)pass_len,
                           salt, XOR_SALT_SIZE,
                           XOR_PBKDF2_ITER, EVP_sha256(),
                           XOR_DERIVED_SIZE, derived) != 1) {
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

    unsigned int hmac_len = 0;
    HMAC(EVP_sha256(), derived + XOR_KEY_SIZE, XOR_HMAC_SIZE,
         cipher, in_size,
         cipher + in_size, &hmac_len);

    out->size = XOR_SALT_SIZE + in_size + XOR_HMAC_SIZE;

    if (out->size > max_out) {
        free(out->data);
        out->data = NULL;
        return EXIT_ERR_INTERNAL;
    }

    return EXIT_OK;
}

ExitCode xor_decrypt_protect(const unsigned char *in, size_t in_size,
                              const unsigned char *pass, size_t pass_len,
                              Buffer *out) {
    if (!in || !out || in_size == 0) return EXIT_ERR_INTERNAL;
    if (!pass || pass_len == 0) {
        fprintf(stderr, "error: XOR protect requires a non-empty key\n");
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

    unsigned char derived[XOR_DERIVED_SIZE];
    if (PKCS5_PBKDF2_HMAC((const char *)pass, (int)pass_len,
                           salt, XOR_SALT_SIZE,
                           XOR_PBKDF2_ITER, EVP_sha256(),
                           XOR_DERIVED_SIZE, derived) != 1) {
        fprintf(stderr, "error: PBKDF2 key derivation failed\n");
        return EXIT_ERR_CRYPTO;
    }

    unsigned char computed_hmac[XOR_HMAC_SIZE];
    unsigned int hmac_len = 0;
    HMAC(EVP_sha256(), derived + XOR_KEY_SIZE, XOR_HMAC_SIZE,
         cipher, cipher_size, computed_hmac, &hmac_len);

    if (hmac_len != XOR_HMAC_SIZE ||
        CRYPTO_memcmp(computed_hmac, stored_hmac, XOR_HMAC_SIZE) != 0) {
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
