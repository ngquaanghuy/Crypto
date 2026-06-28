#include "encode/xorcode.h"
#include "crypto/chacha20.h"
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

ExitCode prng_xor_encrypt(const unsigned char *in, size_t in_size,
                           const unsigned char *key, size_t key_size,
                           Buffer *out) {
    // PRNG-XOR uses ChaCha20 as a cryptographically strong PRNG
    // to generate a keystream for XORing the data.
    // This is functionally identical to ChaCha20 stream encryption.
    return chacha20_encrypt(in, in_size, key, key_size, out);
}

ExitCode prng_xor_decrypt(const unsigned char *in, size_t in_size,
                           const unsigned char *key, size_t key_size,
                           Buffer *out) {
    return chacha20_decrypt(in, in_size, key, key_size, out);
}

ExitCode prng_xor_encrypt_protect(const unsigned char *in, size_t in_size,
                                   const unsigned char *pass, size_t pass_len,
                                   Buffer *out) {
    if (!in || !out || in_size == 0) return EXIT_ERR_INTERNAL;
    if (!pass || pass_len == 0) {
        fprintf(stderr, "error: PRNG-XOR protect requires a non-empty key\n");
        return EXIT_ERR_ARGS;
    }

    unsigned char salt[XOR_SALT_SIZE];
    if (RAND_bytes(salt, XOR_SALT_SIZE) != 1) {
        fprintf(stderr, "error: failed to generate random salt\n");
        return EXIT_ERR_CRYPTO;
    }

    // Derive ChaCha20 key + IV + HMAC key via PBKDF2
    unsigned char chacha_key[32];
    unsigned char chacha_iv[16];
    unsigned char hmac_key[32];
    unsigned char derived[80];
    if (PKCS5_PBKDF2_HMAC((const char *)pass, (int)pass_len,
                           salt, XOR_SALT_SIZE,
                           100000, EVP_sha256(),
                           80, derived) != 1) {
        fprintf(stderr, "error: PBKDF2 key derivation failed\n");
        return EXIT_ERR_CRYPTO;
    }
    memcpy(chacha_key, derived, 32);
    memcpy(chacha_iv,  derived + 32, 16);
    memcpy(hmac_key,   derived + 48, 32);

    size_t max_out = XOR_SALT_SIZE + in_size + XOR_HMAC_SIZE;
    out->data = (unsigned char *)malloc(max_out);
    if (!out->data) return EXIT_ERR_CRYPTO;

    memcpy(out->data, salt, XOR_SALT_SIZE);

    // Encrypt using ChaCha20 as PRNG
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { free(out->data); return EXIT_ERR_CRYPTO; }

    if (EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, chacha_key, chacha_iv) != 1) {
        EVP_CIPHER_CTX_free(ctx); free(out->data);
        return EXIT_ERR_CRYPTO;
    }

    int cipher_len = 0;
    if (EVP_EncryptUpdate(ctx, out->data + XOR_SALT_SIZE, &cipher_len, in, (int)in_size) != 1) {
        EVP_CIPHER_CTX_free(ctx); free(out->data);
        return EXIT_ERR_CRYPTO;
    }
    EVP_CIPHER_CTX_free(ctx);

    unsigned int hmac_len = 0;
    HMAC(EVP_sha256(), hmac_key, 32,
         out->data + XOR_SALT_SIZE, (size_t)cipher_len,
         out->data + XOR_SALT_SIZE + cipher_len, &hmac_len);

    out->size = XOR_SALT_SIZE + (size_t)cipher_len + XOR_HMAC_SIZE;
    return EXIT_OK;
}

ExitCode prng_xor_decrypt_protect(const unsigned char *in, size_t in_size,
                                   const unsigned char *pass, size_t pass_len,
                                   Buffer *out) {
    if (!in || !out || in_size == 0) return EXIT_ERR_INTERNAL;
    if (!pass || pass_len == 0) {
        fprintf(stderr, "error: PRNG-XOR protect requires a non-empty key\n");
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

    unsigned char chacha_key[32];
    unsigned char chacha_iv[16];
    unsigned char hmac_key[32];
    unsigned char derived[80];
    if (PKCS5_PBKDF2_HMAC((const char *)pass, (int)pass_len,
                           salt, XOR_SALT_SIZE,
                           100000, EVP_sha256(),
                           80, derived) != 1) {
        fprintf(stderr, "error: PBKDF2 key derivation failed\n");
        return EXIT_ERR_CRYPTO;
    }
    memcpy(chacha_key, derived, 32);
    memcpy(chacha_iv,  derived + 32, 16);
    memcpy(hmac_key,   derived + 48, 32);

    unsigned char computed_hmac[XOR_HMAC_SIZE];
    unsigned int hmac_len = 0;
    HMAC(EVP_sha256(), hmac_key, 32,
         cipher, cipher_size, computed_hmac, &hmac_len);

    if (hmac_len != XOR_HMAC_SIZE ||
        CRYPTO_memcmp(computed_hmac, stored_hmac, XOR_HMAC_SIZE) != 0) {
        fprintf(stderr, "error: integrity check failed (wrong key or corrupted data)\n");
        return EXIT_ERR_CRYPTO;
    }

    out->data = (unsigned char *)malloc(cipher_size + 8);
    if (!out->data) return EXIT_ERR_CRYPTO;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { free(out->data); return EXIT_ERR_CRYPTO; }

    if (EVP_DecryptInit_ex(ctx, EVP_chacha20(), NULL, chacha_key, chacha_iv) != 1) {
        EVP_CIPHER_CTX_free(ctx); free(out->data);
        return EXIT_ERR_CRYPTO;
    }

    int out_len = 0;
    if (EVP_DecryptUpdate(ctx, out->data, &out_len, cipher, (int)cipher_size) != 1) {
        EVP_CIPHER_CTX_free(ctx); free(out->data);
        return EXIT_ERR_CRYPTO;
    }
    EVP_CIPHER_CTX_free(ctx);

    out->size = (size_t)out_len;
    return EXIT_OK;
}
