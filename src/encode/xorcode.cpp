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
    for (size_t i = 0; i < cipher_size; i++) {
        out->data[i] = cipher[i] ^ derived[i % XOR_KEY_SIZE];
    }
    out->size = cipher_size;

    return EXIT_OK;
}

ExitCode rolling_xor_encrypt_protect(const unsigned char *in, size_t in_size,
                                     const unsigned char *pass, size_t pass_len,
                                     Buffer *out) {
    if (!in || !out || in_size == 0) return EXIT_ERR_INTERNAL;
    if (!pass || pass_len == 0) {
        fprintf(stderr, "error: Rolling XOR protect requires a non-empty key\n");
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
    unsigned char state = derived[0];
    for (size_t i = 0; i < in_size; i++) {
        cipher[i] = in[i] ^ state;
        state = rotl8(cipher[i] ^ derived[(i + 1) % XOR_KEY_SIZE], 3) ^ 0x5A;
    }

    unsigned int hmac_len = 0;
    HMAC(EVP_sha256(), derived + XOR_KEY_SIZE, XOR_HMAC_SIZE,
         cipher, in_size,
         cipher + in_size, &hmac_len);

    out->size = XOR_SALT_SIZE + in_size + XOR_HMAC_SIZE;
    return EXIT_OK;
}

ExitCode rolling_xor_decrypt_protect(const unsigned char *in, size_t in_size,
                                     const unsigned char *pass, size_t pass_len,
                                     Buffer *out) {
    if (!in || !out || in_size == 0) return EXIT_ERR_INTERNAL;
    if (!pass || pass_len == 0) {
        fprintf(stderr, "error: Rolling XOR protect requires a non-empty key\n");
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
    unsigned char state = derived[0];
    for (size_t i = 0; i < cipher_size; i++) {
        out->data[i] = cipher[i] ^ state;
        state = rotl8(cipher[i] ^ derived[(i + 1) % XOR_KEY_SIZE], 3) ^ 0x5A;
    }
    out->size = cipher_size;

    return EXIT_OK;
}

static inline unsigned char rotl8_bits(unsigned char val, int shift) {
    shift &= 7;
    return (unsigned char)((val << shift) | (val >> (8 - shift)));
}

static inline unsigned char rotr8_bits(unsigned char val, int shift) {
    shift &= 7;
    return (unsigned char)((val >> shift) | (val << (8 - shift)));
}

ExitCode multi_pass_xor_encrypt(const unsigned char *in, size_t in_size,
                                 const unsigned char *key, size_t key_size,
                                 int num_passes,
                                 Buffer *out) {
    if (!in || !out || in_size == 0) return EXIT_ERR_INTERNAL;
    if (!key || key_size == 0) {
        fprintf(stderr, "error: Multi-pass XOR requires a non-empty key\n");
        return EXIT_ERR_ARGS;
    }
    if (num_passes < 1) num_passes = 3;

    out->data = (unsigned char *)malloc(in_size);
    if (!out->data) return EXIT_ERR_CRYPTO;
    memcpy(out->data, in, in_size);

    for (int p = 0; p < num_passes; p++) {
        int shift = (3 + p) & 7;
        unsigned char pass_const = (unsigned char)((p * 0x1B + 0x5A) & 0xFF);
        for (size_t i = 0; i < in_size; i++) {
            unsigned char b = out->data[i];
            b ^= key[((size_t)p * in_size + i) % key_size];
            b = rotl8_bits(b, shift);
            b ^= pass_const;
            out->data[i] = b;
        }
    }

    out->size = in_size;
    return EXIT_OK;
}

ExitCode multi_pass_xor_decrypt(const unsigned char *in, size_t in_size,
                                 const unsigned char *key, size_t key_size,
                                 int num_passes,
                                 Buffer *out) {
    if (!in || !out || in_size == 0) return EXIT_ERR_INTERNAL;
    if (!key || key_size == 0) {
        fprintf(stderr, "error: Multi-pass XOR requires a non-empty key\n");
        return EXIT_ERR_ARGS;
    }
    if (num_passes < 1) num_passes = 3;

    out->data = (unsigned char *)malloc(in_size);
    if (!out->data) return EXIT_ERR_CRYPTO;
    memcpy(out->data, in, in_size);

    for (int p = num_passes - 1; p >= 0; p--) {
        int shift = (3 + p) & 7;
        unsigned char pass_const = (unsigned char)((p * 0x1B + 0x5A) & 0xFF);
        for (size_t i = 0; i < in_size; i++) {
            unsigned char b = out->data[i];
            b ^= pass_const;
            b = rotr8_bits(b, shift);
            b ^= key[((size_t)p * in_size + i) % key_size];
            out->data[i] = b;
        }
    }

    out->size = in_size;
    return EXIT_OK;
}

ExitCode multi_pass_xor_encrypt_protect(const unsigned char *in, size_t in_size,
                                         const unsigned char *pass, size_t pass_len,
                                         Buffer *out) {
    if (!in || !out || in_size == 0) return EXIT_ERR_INTERNAL;
    if (!pass || pass_len == 0) {
        fprintf(stderr, "error: Multi-pass XOR protect requires a non-empty key\n");
        return EXIT_ERR_ARGS;
    }

    unsigned char salt[XOR_SALT_SIZE];
    if (RAND_bytes(salt, XOR_SALT_SIZE) != 1) {
        fprintf(stderr, "error: failed to generate random salt\n");
        return EXIT_ERR_CRYPTO;
    }

    int num_passes = 3 + (salt[0] & 7); // 3-10 passes based on salt

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
    memcpy(cipher, in, in_size);

    for (int p = 0; p < num_passes; p++) {
        int shift = (3 + p) & 7;
        unsigned char pass_const = (unsigned char)((p * 0x1B + 0x5A) & 0xFF);
        for (size_t i = 0; i < in_size; i++) {
            unsigned char b = cipher[i];
            b ^= derived[((size_t)p * in_size + i) % XOR_KEY_SIZE];
            b = rotl8_bits(b, shift);
            b ^= pass_const;
            cipher[i] = b;
        }
    }

    unsigned int hmac_len = 0;
    HMAC(EVP_sha256(), derived + XOR_KEY_SIZE, XOR_HMAC_SIZE,
         cipher, in_size,
         cipher + in_size, &hmac_len);

    out->size = XOR_SALT_SIZE + in_size + XOR_HMAC_SIZE;
    return EXIT_OK;
}

ExitCode multi_pass_xor_decrypt_protect(const unsigned char *in, size_t in_size,
                                         const unsigned char *pass, size_t pass_len,
                                         Buffer *out) {
    if (!in || !out || in_size == 0) return EXIT_ERR_INTERNAL;
    if (!pass || pass_len == 0) {
        fprintf(stderr, "error: Multi-pass XOR protect requires a non-empty key\n");
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

    int num_passes = 3 + (salt[0] & 7);

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
    memcpy(out->data, cipher, cipher_size);

    for (int p = num_passes - 1; p >= 0; p--) {
        int shift = (3 + p) & 7;
        unsigned char pass_const = (unsigned char)((p * 0x1B + 0x5A) & 0xFF);
        for (size_t i = 0; i < cipher_size; i++) {
            unsigned char b = out->data[i];
            b ^= pass_const;
            b = rotr8_bits(b, shift);
            b ^= derived[((size_t)p * cipher_size + i) % XOR_KEY_SIZE];
            out->data[i] = b;
        }
    }

    out->size = cipher_size;
    return EXIT_OK;
}

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

