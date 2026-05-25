#include "crypto/chacha20.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>

#define CHACHA20_KEY_SIZE   32
#define CHACHA20_IV_SIZE    16
#define HMAC_KEY_SIZE       32
#define HMAC_SIZE           32
#define SALT_SIZE           16
#define PBKDF2_ITER        100000
#define DERIVED_SIZE        (CHACHA20_KEY_SIZE + CHACHA20_IV_SIZE + HMAC_KEY_SIZE)

static ExitCode derive_keys(const unsigned char *pass, size_t pass_len,
                            const unsigned char *salt, size_t salt_len,
                            unsigned char *out_key, unsigned char *out_iv,
                            unsigned char *out_hmac_key) {
    unsigned char derived[DERIVED_SIZE];
    int ret = PKCS5_PBKDF2_HMAC((const char *)pass, (int)pass_len,
                                 salt, (int)salt_len,
                                 PBKDF2_ITER, EVP_sha256(),
                                 DERIVED_SIZE, derived);
    if (ret != 1) {
        fprintf(stderr, "error: PBKDF2 key derivation failed\n");
        return EXIT_ERR_CRYPTO;
    }
    memcpy(out_key,     derived,                           CHACHA20_KEY_SIZE);
    memcpy(out_iv,      derived + CHACHA20_KEY_SIZE,       CHACHA20_IV_SIZE);
    memcpy(out_hmac_key, derived + CHACHA20_KEY_SIZE + CHACHA20_IV_SIZE, HMAC_KEY_SIZE);
    return EXIT_OK;
}

ExitCode chacha20_encrypt(const unsigned char *in, size_t in_size,
                          const unsigned char *key, size_t key_size,
                          Buffer *out) {
    if (!in || !out || in_size == 0) return EXIT_ERR_INTERNAL;
    if (!key || key_size == 0) {
        fprintf(stderr, "error: ChaCha20 requires a non-empty key\n");
        return EXIT_ERR_ARGS;
    }

    unsigned char salt[SALT_SIZE];
    if (RAND_bytes(salt, SALT_SIZE) != 1) {
        fprintf(stderr, "error: failed to generate random salt\n");
        return EXIT_ERR_CRYPTO;
    }

    unsigned char chacha_key[CHACHA20_KEY_SIZE];
    unsigned char chacha_iv[CHACHA20_IV_SIZE];
    unsigned char hmac_key[HMAC_KEY_SIZE];
    ExitCode ret = derive_keys(key, key_size, salt, SALT_SIZE,
                               chacha_key, chacha_iv, hmac_key);
    if (ret != EXIT_OK) return ret;

    size_t out_size = SALT_SIZE + in_size + HMAC_SIZE + 8;
    out->data = (unsigned char *)malloc(out_size);
    if (!out->data) return EXIT_ERR_CRYPTO;

    memcpy(out->data, salt, SALT_SIZE);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { free(out->data); return EXIT_ERR_CRYPTO; }

    if (EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, chacha_key, chacha_iv) != 1) {
        EVP_CIPHER_CTX_free(ctx); free(out->data);
        fprintf(stderr, "error: ChaCha20 init failed\n");
        return EXIT_ERR_CRYPTO;
    }

    int cipher_len = 0;
    if (EVP_EncryptUpdate(ctx, out->data + SALT_SIZE, &cipher_len, in, (int)in_size) != 1) {
        EVP_CIPHER_CTX_free(ctx); free(out->data);
        fprintf(stderr, "error: ChaCha20 encrypt failed\n");
        return EXIT_ERR_CRYPTO;
    }

    EVP_CIPHER_CTX_free(ctx);

    unsigned int hmac_len = 0;
    HMAC(EVP_sha256(), hmac_key, HMAC_KEY_SIZE,
         out->data + SALT_SIZE, (size_t)cipher_len,
         out->data + SALT_SIZE + cipher_len, &hmac_len);

    out->size = SALT_SIZE + (size_t)cipher_len + HMAC_SIZE;
    return EXIT_OK;
}

ExitCode chacha20_decrypt(const unsigned char *in, size_t in_size,
                          const unsigned char *key, size_t key_size,
                          Buffer *out) {
    if (!in || !out || in_size == 0) return EXIT_ERR_INTERNAL;
    if (!key || key_size == 0) {
        fprintf(stderr, "error: ChaCha20 requires a non-empty key\n");
        return EXIT_ERR_ARGS;
    }
    if (in_size <= SALT_SIZE + HMAC_SIZE) {
        fprintf(stderr, "error: corrupted data (too short)\n");
        return EXIT_ERR_CRYPTO;
    }

    const unsigned char *salt    = in;
    const unsigned char *cipher  = in + SALT_SIZE;
    size_t cipher_size = in_size - SALT_SIZE - HMAC_SIZE;
    const unsigned char *stored_hmac = in + in_size - HMAC_SIZE;

    unsigned char chacha_key[CHACHA20_KEY_SIZE];
    unsigned char chacha_iv[CHACHA20_IV_SIZE];
    unsigned char hmac_key[HMAC_KEY_SIZE];
    ExitCode ret = derive_keys(key, key_size, salt, SALT_SIZE,
                               chacha_key, chacha_iv, hmac_key);
    if (ret != EXIT_OK) return ret;

    unsigned char computed_hmac[HMAC_SIZE];
    unsigned int hmac_len = 0;
    HMAC(EVP_sha256(), hmac_key, HMAC_KEY_SIZE,
         cipher, cipher_size, computed_hmac, &hmac_len);

    if (hmac_len != HMAC_SIZE || CRYPTO_memcmp(computed_hmac, stored_hmac, HMAC_SIZE) != 0) {
        fprintf(stderr, "error: integrity check failed (wrong key or corrupted data)\n");
        return EXIT_ERR_CRYPTO;
    }

    out->data = (unsigned char *)malloc(cipher_size + 8);
    if (!out->data) return EXIT_ERR_CRYPTO;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { free(out->data); return EXIT_ERR_CRYPTO; }

    if (EVP_DecryptInit_ex(ctx, EVP_chacha20(), NULL, chacha_key, chacha_iv) != 1) {
        EVP_CIPHER_CTX_free(ctx); free(out->data);
        fprintf(stderr, "error: ChaCha20 init failed\n");
        return EXIT_ERR_CRYPTO;
    }

    int out_len = 0;
    if (EVP_DecryptUpdate(ctx, out->data, &out_len, cipher, (int)cipher_size) != 1) {
        EVP_CIPHER_CTX_free(ctx); free(out->data);
        fprintf(stderr, "error: ChaCha20 decrypt failed\n");
        return EXIT_ERR_CRYPTO;
    }
    out->size = (size_t)out_len;

    EVP_CIPHER_CTX_free(ctx);
    return EXIT_OK;
}
