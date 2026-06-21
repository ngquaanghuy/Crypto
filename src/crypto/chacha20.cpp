#include "crypto/chacha20.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>

#define SALT_SIZE     16
#define CHACHA_NONCE_SIZE 16 /* OpenSSL EVP_chacha20 uses 4-byte counter + 12-byte nonce = 16-byte IV */
#define KEY_DERIV_ITER 100000
#define HMAC_SIZE      32

/* ─── Derive key via PBKDF2 ─────────────────────────────── */
static void derive_key(const unsigned char *password, size_t pwd_len,
                       const unsigned char *salt,
                       unsigned char *out_key, unsigned int key_len) {
    PKCS5_PBKDF2_HMAC((const char *)password, (int)pwd_len,
                      salt, SALT_SIZE, KEY_DERIV_ITER,
                      EVP_sha256(), key_len, out_key);
}

/* ─── HMAC-SHA256 helper ────────────────────────────────── */
static void compute_hmac(const unsigned char *key, size_t key_len,
                         const unsigned char *data, size_t data_len,
                         unsigned char *out_hmac) {
    unsigned int hmac_len = HMAC_SIZE;
    HMAC(EVP_sha256(), key, (int)key_len,
         data, data_len, out_hmac, &hmac_len);
}

ExitCode chacha20_encrypt(const unsigned char *plaintext, size_t plaintext_len,
                          const unsigned char *key, size_t key_len,
                          Buffer *out) {
    if (!plaintext || plaintext_len == 0 || !key || key_len == 0 || !out) {
        return EXIT_ERR_ARGS;
    }

    unsigned char salt[SALT_SIZE];
    if (RAND_bytes(salt, SALT_SIZE) != 1)
        return EXIT_ERR_CRYPTO;

    unsigned char chacha_key[32];
    derive_key(key, key_len, salt, chacha_key, 32);

    unsigned char nonce[CHACHA_NONCE_SIZE];
    if (RAND_bytes(nonce, CHACHA_NONCE_SIZE) != 1)
        return EXIT_ERR_CRYPTO;

    /* Allocate: salt(16) + nonce(12) + ciphertext + HMAC(32) */
    size_t out_max = SALT_SIZE + CHACHA_NONCE_SIZE + plaintext_len + HMAC_SIZE;
    unsigned char *out_data = (unsigned char *)malloc(out_max);
    if (!out_data) return EXIT_ERR_CRYPTO;

    size_t pos = 0;
    memcpy(out_data + pos, salt, SALT_SIZE); pos += SALT_SIZE;
    memcpy(out_data + pos, nonce, CHACHA_NONCE_SIZE); pos += CHACHA_NONCE_SIZE;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { free(out_data); return EXIT_ERR_CRYPTO; }

    if (EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, chacha_key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx); free(out_data);
        return EXIT_ERR_CRYPTO;
    }

    int outlen = 0;
    if (EVP_EncryptUpdate(ctx, out_data + pos, &outlen,
                          plaintext, (int)plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx); free(out_data);
        return EXIT_ERR_CRYPTO;
    }
    pos += (size_t)outlen;

    int finallen = 0;
    EVP_EncryptFinal_ex(ctx, out_data + pos, &finallen);
    pos += (size_t)finallen;
    EVP_CIPHER_CTX_free(ctx);

    /* Compute HMAC over salt + nonce + ciphertext */
    compute_hmac(chacha_key, 32, out_data, pos, out_data + pos);
    pos += HMAC_SIZE;

    unsigned char *shrunk = (unsigned char *)realloc(out_data, pos);
    if (shrunk) out_data = shrunk;
    out->data = out_data;
    out->size = pos;
    return EXIT_OK;
}

ExitCode chacha20_decrypt(const unsigned char *ciphertext, size_t ciphertext_len,
                          const unsigned char *key, size_t key_len,
                          Buffer *out) {
    if (!ciphertext || ciphertext_len == 0 || !key || key_len == 0 || !out) {
        return EXIT_ERR_ARGS;
    }

    size_t min_len = SALT_SIZE + CHACHA_NONCE_SIZE + HMAC_SIZE + 1;
    if (ciphertext_len < min_len) return EXIT_ERR_CRYPTO;

    const unsigned char *salt     = ciphertext;
    const unsigned char *nonce    = ciphertext + SALT_SIZE;
    size_t ct_len = ciphertext_len - SALT_SIZE - CHACHA_NONCE_SIZE - HMAC_SIZE;
    const unsigned char *ct       = ciphertext + SALT_SIZE + CHACHA_NONCE_SIZE;
    const unsigned char *expected_hmac = ct + ct_len;

    unsigned char chacha_key[32];
    derive_key(key, key_len, salt, chacha_key, 32);

    /* Verify HMAC */
    unsigned char computed_hmac[HMAC_SIZE];
    size_t data_len = SALT_SIZE + CHACHA_NONCE_SIZE + ct_len;
    compute_hmac(chacha_key, 32, ciphertext, data_len, computed_hmac);

    if (CRYPTO_memcmp(computed_hmac, expected_hmac, HMAC_SIZE) != 0) {
        return EXIT_ERR_CRYPTO; /* Integrity check failed */
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return EXIT_ERR_CRYPTO;

    if (EVP_DecryptInit_ex(ctx, EVP_chacha20(), NULL, chacha_key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return EXIT_ERR_CRYPTO;
    }

    unsigned char *out_data = (unsigned char *)malloc(ct_len + 1);
    if (!out_data) { EVP_CIPHER_CTX_free(ctx); return EXIT_ERR_CRYPTO; }

    int outlen = 0;
    if (EVP_DecryptUpdate(ctx, out_data, &outlen, ct, (int)ct_len) != 1) {
        free(out_data); EVP_CIPHER_CTX_free(ctx);
        return EXIT_ERR_CRYPTO;
    }

    int finallen = 0;
    EVP_DecryptFinal_ex(ctx, out_data + outlen, &finallen);
    EVP_CIPHER_CTX_free(ctx);

    size_t total = (size_t)(outlen + finallen);
    unsigned char *shrunk = (unsigned char *)realloc(out_data, total);
    if (shrunk) out_data = shrunk;
    out->data = out_data;
    out->size = total;
    return EXIT_OK;
}
