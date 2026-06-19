#include "crypto/aes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define SALT_SIZE    16
#define NONCE_SIZE   16  /* Max AES IV length (CBC/CTR use 16, GCM uses 12) */
#define TAG_SIZE     16
#define KEY_DERIV_ITER 100000

static void derive_key(const unsigned char *password, size_t pwd_len,
                       const unsigned char *salt,
                       unsigned char *out_key, unsigned int key_len) {
    PKCS5_PBKDF2_HMAC((const char *)password, (int)pwd_len,
                      salt, SALT_SIZE, KEY_DERIV_ITER,
                      EVP_sha256(), key_len, out_key);
}

ExitCode aes_encrypt(const unsigned char *plaintext, size_t plaintext_len,
                     const unsigned char *key, size_t key_len,
                     AesMode mode, Buffer *out) {
    if (!plaintext || plaintext_len == 0 || !key || key_len == 0 || !out) {
        return EXIT_ERR_ARGS;
    }

    unsigned char salt[SALT_SIZE];
    if (RAND_bytes(salt, SALT_SIZE) != 1)
        return EXIT_ERR_CRYPTO;

    unsigned char aes_key[32]; // AES-256
    derive_key(key, key_len, salt, aes_key, 32);

    unsigned char nonce[NONCE_SIZE];
    memset(nonce, 0, NONCE_SIZE);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return EXIT_ERR_CRYPTO;

    const EVP_CIPHER *cipher = NULL;
    int iv_len = 0;

    switch (mode) {
        case AES_ECB:
            cipher = EVP_aes_256_ecb();
            iv_len = 0;
            break;
        case AES_CBC:
            cipher = EVP_aes_256_cbc();
            iv_len = 16;
            if (RAND_bytes(nonce, iv_len) != 1) { EVP_CIPHER_CTX_free(ctx); return EXIT_ERR_CRYPTO; }
            break;
        case AES_CTR:
            cipher = EVP_aes_256_ctr();
            iv_len = 16;
            if (RAND_bytes(nonce, iv_len) != 1) { EVP_CIPHER_CTX_free(ctx); return EXIT_ERR_CRYPTO; }
            break;
        case AES_GCM:
            cipher = EVP_aes_256_gcm();
            iv_len = 12;
            if (RAND_bytes(nonce, iv_len) != 1) { EVP_CIPHER_CTX_free(ctx); return EXIT_ERR_CRYPTO; }
            break;
        default:
            EVP_CIPHER_CTX_free(ctx);
            return EXIT_ERR_INTERNAL;
    }

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, aes_key, iv_len > 0 ? nonce : NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return EXIT_ERR_CRYPTO;
    }

    /* Allocate max output: salt + nonce/iv + plaintext + 16 (padding/tag) */
    size_t out_max = SALT_SIZE + iv_len + plaintext_len + 16;
    unsigned char *out_data = (unsigned char *)malloc(out_max);
    if (!out_data) { EVP_CIPHER_CTX_free(ctx); return EXIT_ERR_CRYPTO; }

    size_t pos = 0;
    memcpy(out_data + pos, salt, SALT_SIZE); pos += SALT_SIZE;
    if (iv_len > 0) {
        memcpy(out_data + pos, nonce, (size_t)iv_len);
        pos += (size_t)iv_len;
    }

    int outlen = 0;
    if (EVP_EncryptUpdate(ctx, out_data + pos, &outlen,
                          plaintext, (int)plaintext_len) != 1) {
        free(out_data); EVP_CIPHER_CTX_free(ctx);
        return EXIT_ERR_CRYPTO;
    }
    pos += (size_t)outlen;

    if (EVP_EncryptFinal_ex(ctx, out_data + pos, &outlen) != 1) {
        free(out_data); EVP_CIPHER_CTX_free(ctx);
        return EXIT_ERR_CRYPTO;
    }
    pos += (size_t)outlen;

    /* For GCM, append tag */
    if (mode == AES_GCM) {
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE,
                                out_data + pos) != 1) {
            free(out_data); EVP_CIPHER_CTX_free(ctx);
            return EXIT_ERR_CRYPTO;
        }
        pos += TAG_SIZE;
    }

    EVP_CIPHER_CTX_free(ctx);

    unsigned char *shrunk = (unsigned char *)realloc(out_data, pos);
    if (shrunk) out_data = shrunk;
    out->data = out_data;
    out->size = pos;
    return EXIT_OK;
}

ExitCode aes_decrypt(const unsigned char *ciphertext, size_t ciphertext_len,
                     const unsigned char *key, size_t key_len,
                     AesMode mode, Buffer *out) {
    if (!ciphertext || ciphertext_len == 0 || !key || key_len == 0 || !out) {
        return EXIT_ERR_ARGS;
    }

    int iv_len = 0;
    switch (mode) {
        case AES_ECB: iv_len = 0;  break;
        case AES_CBC:
        case AES_CTR: iv_len = 16; break;
        case AES_GCM: iv_len = 12; break;
        default: return EXIT_ERR_INTERNAL;
    }

    size_t min_len = (size_t)SALT_SIZE + (size_t)(iv_len > 0 ? iv_len : 0);
    size_t tag_len = (mode == AES_GCM) ? TAG_SIZE : 0;
    min_len += tag_len;

    if (ciphertext_len < min_len + 1) return EXIT_ERR_CRYPTO;

    const unsigned char *salt = ciphertext;
    const unsigned char *nonce = iv_len > 0 ? ciphertext + SALT_SIZE : NULL;
    const unsigned char *ct = ciphertext + SALT_SIZE + (iv_len > 0 ? (size_t)iv_len : 0);
    size_t ct_len = ciphertext_len - SALT_SIZE - (iv_len > 0 ? (size_t)iv_len : 0) - tag_len;

    unsigned char aes_key[32];
    derive_key(key, key_len, salt, aes_key, 32);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return EXIT_ERR_CRYPTO;

    const EVP_CIPHER *cipher = NULL;
    switch (mode) {
        case AES_ECB: cipher = EVP_aes_256_ecb(); break;
        case AES_CBC: cipher = EVP_aes_256_cbc(); break;
        case AES_CTR: cipher = EVP_aes_256_ctr(); break;
        case AES_GCM: cipher = EVP_aes_256_gcm(); break;
        default: EVP_CIPHER_CTX_free(ctx); return EXIT_ERR_INTERNAL;
    }

    if (EVP_DecryptInit_ex(ctx, cipher, NULL, aes_key,
                           nonce ? nonce : NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return EXIT_ERR_CRYPTO;
    }

    size_t out_max = ct_len + 16;
    unsigned char *out_data = (unsigned char *)malloc(out_max);
    if (!out_data) { EVP_CIPHER_CTX_free(ctx); return EXIT_ERR_CRYPTO; }

    int outlen = 0;
    if (EVP_DecryptUpdate(ctx, out_data, &outlen, ct, (int)ct_len) != 1) {
        free(out_data); EVP_CIPHER_CTX_free(ctx);
        return EXIT_ERR_CRYPTO;
    }
    size_t pos = (size_t)outlen;

    /* For GCM, set expected tag before Final */
    if (mode == AES_GCM) {
        const unsigned char *tag = ciphertext + ciphertext_len - TAG_SIZE;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE,
                                (void *)tag) != 1) {
            free(out_data); EVP_CIPHER_CTX_free(ctx);
            return EXIT_ERR_CRYPTO;
        }
    }

    int ret = EVP_DecryptFinal_ex(ctx, out_data + pos, &outlen);
    EVP_CIPHER_CTX_free(ctx);

    if (ret != 1) {
        free(out_data);
        return EXIT_ERR_CRYPTO; /* Authentication failed (GCM) or bad padding */
    }
    pos += (size_t)outlen;

    unsigned char *shrunk = (unsigned char *)realloc(out_data, pos);
    if (shrunk) out_data = shrunk;
    out->data = out_data;
    out->size = pos;
    return EXIT_OK;
}
