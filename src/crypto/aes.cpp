#include "crypto/aes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>

#define AES_KEY_SIZE     32
#define HMAC_KEY_SIZE    32
#define HMAC_SIZE        32
#define SALT_SIZE        16
#define PBKDF2_ITER     100000
#define GCM_TAG_SIZE     16

static int iv_size(AesMode mode) {
    switch (mode) {
        case AES_ECB: return 0;
        case AES_CBC: return 16;
        case AES_CTR: return 16;
        case AES_GCM: return 12;
    }
    return 0;
}

static int derived_size(AesMode mode) {
    return AES_KEY_SIZE + iv_size(mode) + HMAC_KEY_SIZE;
}

static const EVP_CIPHER *cipher_for_mode(AesMode mode) {
    switch (mode) {
        case AES_ECB: return EVP_aes_256_ecb();
        case AES_CBC: return EVP_aes_256_cbc();
        case AES_CTR: return EVP_aes_256_ctr();
        case AES_GCM: return EVP_aes_256_gcm();
    }
    return NULL;
}

static ExitCode derive_keys(AesMode mode,
                            const unsigned char *pass, size_t pass_len,
                            const unsigned char *salt, size_t salt_len,
                            unsigned char *out_key, unsigned char *out_iv,
                            unsigned char *out_hmac_key) {
    int dsize = derived_size(mode);
    unsigned char *derived = (unsigned char *)malloc((size_t)dsize);
    if (!derived) return EXIT_ERR_CRYPTO;

    int ret = PKCS5_PBKDF2_HMAC((const char *)pass, (int)pass_len,
                                 salt, (int)salt_len,
                                 PBKDF2_ITER, EVP_sha256(),
                                 dsize, derived);
    if (ret != 1) {
        free(derived);
        fprintf(stderr, "error: PBKDF2 key derivation failed\n");
        return EXIT_ERR_CRYPTO;
    }

    int iv_sz = iv_size(mode);
    memcpy(out_key, derived, AES_KEY_SIZE);
    if (iv_sz > 0)
        memcpy(out_iv, derived + AES_KEY_SIZE, (size_t)iv_sz);
    memcpy(out_hmac_key, derived + AES_KEY_SIZE + iv_sz, HMAC_KEY_SIZE);
    free(derived);
    return EXIT_OK;
}

ExitCode aes_encrypt(const unsigned char *in, size_t in_size,
                     const unsigned char *key, size_t key_size,
                     AesMode mode, Buffer *out) {
    if (!in || !out || in_size == 0) return EXIT_ERR_INTERNAL;
    if (!key || key_size == 0) {
        fprintf(stderr, "error: AES requires a non-empty key\n");
        return EXIT_ERR_ARGS;
    }

    int iv_sz = iv_size(mode);
    int dsize = derived_size(mode);
    int is_stream = (mode == AES_CTR || mode == AES_GCM);

    unsigned char salt[SALT_SIZE];
    if (RAND_bytes(salt, SALT_SIZE) != 1) {
        fprintf(stderr, "error: failed to generate random salt\n");
        return EXIT_ERR_CRYPTO;
    }

    unsigned char aes_key[AES_KEY_SIZE];
    unsigned char aes_iv[16] = {0};
    unsigned char hmac_key[HMAC_KEY_SIZE];
    ExitCode ret = derive_keys(mode, key, key_size, salt, SALT_SIZE,
                                aes_key, aes_iv, hmac_key);
    if (ret != EXIT_OK) return ret;

    int block_size = 16;
    size_t cipher_max = is_stream ? in_size : in_size + block_size;

    size_t tag_size = (mode == AES_GCM) ? GCM_TAG_SIZE : 0;
    size_t max_out = SALT_SIZE + cipher_max + tag_size + HMAC_SIZE;
    out->data = (unsigned char *)malloc(max_out);
    if (!out->data) return EXIT_ERR_CRYPTO;

    memcpy(out->data, salt, SALT_SIZE);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (iv_sz > 0)
        EVP_EncryptInit_ex(ctx, cipher_for_mode(mode), NULL, aes_key, aes_iv);
    else
        EVP_EncryptInit_ex(ctx, cipher_for_mode(mode), NULL, aes_key, NULL);

    int cipher_len = 0;
    EVP_EncryptUpdate(ctx, out->data + SALT_SIZE, &cipher_len, in, (int)in_size);
    int final_len = 0;
    EVP_EncryptFinal_ex(ctx, out->data + SALT_SIZE + cipher_len, &final_len);
    if (mode == AES_GCM)
        cipher_len = (int)in_size;
    else
        cipher_len += final_len;

    unsigned char tag[GCM_TAG_SIZE] = {0};
    if (mode == AES_GCM) {
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE, tag);
        memcpy(out->data + SALT_SIZE + cipher_len, tag, GCM_TAG_SIZE);
    }

    EVP_CIPHER_CTX_free(ctx);

    size_t hmac_input_size = (size_t)cipher_len + tag_size;
    unsigned int hmac_len = 0;
    HMAC(EVP_sha256(), hmac_key, HMAC_KEY_SIZE,
         out->data + SALT_SIZE, hmac_input_size,
         out->data + SALT_SIZE + hmac_input_size, &hmac_len);

    out->size = SALT_SIZE + hmac_input_size + HMAC_SIZE;

    if (out->size > max_out) {
        free(out->data);
        out->data = NULL;
        return EXIT_ERR_INTERNAL;
    }

    return EXIT_OK;
}

ExitCode aes_decrypt(const unsigned char *in, size_t in_size,
                     const unsigned char *key, size_t key_size,
                     AesMode mode, Buffer *out) {
    if (!in || !out || in_size == 0) return EXIT_ERR_INTERNAL;
    if (!key || key_size == 0) {
        fprintf(stderr, "error: AES requires a non-empty key\n");
        return EXIT_ERR_ARGS;
    }

    int iv_sz = iv_size(mode);
    int dsize = derived_size(mode);
    int is_stream = (mode == AES_CTR || mode == AES_GCM);
    size_t tag_size = (mode == AES_GCM) ? GCM_TAG_SIZE : 0;

    size_t min_size = SALT_SIZE + (is_stream ? 0 : 1) + tag_size + HMAC_SIZE;
    if (in_size <= SALT_SIZE + tag_size + HMAC_SIZE) {
        fprintf(stderr, "error: corrupted data (too short)\n");
        return EXIT_ERR_CRYPTO;
    }

    const unsigned char *salt    = in;
    size_t hmac_input_size = in_size - SALT_SIZE - HMAC_SIZE;
    const unsigned char *hmac_input = in + SALT_SIZE;
    size_t cipher_size = hmac_input_size - tag_size;
    const unsigned char *cipher  = in + SALT_SIZE;
    const unsigned char *stored_tag = (mode == AES_GCM) ? in + SALT_SIZE + cipher_size : NULL;
    const unsigned char *stored_hmac = in + in_size - HMAC_SIZE;

    unsigned char aes_key[AES_KEY_SIZE];
    unsigned char aes_iv[16] = {0};
    unsigned char hmac_key[HMAC_KEY_SIZE];
    ExitCode ret = derive_keys(mode, key, key_size, salt, SALT_SIZE,
                                aes_key, aes_iv, hmac_key);
    if (ret != EXIT_OK) return ret;

    unsigned char computed_hmac[HMAC_SIZE];
    unsigned int hmac_len = 0;
    HMAC(EVP_sha256(), hmac_key, HMAC_KEY_SIZE,
         hmac_input, hmac_input_size, computed_hmac, &hmac_len);

    if (hmac_len != HMAC_SIZE || CRYPTO_memcmp(computed_hmac, stored_hmac, HMAC_SIZE) != 0) {
        fprintf(stderr, "error: integrity check failed (wrong key or corrupted data)\n");
        return EXIT_ERR_CRYPTO;
    }

    size_t max_out = cipher_size + 16;
    out->data = (unsigned char *)malloc(max_out);
    if (!out->data) return EXIT_ERR_CRYPTO;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (iv_sz > 0)
        EVP_DecryptInit_ex(ctx, cipher_for_mode(mode), NULL, aes_key, aes_iv);
    else
        EVP_DecryptInit_ex(ctx, cipher_for_mode(mode), NULL, aes_key, NULL);

    if (mode == AES_GCM) {
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_SIZE, (void *)stored_tag);
    }

    int out_len = 0;
    EVP_DecryptUpdate(ctx, out->data, &out_len, cipher, (int)cipher_size);

    int final_len = 0;
    int ok = EVP_DecryptFinal_ex(ctx, out->data + out_len, &final_len);
    if (ok <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        free(out->data);
        out->data = NULL;
        fprintf(stderr, "error: AES decryption failed (bad key or corrupted data)\n");
        return EXIT_ERR_CRYPTO;
    }
    out_len += final_len;
    out->size = (size_t)out_len;

    EVP_CIPHER_CTX_free(ctx);
    return EXIT_OK;
}
