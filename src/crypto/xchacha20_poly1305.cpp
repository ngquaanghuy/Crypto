#include "crypto/xchacha20_poly1305.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>

#define KEY_SIZE      32
#define NONCE_SIZE    24
#define XNONCE_HALF   16
#define TAG_SIZE      16
#define HMAC_KEY_SIZE 32
#define HMAC_SIZE     32
#define SALT_SIZE     16
#define PBKDF2_ITER  100000
#define DERIVED_SIZE  (KEY_SIZE + HMAC_KEY_SIZE)

static uint32_t le32dec(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void le32enc(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)(v);
    p[1] = (unsigned char)(v >> 8);
    p[2] = (unsigned char)(v >> 16);
    p[3] = (unsigned char)(v >> 24);
}

static uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

#define QROUND(a, b, c, d) \
    do { \
        a += b; d ^= a; d = rotl32(d, 16); \
        c += d; b ^= c; b = rotl32(b, 12); \
        a += b; d ^= a; d = rotl32(d,  8); \
        c += d; b ^= c; b = rotl32(b,  7); \
    } while (0)

static void hchacha20(const unsigned char key[32],
                      const unsigned char nonce[16],
                      unsigned char out[32]) {
    uint32_t state[16];
    static const uint32_t constants[4] = {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
    };

    state[0]  = constants[0];
    state[1]  = constants[1];
    state[2]  = constants[2];
    state[3]  = constants[3];
    state[4]  = le32dec(key +  0);
    state[5]  = le32dec(key +  4);
    state[6]  = le32dec(key +  8);
    state[7]  = le32dec(key + 12);
    state[8]  = le32dec(key + 16);
    state[9]  = le32dec(key + 20);
    state[10] = le32dec(key + 24);
    state[11] = le32dec(key + 28);
    state[12] = le32dec(nonce +  0);
    state[13] = le32dec(nonce +  4);
    state[14] = le32dec(nonce +  8);
    state[15] = le32dec(nonce + 12);

    uint32_t x[16];
    memcpy(x, state, sizeof(x));

    for (int i = 0; i < 10; i++) {
        QROUND(x[0], x[4], x[8],  x[12]);
        QROUND(x[1], x[5], x[9],  x[13]);
        QROUND(x[2], x[6], x[10], x[14]);
        QROUND(x[3], x[7], x[11], x[15]);
        QROUND(x[0], x[5], x[10], x[15]);
        QROUND(x[1], x[6], x[11], x[12]);
        QROUND(x[2], x[7], x[8],  x[13]);
        QROUND(x[3], x[4], x[9],  x[14]);
    }

    le32enc(out +  0, x[0]);
    le32enc(out +  4, x[1]);
    le32enc(out +  8, x[2]);
    le32enc(out + 12, x[3]);
    le32enc(out + 16, x[12]);
    le32enc(out + 20, x[13]);
    le32enc(out + 24, x[14]);
    le32enc(out + 28, x[15]);
}

static ExitCode derive_keys(const unsigned char *pass, size_t pass_len,
                            const unsigned char *salt, size_t salt_len,
                            unsigned char *out_key,
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
    memcpy(out_key,      derived,               KEY_SIZE);
    memcpy(out_hmac_key, derived + KEY_SIZE,     HMAC_KEY_SIZE);
    return EXIT_OK;
}

ExitCode xchacha20_poly1305_encrypt(const unsigned char *in, size_t in_size,
                                    const unsigned char *key, size_t key_size,
                                    Buffer *out) {
    if (!in || !out || in_size == 0) return EXIT_ERR_INTERNAL;
    if (!key || key_size == 0) {
        fprintf(stderr, "error: XChaCha20-Poly1305 requires a non-empty key\n");
        return EXIT_ERR_ARGS;
    }

    unsigned char salt[SALT_SIZE];
    unsigned char nonce[NONCE_SIZE];
    if (RAND_bytes(salt, SALT_SIZE) != 1 ||
        RAND_bytes(nonce, NONCE_SIZE) != 1) {
        fprintf(stderr, "error: failed to generate random salt/nonce\n");
        return EXIT_ERR_CRYPTO;
    }

    unsigned char enc_key[KEY_SIZE];
    unsigned char hmac_key[HMAC_KEY_SIZE];
    ExitCode ret = derive_keys(key, key_size, salt, SALT_SIZE,
                                enc_key, hmac_key);
    if (ret != EXIT_OK) return ret;

    unsigned char subkey[32];
    hchacha20(enc_key, nonce, subkey);

    unsigned char chacha_nonce[12] = {0};
    memcpy(chacha_nonce + 4, nonce + XNONCE_HALF, 8);

    size_t out_size = SALT_SIZE + NONCE_SIZE + in_size + TAG_SIZE + HMAC_SIZE;
    out->data = (unsigned char *)malloc(out_size);
    if (!out->data) return EXIT_ERR_CRYPTO;

    memcpy(out->data, salt, SALT_SIZE);
    memcpy(out->data + SALT_SIZE, nonce, NONCE_SIZE);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { free(out->data); return EXIT_ERR_CRYPTO; }

    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL,
                           subkey, chacha_nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx); free(out->data);
        fprintf(stderr, "error: XChaCha20-Poly1305 init failed\n");
        return EXIT_ERR_CRYPTO;
    }

    int cipher_len = 0;
    if (EVP_EncryptUpdate(ctx, out->data + SALT_SIZE + NONCE_SIZE,
                          &cipher_len, in, (int)in_size) != 1) {
        EVP_CIPHER_CTX_free(ctx); free(out->data);
        fprintf(stderr, "error: XChaCha20-Poly1305 encrypt failed\n");
        return EXIT_ERR_CRYPTO;
    }

    int final_len = 0;
    EVP_EncryptFinal_ex(ctx, out->data + SALT_SIZE + NONCE_SIZE + cipher_len,
                        &final_len);

    unsigned char tag[TAG_SIZE] = {0};
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_SIZE, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx); free(out->data);
        fprintf(stderr, "error: failed to get Poly1305 tag\n");
        return EXIT_ERR_CRYPTO;
    }

    EVP_CIPHER_CTX_free(ctx);

    memcpy(out->data + SALT_SIZE + NONCE_SIZE + cipher_len, tag, TAG_SIZE);

    size_t hmac_input_size = (size_t)cipher_len + TAG_SIZE;
    unsigned int hmac_len = 0;
    HMAC(EVP_sha256(), hmac_key, HMAC_KEY_SIZE,
         out->data + SALT_SIZE + NONCE_SIZE, hmac_input_size,
         out->data + SALT_SIZE + NONCE_SIZE + hmac_input_size, &hmac_len);

    out->size = SALT_SIZE + NONCE_SIZE + hmac_input_size + HMAC_SIZE;
    return EXIT_OK;
}

ExitCode xchacha20_poly1305_decrypt(const unsigned char *in, size_t in_size,
                                    const unsigned char *key, size_t key_size,
                                    Buffer *out) {
    if (!in || !out || in_size == 0) return EXIT_ERR_INTERNAL;
    if (!key || key_size == 0) {
        fprintf(stderr, "error: XChaCha20-Poly1305 requires a non-empty key\n");
        return EXIT_ERR_ARGS;
    }
    if (in_size <= SALT_SIZE + NONCE_SIZE + TAG_SIZE + HMAC_SIZE) {
        fprintf(stderr, "error: corrupted data (too short)\n");
        return EXIT_ERR_CRYPTO;
    }

    const unsigned char *salt       = in;
    const unsigned char *nonce      = in + SALT_SIZE;
    size_t hmac_input_size = in_size - SALT_SIZE - NONCE_SIZE - HMAC_SIZE;
    const unsigned char *hmac_input = in + SALT_SIZE + NONCE_SIZE;
    size_t cipher_size = hmac_input_size - TAG_SIZE;
    const unsigned char *cipher     = in + SALT_SIZE + NONCE_SIZE;
    const unsigned char *stored_tag = in + SALT_SIZE + NONCE_SIZE + cipher_size;
    const unsigned char *stored_hmac = in + in_size - HMAC_SIZE;

    unsigned char enc_key[KEY_SIZE];
    unsigned char hmac_key[HMAC_KEY_SIZE];
    ExitCode ret = derive_keys(key, key_size, salt, SALT_SIZE,
                                enc_key, hmac_key);
    if (ret != EXIT_OK) return ret;

    unsigned char computed_hmac[HMAC_SIZE];
    unsigned int hmac_len = 0;
    HMAC(EVP_sha256(), hmac_key, HMAC_KEY_SIZE,
         hmac_input, hmac_input_size, computed_hmac, &hmac_len);

    if (hmac_len != HMAC_SIZE ||
        CRYPTO_memcmp(computed_hmac, stored_hmac, HMAC_SIZE) != 0) {
        fprintf(stderr, "error: integrity check failed (wrong key or corrupted data)\n");
        return EXIT_ERR_CRYPTO;
    }

    unsigned char subkey[32];
    hchacha20(enc_key, nonce, subkey);

    unsigned char chacha_nonce[12] = {0};
    memcpy(chacha_nonce + 4, nonce + XNONCE_HALF, 8);

    out->data = (unsigned char *)malloc(cipher_size + 16);
    if (!out->data) return EXIT_ERR_CRYPTO;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { free(out->data); return EXIT_ERR_CRYPTO; }

    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL,
                           subkey, chacha_nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx); free(out->data);
        fprintf(stderr, "error: XChaCha20-Poly1305 init failed\n");
        return EXIT_ERR_CRYPTO;
    }

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG_SIZE,
                        (void *)stored_tag);

    int out_len = 0;
    if (EVP_DecryptUpdate(ctx, out->data, &out_len, cipher,
                          (int)cipher_size) != 1) {
        EVP_CIPHER_CTX_free(ctx); free(out->data);
        fprintf(stderr, "error: XChaCha20-Poly1305 decrypt failed\n");
        return EXIT_ERR_CRYPTO;
    }

    int final_len = 0;
    int ok = EVP_DecryptFinal_ex(ctx, out->data + out_len, &final_len);
    if (ok <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        free(out->data);
        out->data = NULL;
        fprintf(stderr, "error: XChaCha20-Poly1305 AEAD verification failed\n");
        return EXIT_ERR_CRYPTO;
    }
    out_len += final_len;
    out->size = (size_t)out_len;

    EVP_CIPHER_CTX_free(ctx);
    return EXIT_OK;
}
