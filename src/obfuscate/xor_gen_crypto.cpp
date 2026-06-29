#include "crypto/obfuscate.h"
#include "obfuscate/xor_gen_crypto.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

/* ── HMAC-based key derivation (HKDF-expand style) ── */
ExitCode xorgen_derive_keys(const unsigned char *master_key, size_t master_len,
                            const unsigned char *salt, size_t salt_len,
                            unsigned char *out_enc_key, size_t enc_key_len,
                            unsigned char *out_hmac_key, size_t hmac_key_len) {
    if (!master_key || master_len == 0) return EXIT_ERR_ARGS;

    unsigned char prk[32];
    unsigned int prk_len = 32;
    HMAC(EVP_sha256(), salt, (int)salt_len,
         master_key, (int)master_len, prk, &prk_len);

    unsigned char derived[64];
    unsigned char t1[32];
    unsigned int tlen = 32;

    unsigned char one = 1;
    HMAC(EVP_sha256(), prk, 32, &one, 1, t1, &tlen);
    memcpy(derived, t1, 32);

    unsigned char input[33];
    memcpy(input, t1, 32);
    input[32] = 2;
    HMAC(EVP_sha256(), prk, 32, input, 33, t1, &tlen);
    memcpy(derived + 32, t1, 32);

    size_t to_copy = enc_key_len < 32 ? enc_key_len : 32;
    memcpy(out_enc_key, derived, to_copy);

    to_copy = hmac_key_len < 32 ? hmac_key_len : 32;
    memcpy(out_hmac_key, derived + 32, to_copy);

    return EXIT_OK;
}

/* ── ChaCha20 encryption + HMAC integrity tag ── */
ExitCode xorgen_chacha20_encrypt(const unsigned char *plain, size_t plain_len,
                                 const unsigned char *key, size_t key_len,
                                 unsigned char **out, size_t *out_len) {
    if (!plain || !out || plain_len == 0) return EXIT_ERR_INTERNAL;

    unsigned char salt[OBFUSCATE_SALT_SIZE];
    unsigned char nonce[OBFUSCATE_NONCE_SIZE];
    if (RAND_bytes(salt, OBFUSCATE_SALT_SIZE) != 1) return EXIT_ERR_CRYPTO;
    if (RAND_bytes(nonce, OBFUSCATE_NONCE_SIZE) != 1) return EXIT_ERR_CRYPTO;

    unsigned char enc_key[OBFUSCATE_CHACHA20_KEY_SIZE];
    unsigned char hmac_key[OBFUSCATE_HMAC_KEY_SIZE];
    ExitCode ret = xorgen_derive_keys(key, key_len, salt, OBFUSCATE_SALT_SIZE,
                                      enc_key, OBFUSCATE_CHACHA20_KEY_SIZE,
                                      hmac_key, OBFUSCATE_HMAC_KEY_SIZE);
    if (ret != EXIT_OK) return ret;

    unsigned char iv[16];
    memset(iv, 0, 4);
    memcpy(iv + 4, nonce, 12);

    size_t ciphertext_len = plain_len;
    unsigned char *ciphertext = (unsigned char *)malloc(ciphertext_len);
    if (!ciphertext) return EXIT_ERR_CRYPTO;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { free(ciphertext); return EXIT_ERR_CRYPTO; }

    int len = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, enc_key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx); free(ciphertext);
        return EXIT_ERR_CRYPTO;
    }
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plain, (int)plain_len) != 1) {
        EVP_CIPHER_CTX_free(ctx); free(ciphertext);
        return EXIT_ERR_CRYPTO;
    }
    ciphertext_len = (size_t)len;
    EVP_CIPHER_CTX_free(ctx);

    size_t tag_input_len = OBFUSCATE_SALT_SIZE + OBFUSCATE_NONCE_SIZE + ciphertext_len;
    unsigned char *tag_input = (unsigned char *)malloc(tag_input_len);
    if (!tag_input) { free(ciphertext); return EXIT_ERR_CRYPTO; }

    memcpy(tag_input, salt, OBFUSCATE_SALT_SIZE);
    memcpy(tag_input + OBFUSCATE_SALT_SIZE, nonce, OBFUSCATE_NONCE_SIZE);
    memcpy(tag_input + OBFUSCATE_SALT_SIZE + OBFUSCATE_NONCE_SIZE,
           ciphertext, ciphertext_len);

    unsigned char tag[OBFUSCATE_TAG_SIZE];
    unsigned int tag_len = OBFUSCATE_TAG_SIZE;
    HMAC(EVP_sha256(), hmac_key, OBFUSCATE_HMAC_KEY_SIZE,
         tag_input, tag_input_len, tag, &tag_len);
    free(tag_input);

    *out_len = OBFUSCATE_SALT_SIZE + OBFUSCATE_NONCE_SIZE + ciphertext_len + OBFUSCATE_TAG_SIZE;
    *out = (unsigned char *)malloc(*out_len);
    if (!*out) { free(ciphertext); return EXIT_ERR_CRYPTO; }

    memcpy(*out, salt, OBFUSCATE_SALT_SIZE);
    memcpy(*out + OBFUSCATE_SALT_SIZE, nonce, OBFUSCATE_NONCE_SIZE);
    memcpy(*out + OBFUSCATE_SALT_SIZE + OBFUSCATE_NONCE_SIZE,
           ciphertext, ciphertext_len);
    memcpy(*out + OBFUSCATE_SALT_SIZE + OBFUSCATE_NONCE_SIZE + ciphertext_len,
           tag, OBFUSCATE_TAG_SIZE);

    free(ciphertext);
    return EXIT_OK;
}

/* ── ChaCha20 decryption + integrity verification ── */
ExitCode xorgen_chacha20_decrypt(const unsigned char *in, size_t in_len,
                                 const unsigned char *key, size_t key_len,
                                 unsigned char **out, size_t *out_len) {
    if (!in || !out) return EXIT_ERR_INTERNAL;

    size_t min_len = OBFUSCATE_SALT_SIZE + OBFUSCATE_NONCE_SIZE + OBFUSCATE_TAG_SIZE;
    if (in_len <= min_len) return EXIT_ERR_CRYPTO;

    const unsigned char *salt       = in;
    const unsigned char *nonce      = in + OBFUSCATE_SALT_SIZE;
    const unsigned char *ciphertext = in + OBFUSCATE_SALT_SIZE + OBFUSCATE_NONCE_SIZE;
    size_t ciphertext_len = in_len - OBFUSCATE_SALT_SIZE - OBFUSCATE_NONCE_SIZE - OBFUSCATE_TAG_SIZE;
    const unsigned char *stored_tag = in + in_len - OBFUSCATE_TAG_SIZE;

    unsigned char enc_key[OBFUSCATE_CHACHA20_KEY_SIZE];
    unsigned char hmac_key[OBFUSCATE_HMAC_KEY_SIZE];
    ExitCode ret = xorgen_derive_keys(key, key_len, salt, OBFUSCATE_SALT_SIZE,
                                      enc_key, OBFUSCATE_CHACHA20_KEY_SIZE,
                                      hmac_key, OBFUSCATE_HMAC_KEY_SIZE);
    if (ret != EXIT_OK) return ret;

    size_t tag_input_len = OBFUSCATE_SALT_SIZE + OBFUSCATE_NONCE_SIZE + ciphertext_len;
    unsigned char *tag_input = (unsigned char *)malloc(tag_input_len);
    if (!tag_input) return EXIT_ERR_CRYPTO;

    memcpy(tag_input, salt, OBFUSCATE_SALT_SIZE);
    memcpy(tag_input + OBFUSCATE_SALT_SIZE, nonce, OBFUSCATE_NONCE_SIZE);
    memcpy(tag_input + OBFUSCATE_SALT_SIZE + OBFUSCATE_NONCE_SIZE,
           ciphertext, ciphertext_len);

    unsigned char computed_tag[OBFUSCATE_TAG_SIZE];
    unsigned int computed_tag_len = OBFUSCATE_TAG_SIZE;
    HMAC(EVP_sha256(), hmac_key, OBFUSCATE_HMAC_KEY_SIZE,
         tag_input, tag_input_len, computed_tag, &computed_tag_len);
    free(tag_input);

    if (computed_tag_len != OBFUSCATE_TAG_SIZE ||
        CRYPTO_memcmp(computed_tag, stored_tag, OBFUSCATE_TAG_SIZE) != 0) {
        return EXIT_ERR_CRYPTO;
    }

    *out_len = ciphertext_len;
    *out = (unsigned char *)malloc(ciphertext_len);
    if (!*out) return EXIT_ERR_CRYPTO;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { free(*out); *out = nullptr; return EXIT_ERR_CRYPTO; }

    unsigned char iv[16];
    memset(iv, 0, 4);
    memcpy(iv + 4, nonce, 12);

    int len;
    if (EVP_DecryptInit_ex(ctx, EVP_chacha20(), NULL, enc_key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx); free(*out); *out = nullptr;
        return EXIT_ERR_CRYPTO;
    }
    if (EVP_DecryptUpdate(ctx, *out, &len, ciphertext, (int)ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx); free(*out); *out = nullptr;
        return EXIT_ERR_CRYPTO;
    }
    EVP_CIPHER_CTX_free(ctx);

    return EXIT_OK;
}
