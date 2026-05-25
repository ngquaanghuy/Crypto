#ifndef CRYPTO_AES_H
#define CRYPTO_AES_H

#include "crypto/common.h"

typedef enum {
    AES_ECB,
    AES_CBC,
    AES_CTR,
    AES_GCM,
} AesMode;

ExitCode aes_encrypt(const unsigned char *in, size_t in_size,
                     const unsigned char *key, size_t key_size,
                     AesMode mode, Buffer *out);

ExitCode aes_decrypt(const unsigned char *in, size_t in_size,
                     const unsigned char *key, size_t key_size,
                     AesMode mode, Buffer *out);

#endif
