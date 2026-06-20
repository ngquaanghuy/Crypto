#ifndef CRYPTO_AES_H
#define CRYPTO_AES_H

#include "crypto/common.h"

#ifdef __cplusplus
extern "C" {
#endif

ExitCode aes_encrypt(const unsigned char *plaintext, size_t plaintext_len,
                     const unsigned char *key, size_t key_len,
                     AesMode mode, Buffer *out);

ExitCode aes_decrypt(const unsigned char *ciphertext, size_t ciphertext_len,
                     const unsigned char *key, size_t key_len,
                     AesMode mode, Buffer *out);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_AES_H */
