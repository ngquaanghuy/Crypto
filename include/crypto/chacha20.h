#ifndef CRYPTO_CHACHA20_H
#define CRYPTO_CHACHA20_H

#include "crypto/common.h"

#ifdef __cplusplus
extern "C" {
#endif

ExitCode chacha20_encrypt(const unsigned char *plaintext, size_t plaintext_len,
                          const unsigned char *key, size_t key_len,
                          Buffer *out);

ExitCode chacha20_decrypt(const unsigned char *ciphertext, size_t ciphertext_len,
                          const unsigned char *key, size_t key_len,
                          Buffer *out);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_CHACHA20_H */
