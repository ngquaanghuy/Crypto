#ifndef CRYPTO_CIPHER_H
#define CRYPTO_CIPHER_H

#include "crypto/common.h"

#ifdef __cplusplus
extern "C" {
#endif

ExitCode encrypt_data(const unsigned char *pt, size_t ptsz,
                      Algorithm algo, const unsigned char *key,
                      size_t key_len, Buffer *out);

ExitCode decrypt_data(const unsigned char *ct, size_t ctsz,
                      Algorithm algo, const unsigned char *key,
                      size_t key_len, Buffer *out);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_CIPHER_H */
