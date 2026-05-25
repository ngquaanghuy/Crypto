#ifndef CRYPTO_CHACHA20_H
#define CRYPTO_CHACHA20_H

#include "crypto/common.h"

ExitCode chacha20_encrypt(const unsigned char *in, size_t in_size,
                          const unsigned char *key, size_t key_size,
                          Buffer *out);

ExitCode chacha20_decrypt(const unsigned char *in, size_t in_size,
                          const unsigned char *key, size_t key_size,
                          Buffer *out);

#endif
