#ifndef CRYPTO_XCHACHA20_POLY1305_H
#define CRYPTO_XCHACHA20_POLY1305_H

#include "crypto/common.h"

ExitCode xchacha20_poly1305_encrypt(const unsigned char *in, size_t in_size,
                                    const unsigned char *key, size_t key_size,
                                    Buffer *out);

ExitCode xchacha20_poly1305_decrypt(const unsigned char *in, size_t in_size,
                                    const unsigned char *key, size_t key_size,
                                    Buffer *out);

#endif
