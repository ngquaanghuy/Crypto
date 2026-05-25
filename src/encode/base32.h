#ifndef CRYPTO_BASE32_H
#define CRYPTO_BASE32_H

#include "crypto/common.h"

ExitCode base32_encode(const unsigned char *in, size_t in_size, Buffer *out);
ExitCode base32_decode(const unsigned char *in, size_t in_size, Buffer *out);

#endif
