#ifndef CRYPTO_HEXCODE_H
#define CRYPTO_HEXCODE_H

#include "crypto/common.h"

ExitCode hex_encode(const unsigned char *in, size_t in_size, Buffer *out);
ExitCode hex_decode(const unsigned char *in, size_t in_size, Buffer *out);

#endif
