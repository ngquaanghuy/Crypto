#ifndef CRYPTO_ASCII85_H
#define CRYPTO_ASCII85_H

#include "crypto/common.h"

ExitCode ascii85_encode(const unsigned char *in, size_t in_size, Buffer *out);
ExitCode ascii85_decode(const unsigned char *in, size_t in_size, Buffer *out);

#endif
