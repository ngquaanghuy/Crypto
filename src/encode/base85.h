#ifndef CRYPTO_BASE85_H
#define CRYPTO_BASE85_H

#include "crypto/common.h"

ExitCode base85_encode(const unsigned char *in, size_t in_size, Buffer *out);
ExitCode base85_decode(const unsigned char *in, size_t in_size, Buffer *out);

#endif
