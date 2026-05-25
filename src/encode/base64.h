#ifndef CRYPTO_BASE64_H
#define CRYPTO_BASE64_H

#include "crypto/common.h"

ExitCode base64_encode(const unsigned char *in, size_t in_size, Buffer *out);
ExitCode base64_decode(const unsigned char *in, size_t in_size, Buffer *out);

#endif
