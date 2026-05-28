#ifndef CRYPTO_ENCODER_H
#define CRYPTO_ENCODER_H

#include "crypto/common.h"

ExitCode encode_file(const char *input, const char *output,
                     Algorithm algo, const char *key,
                     int compress_algo, int compress_level);

ExitCode decode_file(const char *input, const char *output,
                     Algorithm algo, const char *key);

#endif
