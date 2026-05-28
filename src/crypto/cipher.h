#ifndef CRYPTO_CIPHER_H
#define CRYPTO_CIPHER_H

#include "crypto/common.h"

ExitCode encrypt_file(const char *input, const char *output,
                      Algorithm algo, const char *key,
                      int compress_algo, int compress_level);

ExitCode decrypt_file(const char *input, const char *output,
                      Algorithm algo, const char *key);

#endif
