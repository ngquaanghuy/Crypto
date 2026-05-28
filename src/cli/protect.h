#ifndef CRYPTO_PROTECT_H
#define CRYPTO_PROTECT_H

#include "crypto/common.h"

ExitCode protect_file(const char *input, const char *output,
                      Algorithm algo, const char *key,
                      const char *obf_techniques,
                      const char *anti_analysis,
                      int compress_algo, int compress_level,
                      int use_vm);

#endif
