#ifndef CRYPTO_COMPRESS_H
#define CRYPTO_COMPRESS_H

#include "crypto/common.h"

#ifdef __cplusplus
extern "C" {
#endif

ExitCode    compress_data(const unsigned char *data, size_t size,
                          int algo_id, int level, Buffer *out);

ExitCode    decompress_data(const unsigned char *data, size_t size,
                            int algo_id, Buffer *out);

const char *compress_name(int algo_id);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_COMPRESS_H */
