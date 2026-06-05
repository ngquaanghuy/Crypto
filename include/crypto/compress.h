#ifndef CRYPTO_COMPRESS_H
#define CRYPTO_COMPRESS_H

#include "crypto/common.h"

#define COMPRESS_ID_NONE    0
#define COMPRESS_ID_ZLIB    1
#define COMPRESS_ID_LZMA    2
#define COMPRESS_ID_BZ2     3
#define COMPRESS_ID_BROTLI  4
#define COMPRESS_ID_GZIP    6
#define COMPRESS_ID_LZ4     7
#define COMPRESS_ID_SNAPPY  8
#define COMPRESS_ID_BLOSC   9

ExitCode compress_data(const unsigned char *data, size_t size,
                        int algo_id, int level, Buffer *out);

ExitCode decompress_data(const unsigned char *data, size_t size,
                          int algo_id, Buffer *out);

const char *compress_name(int algo_id);

#endif
