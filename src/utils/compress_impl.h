#ifndef CRYPTO_COMPRESS_IMPL_H
#define CRYPTO_COMPRESS_IMPL_H

#include "crypto/common.h"

/* Internal compression implementation functions.
 * Not part of the public API — used only by compress.cpp dispatchers. */

ExitCode zlib_compress(const unsigned char *input, size_t input_size,
                       int level, Buffer *out);
ExitCode zlib_decompress(const unsigned char *input, size_t input_size,
                         Buffer *out);
ExitCode gzip_compress(const unsigned char *input, size_t input_size,
                      int level, Buffer *out);
ExitCode gzip_decompress(const unsigned char *input, size_t input_size,
                         Buffer *out);
ExitCode bz2_compress(const unsigned char *input, size_t input_size,
                      int level, Buffer *out);
ExitCode bz2_decompress(const unsigned char *input, size_t input_size,
                         Buffer *out);
ExitCode lzma_compress(const unsigned char *input, size_t input_size,
                       int level, Buffer *out);
ExitCode lzma_decompress(const unsigned char *input, size_t input_size,
                          Buffer *out);

#endif /* CRYPTO_COMPRESS_IMPL_H */
