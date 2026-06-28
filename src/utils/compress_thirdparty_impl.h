#ifndef CRYPTO_COMPRESS_THIRDPARTY_IMPL_H
#define CRYPTO_COMPRESS_THIRDPARTY_IMPL_H

#include "crypto/common.h"

/* Internal third-party compression implementation functions.
 * Not part of the public API — used only by compress.cpp dispatchers. */

ExitCode brotli_compress(const unsigned char *input, size_t input_size,
                         int level, Buffer *out);
ExitCode brotli_decompress(const unsigned char *input, size_t input_size,
                            Buffer *out);
ExitCode lz4_compress(const unsigned char *input, size_t input_size,
                      int level, Buffer *out);
ExitCode lz4_decompress(const unsigned char *input, size_t input_size,
                         Buffer *out);
ExitCode snappy_compress_data(const unsigned char *input, size_t input_size,
                              Buffer *out);
ExitCode snappy_decompress_data(const unsigned char *input, size_t input_size,
                                Buffer *out);
ExitCode blosc_compress(const unsigned char *input, size_t input_size,
                        int level, Buffer *out);
ExitCode blosc_decompress(const unsigned char *input, size_t input_size,
                           Buffer *out);

#endif /* CRYPTO_COMPRESS_THIRDPARTY_IMPL_H */
