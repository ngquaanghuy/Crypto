#include "crypto/compress.h"
#include "compress_impl.h"
#include "compress_thirdparty_impl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

ExitCode compress_data(const unsigned char *data, size_t size,
                        int algo_id, int level, Buffer *out) {
    if (!data || size == 0 || !out) {
        out->data = NULL; out->size = 0;
        return EXIT_ERR_CRYPTO;
    }
    if (algo_id <= COMPRESS_ID_NONE || algo_id > COMPRESS_ID_BLOSC) {
        out->data = (unsigned char *)malloc(size);
        if (!out->data) return EXIT_ERR_CRYPTO;
        memcpy(out->data, data, size);
        out->size = size;
        return EXIT_OK;
    }
    switch (algo_id) {
        case COMPRESS_ID_ZLIB:   return zlib_compress(data, size, level, out);
        case COMPRESS_ID_LZMA:   return lzma_compress(data, size, level, out);
        case COMPRESS_ID_BZ2:    return bz2_compress(data, size, level, out);
        case COMPRESS_ID_BROTLI: return brotli_compress(data, size, level, out);
        case COMPRESS_ID_GZIP:   return gzip_compress(data, size, level, out);
        case COMPRESS_ID_LZ4:    return lz4_compress(data, size, level, out);
        case COMPRESS_ID_SNAPPY: return snappy_compress_data(data, size, out);
        case COMPRESS_ID_BLOSC:  return blosc_compress(data, size, level, out);
        default:
            fprintf(stderr, "error: compression algorithm '%s' not supported\n",
                    compress_name(algo_id));
            return EXIT_ERR_CRYPTO;
    }
}

ExitCode decompress_data(const unsigned char *data, size_t size,
                          int algo_id, Buffer *out) {
    if (!data || size == 0 || !out) {
        out->data = NULL; out->size = 0;
        return EXIT_ERR_CRYPTO;
    }
    if (algo_id <= COMPRESS_ID_NONE || algo_id > COMPRESS_ID_BLOSC) {
        out->data = (unsigned char *)malloc(size);
        if (!out->data) return EXIT_ERR_CRYPTO;
        memcpy(out->data, data, size);
        out->size = size;
        return EXIT_OK;
    }
    switch (algo_id) {
        case COMPRESS_ID_ZLIB:   return zlib_decompress(data, size, out);
        case COMPRESS_ID_LZMA:   return lzma_decompress(data, size, out);
        case COMPRESS_ID_BZ2:    return bz2_decompress(data, size, out);
        case COMPRESS_ID_BROTLI: return brotli_decompress(data, size, out);
        case COMPRESS_ID_GZIP:   return gzip_decompress(data, size, out);
        case COMPRESS_ID_LZ4:    return lz4_decompress(data, size, out);
        case COMPRESS_ID_SNAPPY: return snappy_decompress_data(data, size, out);
        case COMPRESS_ID_BLOSC:  return blosc_decompress(data, size, out);
        default:
            fprintf(stderr, "error: decompression algorithm '%s' not supported\n",
                    compress_name(algo_id));
            return EXIT_ERR_CRYPTO;
    }
}

const char *compress_name(int algo_id) {
    switch (algo_id) {
        case COMPRESS_ID_NONE:   return "none";
        case COMPRESS_ID_ZLIB:   return "zlib";
        case COMPRESS_ID_LZMA:   return "lzma";
        case COMPRESS_ID_BZ2:    return "bz2";
        case COMPRESS_ID_BROTLI: return "brotli";
        case COMPRESS_ID_GZIP:   return "gzip";
        case COMPRESS_ID_LZ4:    return "lz4";
        case COMPRESS_ID_SNAPPY: return "snappy";
        case COMPRESS_ID_BLOSC:  return "blosc";
        default:                 return "unknown";
    }
}
