#include "crypto/compress.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#define LZ4F_STATIC_LINKING_ONLY
#include "lz4frame.h"
#include "snappy-c.h"
#include <bzlib.h>
#include <lzma.h>
#include <brotli/encode.h>
#include <brotli/decode.h>

static ExitCode zlib_compress(const unsigned char *input, size_t input_size,
                               int level, Buffer *out) {
    uLongf dst_len = compressBound((uLong)input_size);
    out->data = (unsigned char *)malloc(dst_len);
    if (!out->data) return EXIT_ERR_CRYPTO;

    int ret = compress2((Bytef *)out->data, &dst_len,
                        (const Bytef *)input, (uLong)input_size,
                        level);
    if (ret != Z_OK) {
        free(out->data);
        out->data = NULL;
        return EXIT_ERR_CRYPTO;
    }
    unsigned char *shrunk = (unsigned char *)realloc(out->data, dst_len);
    if (shrunk) out->data = shrunk;
    out->size = dst_len;
    return EXIT_OK;
}

static ExitCode zlib_decompress(const unsigned char *input, size_t input_size,
                                 Buffer *out) {
    uLongf dst_len = input_size * 4 + 128;
    out->data = (unsigned char *)malloc(dst_len);
    if (!out->data) return EXIT_ERR_CRYPTO;

    while (1) {
        uLongf actual = dst_len;
        int ret = uncompress((Bytef *)out->data, &actual,
                             (const Bytef *)input, (uLong)input_size);
        if (ret == Z_OK) {
            unsigned char *shrunk = (unsigned char *)realloc(out->data, actual);
            if (shrunk) out->data = shrunk;
            out->size = actual;
            return EXIT_OK;
        }
        if (ret == Z_BUF_ERROR) {
            dst_len *= 2;
            unsigned char *new_data = (unsigned char *)realloc(out->data, dst_len);
            if (!new_data) { free(out->data); return EXIT_ERR_CRYPTO; }
            out->data = new_data;
            continue;
        }
        free(out->data);
        out->data = NULL;
        return EXIT_ERR_CRYPTO;
    }
}

static ExitCode gzip_compress(const unsigned char *input, size_t input_size,
                               int level, Buffer *out) {
    z_stream strm;
    memset(&strm, 0, sizeof(strm));
    if (deflateInit2(&strm, level, Z_DEFLATED, 15 + 16, 8,
                     Z_DEFAULT_STRATEGY) != Z_OK)
        return EXIT_ERR_CRYPTO;

    size_t dst_cap = deflateBound(&strm, (uLong)input_size);
    out->data = (unsigned char *)malloc(dst_cap);
    if (!out->data) { deflateEnd(&strm); return EXIT_ERR_CRYPTO; }

    strm.next_in = (Bytef *)input;
    strm.avail_in = (uInt)input_size;
    strm.next_out = (Bytef *)out->data;
    strm.avail_out = (uInt)dst_cap;

    int ret = deflate(&strm, Z_FINISH);
    size_t written = dst_cap - strm.avail_out;
    deflateEnd(&strm);
    if (ret != Z_STREAM_END) { free(out->data); return EXIT_ERR_CRYPTO; }

    unsigned char *shrunk = (unsigned char *)realloc(out->data, written);
    if (shrunk) out->data = shrunk;
    out->size = written;
    return EXIT_OK;
}

static ExitCode gzip_decompress(const unsigned char *input, size_t input_size,
                                 Buffer *out) {
    z_stream strm;
    memset(&strm, 0, sizeof(strm));
    if (inflateInit2(&strm, 15 + 16) != Z_OK)
        return EXIT_ERR_CRYPTO;

    size_t dst_cap = input_size * 4 + 128;
    size_t dst_size = 0;
    out->data = (unsigned char *)malloc(dst_cap);
    if (!out->data) { inflateEnd(&strm); return EXIT_ERR_CRYPTO; }

    strm.next_in = (Bytef *)input;
    strm.avail_in = (uInt)input_size;

    while (1) {
        strm.next_out = (Bytef *)out->data + dst_size;
        strm.avail_out = (uInt)(dst_cap - dst_size);
        int ret = inflate(&strm, Z_NO_FLUSH);
        if (ret == Z_STREAM_END) {
            dst_size = dst_cap - strm.avail_out;
            inflateEnd(&strm);
            unsigned char *shrunk = (unsigned char *)realloc(out->data, dst_size);
            if (shrunk) out->data = shrunk;
            out->size = dst_size;
            return EXIT_OK;
        }
        if (ret != Z_OK) { inflateEnd(&strm); free(out->data); return EXIT_ERR_CRYPTO; }
        dst_size = dst_cap - strm.avail_out;
        if (strm.avail_out == 0) {
            dst_cap *= 2;
            unsigned char *new_data = (unsigned char *)realloc(out->data, dst_cap);
            if (!new_data) { inflateEnd(&strm); free(out->data); return EXIT_ERR_CRYPTO; }
            out->data = new_data;
        }
    }
}

static ExitCode bz2_compress(const unsigned char *input, size_t input_size,
                              int level, Buffer *out) {
    unsigned int dst_len = input_size * 2 + 600;
    out->data = (unsigned char *)malloc(dst_len);
    if (!out->data) return EXIT_ERR_CRYPTO;

    int bzlevel = level < 1 ? 1 : (level > 9 ? 9 : level);
    int ret = BZ2_bzBuffToBuffCompress((char *)out->data, &dst_len,
                                        (char *)input, (unsigned int)input_size,
                                        bzlevel, 0, 30);
    if (ret != BZ_OK) { free(out->data); return EXIT_ERR_CRYPTO; }

    unsigned char *shrunk = (unsigned char *)realloc(out->data, dst_len);
    if (shrunk) out->data = shrunk;
    out->size = dst_len;
    return EXIT_OK;
}

static ExitCode bz2_decompress(const unsigned char *input, size_t input_size,
                                Buffer *out) {
    unsigned int dst_len = (unsigned int)(input_size * 4 + 128);
    out->data = (unsigned char *)malloc(dst_len);
    if (!out->data) return EXIT_ERR_CRYPTO;

    while (1) {
        unsigned int actual = dst_len;
        int ret = BZ2_bzBuffToBuffDecompress((char *)out->data, &actual,
                                              (char *)input, (unsigned int)input_size,
                                              0, 0);
        if (ret == BZ_OK) {
            unsigned char *shrunk = (unsigned char *)realloc(out->data, actual);
            if (shrunk) out->data = shrunk;
            out->size = actual;
            return EXIT_OK;
        }
        if (ret == BZ_OUTBUFF_FULL) {
            dst_len *= 2;
            unsigned char *new_data = (unsigned char *)realloc(out->data, dst_len);
            if (!new_data) { free(out->data); return EXIT_ERR_CRYPTO; }
            out->data = new_data;
            continue;
        }
        free(out->data);
        return EXIT_ERR_CRYPTO;
    }
}

static ExitCode lzma_compress(const unsigned char *input, size_t input_size,
                               int level, Buffer *out) {
    lzma_stream strm = LZMA_STREAM_INIT;
    lzma_ret ret = lzma_easy_encoder(&strm, level, LZMA_CHECK_CRC64);
    if (ret != LZMA_OK) return EXIT_ERR_CRYPTO;

    size_t dst_cap = lzma_stream_buffer_bound(input_size);
    out->data = (unsigned char *)malloc(dst_cap);
    if (!out->data) { lzma_end(&strm); return EXIT_ERR_CRYPTO; }

    strm.next_in = input;
    strm.avail_in = input_size;
    strm.next_out = out->data;
    strm.avail_out = dst_cap;

    ret = lzma_code(&strm, LZMA_FINISH);
    size_t written = dst_cap - strm.avail_out;
    lzma_end(&strm);
    if (ret != LZMA_STREAM_END) { free(out->data); return EXIT_ERR_CRYPTO; }

    unsigned char *shrunk = (unsigned char *)realloc(out->data, written);
    if (shrunk) out->data = shrunk;
    out->size = written;
    return EXIT_OK;
}

static ExitCode lzma_decompress(const unsigned char *input, size_t input_size,
                                 Buffer *out) {
    uint64_t memlimit = UINT64_MAX;
    size_t dst_cap = input_size * 4 + 128;
    size_t dst_size = dst_cap;
    out->data = (unsigned char *)malloc(dst_cap);
    if (!out->data) return EXIT_ERR_CRYPTO;

    while (1) {
        size_t in_pos = 0;
        size_t out_pos = 0;
        lzma_ret ret = lzma_stream_buffer_decode(&memlimit, 0, NULL,
                                                  input, &in_pos, input_size,
                                                  out->data, &out_pos, dst_cap);
        if (ret == LZMA_OK || ret == LZMA_STREAM_END) {
            unsigned char *shrunk = (unsigned char *)realloc(out->data, out_pos);
            if (shrunk) out->data = shrunk;
            out->size = out_pos;
            return EXIT_OK;
        }
        if (ret == LZMA_BUF_ERROR || ret == LZMA_MEMLIMIT_ERROR) {
            dst_cap *= 2;
            unsigned char *new_data = (unsigned char *)realloc(out->data, dst_cap);
            if (!new_data) { free(out->data); return EXIT_ERR_CRYPTO; }
            out->data = new_data;
            continue;
        }
        free(out->data);
        return EXIT_ERR_CRYPTO;
    }
}

static ExitCode brotli_compress(const unsigned char *input, size_t input_size,
                                 int level, Buffer *out) {
    size_t dst_len = BrotliEncoderMaxCompressedSize(input_size);
    if (dst_len == 0) dst_len = input_size + 16;
    out->data = (unsigned char *)malloc(dst_len);
    if (!out->data) return EXIT_ERR_CRYPTO;

    int bret = BrotliEncoderCompress(level, BROTLI_DEFAULT_WINDOW,
                                      BROTLI_DEFAULT_MODE,
                                      input_size, input,
                                      &dst_len, out->data);
    if (!bret) { free(out->data); return EXIT_ERR_CRYPTO; }

    unsigned char *shrunk = (unsigned char *)realloc(out->data, dst_len);
    if (shrunk) out->data = shrunk;
    out->size = dst_len;
    return EXIT_OK;
}

static ExitCode brotli_decompress(const unsigned char *input, size_t input_size,
                                   Buffer *out) {
    size_t dst_len = input_size * 4 + 128;
    out->data = (unsigned char *)malloc(dst_len);
    if (!out->data) return EXIT_ERR_CRYPTO;

    while (1) {
        size_t actual = dst_len;
        int bret = BrotliDecoderDecompress(input_size, input,
                                            &actual, out->data);
        if (bret == BROTLI_DECODER_RESULT_SUCCESS) {
            unsigned char *shrunk = (unsigned char *)realloc(out->data, actual);
            if (shrunk) out->data = shrunk;
            out->size = actual;
            return EXIT_OK;
        }
        if (bret == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) {
            dst_len *= 2;
            unsigned char *new_data = (unsigned char *)realloc(out->data, dst_len);
            if (!new_data) { free(out->data); return EXIT_ERR_CRYPTO; }
            out->data = new_data;
            continue;
        }
        free(out->data);
        return EXIT_ERR_CRYPTO;
    }
}

static ExitCode lz4_compress(const unsigned char *input, size_t input_size,
                              int level, Buffer *out) {
    LZ4F_preferences_t prefs = LZ4F_INIT_PREFERENCES;
    prefs.frameInfo.contentSize = input_size;
    if (level > LZ4F_compressionLevel_max())
        level = LZ4F_compressionLevel_max();
    if (level > 0)
        prefs.compressionLevel = level;

    size_t dst_cap = LZ4F_compressFrameBound(input_size, &prefs);
    out->data = (unsigned char *)malloc(dst_cap);
    if (!out->data) return EXIT_ERR_CRYPTO;

    size_t result = LZ4F_compressFrame(out->data, dst_cap,
                                        input, input_size, &prefs);
    if (LZ4F_isError(result)) {
        free(out->data);
        out->data = NULL;
        return EXIT_ERR_CRYPTO;
    }
    unsigned char *shrunk = (unsigned char *)realloc(out->data, result);
    if (shrunk) out->data = shrunk;
    out->size = result;
    return EXIT_OK;
}

static ExitCode lz4_decompress(const unsigned char *input, size_t input_size,
                                Buffer *out) {
    LZ4F_dctx *dctx = NULL;
    if (LZ4F_isError(LZ4F_createDecompressionContext(&dctx, LZ4F_VERSION)))
        return EXIT_ERR_CRYPTO;

    size_t src_consumed = input_size;
    LZ4F_frameInfo_t fi;
    size_t err = LZ4F_getFrameInfo(dctx, &fi, input, &src_consumed);
    if (LZ4F_isError(err)) { LZ4F_freeDecompressionContext(dctx); return EXIT_ERR_CRYPTO; }

    size_t src_pos = src_consumed;
    size_t dst_cap = (fi.contentSize > 0) ? (size_t)fi.contentSize : input_size * 4;
    size_t dst_size = 0;
    out->data = (unsigned char *)malloc(dst_cap);
    if (!out->data) { LZ4F_freeDecompressionContext(dctx); return EXIT_ERR_CRYPTO; }

    while (src_pos < input_size) {
        size_t dst_written = dst_cap - dst_size;
        size_t src_remaining = input_size - src_pos;
        src_consumed = src_remaining;
        err = LZ4F_decompress(dctx,
                              out->data + dst_size, &dst_written,
                              input + src_pos, &src_consumed, NULL);
        if (LZ4F_isError(err)) {
            free(out->data); out->data = NULL;
            LZ4F_freeDecompressionContext(dctx);
            return EXIT_ERR_CRYPTO;
        }
        dst_size += dst_written;
        src_pos += src_consumed;
        if (dst_size == dst_cap && src_pos < input_size) {
            dst_cap *= 2;
            unsigned char *nd = (unsigned char *)realloc(out->data, dst_cap);
            if (!nd) { free(out->data); LZ4F_freeDecompressionContext(dctx); return EXIT_ERR_CRYPTO; }
            out->data = nd;
        }
    }
    LZ4F_freeDecompressionContext(dctx);
    unsigned char *shrunk = (unsigned char *)realloc(out->data, dst_size);
    if (shrunk) out->data = shrunk;
    out->size = dst_size;
    return EXIT_OK;
}

static ExitCode snappy_compress_data(const unsigned char *input, size_t input_size,
                                      Buffer *out) {
    size_t dst_len = snappy_max_compressed_length(input_size);
    out->data = (unsigned char *)malloc(dst_len);
    if (!out->data) return EXIT_ERR_CRYPTO;

    snappy_status st = snappy_compress((const char *)input, input_size,
                                        (char *)out->data, &dst_len);
    if (st != SNAPPY_OK) { free(out->data); return EXIT_ERR_CRYPTO; }
    unsigned char *shrunk = (unsigned char *)realloc(out->data, dst_len);
    if (shrunk) out->data = shrunk;
    out->size = dst_len;
    return EXIT_OK;
}

static ExitCode snappy_decompress_data(const unsigned char *input, size_t input_size,
                                        Buffer *out) {
    size_t uncomp_len = 0;
    if (snappy_uncompressed_length((const char *)input, input_size,
                                    &uncomp_len) != SNAPPY_OK)
        return EXIT_ERR_CRYPTO;

    out->data = (unsigned char *)malloc(uncomp_len);
    if (!out->data) return EXIT_ERR_CRYPTO;

    snappy_status st = snappy_uncompress((const char *)input, input_size,
                                          (char *)out->data, &uncomp_len);
    if (st != SNAPPY_OK) { free(out->data); return EXIT_ERR_CRYPTO; }
    out->size = uncomp_len;
    return EXIT_OK;
}

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
