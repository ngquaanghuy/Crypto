#include "crypto/compress.h"
#include "compress_impl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <bzlib.h>
#include <lzma.h>

ExitCode zlib_compress(const unsigned char *input, size_t input_size,
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

ExitCode zlib_decompress(const unsigned char *input, size_t input_size,
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

ExitCode gzip_compress(const unsigned char *input, size_t input_size,
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

ExitCode gzip_decompress(const unsigned char *input, size_t input_size,
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

ExitCode bz2_compress(const unsigned char *input, size_t input_size,
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

ExitCode bz2_decompress(const unsigned char *input, size_t input_size,
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

ExitCode lzma_compress(const unsigned char *input, size_t input_size,
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

ExitCode lzma_decompress(const unsigned char *input, size_t input_size,
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
