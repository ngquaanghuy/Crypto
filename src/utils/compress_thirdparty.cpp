#include "crypto/compress.h"
#include "compress_thirdparty_impl.h"
#define LZ4F_STATIC_LINKING_ONLY
#include "lz4frame.h"
#include "snappy-c.h"
#include <brotli/encode.h>
#include <brotli/decode.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

ExitCode brotli_compress(const unsigned char *input, size_t input_size,
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

ExitCode brotli_decompress(const unsigned char *input, size_t input_size,
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

ExitCode lz4_compress(const unsigned char *input, size_t input_size,
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

ExitCode lz4_decompress(const unsigned char *input, size_t input_size,
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

ExitCode snappy_compress_data(const unsigned char *input, size_t input_size,
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

ExitCode snappy_decompress_data(const unsigned char *input, size_t input_size,
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

ExitCode blosc_compress(const unsigned char *input, size_t input_size,
                        int level, Buffer *out) {
    char *tmpdir = getenv("TMPDIR");
    if (!tmpdir) tmpdir = "/tmp";
    char tmp_in[256], tmp_out[256];
    snprintf(tmp_in, sizeof(tmp_in), "%s/blosc_in_XXXXXX", tmpdir);
    snprintf(tmp_out, sizeof(tmp_out), "%s/blosc_out_XXXXXX", tmpdir);
    int fd_in = mkstemp(tmp_in);
    int fd_out = mkstemp(tmp_out);
    if (fd_in < 0 || fd_out < 0) {
        if (fd_in >= 0) close(fd_in);
        if (fd_out >= 0) close(fd_out);
        return EXIT_ERR_CRYPTO;
    }
    write(fd_in, input, input_size);
    close(fd_in);
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "python3 -c \"import blosc,sys;d=open('%s','rb').read();open('%s','wb').write(blosc.compress(d))\"> /dev/null 2>&1",
             tmp_in, tmp_out);
    int rc = system(cmd);
    if (rc != 0) {
        unlink(tmp_in); unlink(tmp_out);
        return EXIT_ERR_CRYPTO;
    }
    struct stat st;
    if (stat(tmp_out, &st) != 0) {
        unlink(tmp_in); unlink(tmp_out);
        return EXIT_ERR_CRYPTO;
    }
    out->data = (unsigned char *)malloc(st.st_size);
    if (!out->data) {
        unlink(tmp_in); unlink(tmp_out);
        return EXIT_ERR_CRYPTO;
    }
    int fd = open(tmp_out, O_RDONLY);
    if (fd < 0) {
        free(out->data);
        unlink(tmp_in); unlink(tmp_out);
        return EXIT_ERR_CRYPTO;
    }
    read(fd, out->data, st.st_size);
    close(fd);
    out->size = st.st_size;
    unlink(tmp_in); unlink(tmp_out);
    return EXIT_OK;
}

ExitCode blosc_decompress(const unsigned char *input, size_t input_size,
                           Buffer *out) {
    char *tmpdir = getenv("TMPDIR");
    if (!tmpdir) tmpdir = "/tmp";
    char tmp_in[256], tmp_out[256];
    snprintf(tmp_in, sizeof(tmp_in), "%s/blosc_in_XXXXXX", tmpdir);
    snprintf(tmp_out, sizeof(tmp_out), "%s/blosc_out_XXXXXX", tmpdir);
    int fd_in = mkstemp(tmp_in);
    int fd_out = mkstemp(tmp_out);
    if (fd_in < 0 || fd_out < 0) {
        if (fd_in >= 0) close(fd_in);
        if (fd_out >= 0) close(fd_out);
        return EXIT_ERR_CRYPTO;
    }
    write(fd_in, input, input_size);
    close(fd_in);
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "python3 -c \"import blosc,sys;d=open('%s','rb').read();open('%s','wb').write(blosc.decompress(d))\"> /dev/null 2>&1",
             tmp_in, tmp_out);
    int rc = system(cmd);
    if (rc != 0) {
        unlink(tmp_in); unlink(tmp_out);
        return EXIT_ERR_CRYPTO;
    }
    struct stat st;
    if (stat(tmp_out, &st) != 0) {
        unlink(tmp_in); unlink(tmp_out);
        return EXIT_ERR_CRYPTO;
    }
    out->data = (unsigned char *)malloc(st.st_size);
    if (!out->data) {
        unlink(tmp_in); unlink(tmp_out);
        return EXIT_ERR_CRYPTO;
    }
    int fd = open(tmp_out, O_RDONLY);
    if (fd < 0) {
        free(out->data);
        unlink(tmp_in); unlink(tmp_out);
        return EXIT_ERR_CRYPTO;
    }
    read(fd, out->data, st.st_size);
    close(fd);
    out->size = st.st_size;
    unlink(tmp_in); unlink(tmp_out);
    return EXIT_OK;
}
