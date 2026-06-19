#include "encode/encoder.h"
#include "crypto/file_util.h"
#include "crypto/compress.h"
#include "crypto/cipher.h"
#include "crypto/aes.h"
#include "crypto/chacha20.h"
#include "encode/base64.h"
#include "encode/base32.h"
#include "encode/base85.h"
#include "encode/ascii85.h"
#include "encode/hexcode.h"
#include "encode/xorcode.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static ExitCode dispatch_encode(const unsigned char *data, size_t size,
                                Algorithm algo, const unsigned char *key,
                                size_t key_size, Buffer *out) {
    switch (algo) {
        case ALGO_BASE64:  return base64_encode(data, size, out);
        case ALGO_BASE32:  return base32_encode(data, size, out);
        case ALGO_BASE85:  return base85_encode(data, size, out);
        case ALGO_ASCII85: return ascii85_encode(data, size, out);
        case ALGO_HEX:     return hex_encode(data, size, out);
        case ALGO_XOR:     return xor_transform(data, size, key, key_size, out);
        default:
            out->data = (unsigned char *)malloc(size);
            if (!out->data) return EXIT_ERR_CRYPTO;
            memcpy(out->data, data, size);
            out->size = size;
            return EXIT_OK;
    }
}

static ExitCode dispatch_decode(const unsigned char *data, size_t size,
                                Algorithm algo, const unsigned char *key,
                                size_t key_size, Buffer *out) {
    switch (algo) {
        case ALGO_BASE64:  return base64_decode(data, size, out);
        case ALGO_BASE32:  return base32_decode(data, size, out);
        case ALGO_BASE85:  return base85_decode(data, size, out);
        case ALGO_ASCII85: return ascii85_decode(data, size, out);
        case ALGO_HEX:     return hex_decode(data, size, out);
        case ALGO_XOR:     return xor_transform(data, size, key, key_size, out);
        default:
            out->data = (unsigned char *)malloc(size);
            if (!out->data) return EXIT_ERR_CRYPTO;
            memcpy(out->data, data, size);
            out->size = size;
            return EXIT_OK;
    }
}

#define HEADER_SIZE 4

ExitCode encode_file(const char *input, const char *output,
                     Algorithm algo, const char *key,
                     int compress_algo, int compress_level) {
    FileBuffer buf;
    ExitCode ret = file_read(input, &buf);
    if (ret != EXIT_OK) return ret;

    // Progress indicator for large files
    const size_t PROGRESS_THRESHOLD = 65536;
    if (buf.size >= PROGRESS_THRESHOLD)
        fprintf(stderr, "\r  [encode] processing %zu bytes...", buf.size);

    // Compress with header
    Buffer comp = {0};
    if (compress_algo > COMPRESS_ID_NONE) {
        ret = compress_data(buf.data, buf.size, compress_algo, compress_level, &comp);
    } else {
        comp.data = (unsigned char *)malloc(buf.size);
        if (!comp.data) { file_buffer_free(&buf); return EXIT_ERR_CRYPTO; }
        memcpy(comp.data, buf.data, buf.size);
        comp.size = buf.size;
    }
    if (ret != EXIT_OK) { file_buffer_free(&buf); return ret; }

    unsigned char hdr[HEADER_SIZE] = {1, (unsigned char)compress_algo, 0, 0};
    size_t ptsz = HEADER_SIZE + comp.size;
    unsigned char *pt = (unsigned char *)malloc(ptsz);
    if (!pt) { free(comp.data); file_buffer_free(&buf); return EXIT_ERR_CRYPTO; }
    memcpy(pt, hdr, HEADER_SIZE);
    memcpy(pt + HEADER_SIZE, comp.data, comp.size);
    free(comp.data);

    size_t key_size = key ? strlen(key) : 0;

    if (buf.size >= PROGRESS_THRESHOLD)
        fprintf(stderr, "\r  [encode] encoding...");

    Buffer out = {NULL, 0};
    ret = dispatch_encode(pt, ptsz, algo,
                          (const unsigned char *)key, key_size, &out);
    free(pt);
    if (ret != EXIT_OK) {
        file_buffer_free(&buf);
        return ret;
    }

    printf("[encode] %s (%s", input, algo_name(algo));
    if (compress_algo > COMPRESS_ID_NONE)
        printf("+%s", compress_name(compress_algo));
    printf(") %zu bytes -> %s (%zu bytes)\n", buf.size, output, out.size);

    ret = file_write(output, out.data, out.size);
    free(out.data);
    file_buffer_free(&buf);
    return ret;
}

ExitCode decode_file(const char *input, const char *output,
                     Algorithm algo, const char *key) {
    FileBuffer buf;
    ExitCode ret = file_read(input, &buf);
    if (ret != EXIT_OK) return ret;

    size_t key_size = key ? strlen(key) : 0;

    const size_t PROGRESS_THRESHOLD = 65536;
    if (buf.size >= PROGRESS_THRESHOLD)
        fprintf(stderr, "\r  [decode] decoding %zu bytes...", buf.size);

    Buffer out = {NULL, 0};
    ret = dispatch_decode(buf.data, buf.size, algo,
                           (const unsigned char *)key, key_size, &out);
    if (ret != EXIT_OK) {
        file_buffer_free(&buf);
        return ret;
    }

    // Check for compression header
    if (out.size >= HEADER_SIZE && out.data[0] == 1) {
        int comp_algo = out.data[1];
        if (comp_algo > COMPRESS_ID_NONE) {
            Buffer decomp = {0};
            ret = decompress_data(out.data + HEADER_SIZE, out.size - HEADER_SIZE,
                                   comp_algo, &decomp);
            if (ret == EXIT_OK) {
                free(out.data);
                out = decomp;
            } else {
                // decompress failed, keep as-is
            }
        } else {
            // No compression, strip header
            size_t new_sz = out.size - HEADER_SIZE;
            unsigned char *new_d = (unsigned char *)malloc(new_sz);
            if (new_d) {
                memcpy(new_d, out.data + HEADER_SIZE, new_sz);
                free(out.data);
                out.data = new_d;
                out.size = new_sz;
            }
        }
    }

    printf("[decode] %s (%s) %zu bytes -> %s (%zu bytes)\n",
           input, algo_name(algo), buf.size, output, out.size);

    ret = file_write(output, out.data, out.size);
    free(out.data);
    file_buffer_free(&buf);
    return ret;
}

ExitCode encrypt_file(const char *input, const char *output,
                      Algorithm algo, const char *key,
                      int compress_algo, int compress_level) {
    FileBuffer buf;
    ExitCode ret = file_read(input, &buf);
    if (ret != EXIT_OK) return ret;

    Buffer comp = {0};
    if (compress_algo > COMPRESS_ID_NONE) {
        ret = compress_data(buf.data, buf.size, compress_algo, compress_level, &comp);
    } else {
        comp.data = (unsigned char *)malloc(buf.size);
        if (!comp.data) { file_buffer_free(&buf); return EXIT_ERR_CRYPTO; }
        memcpy(comp.data, buf.data, buf.size);
        comp.size = buf.size;
    }
    if (ret != EXIT_OK) { file_buffer_free(&buf); return ret; }

    unsigned char hdr[HEADER_SIZE] = {1, (unsigned char)compress_algo, 0, 0};
    size_t ptsz = HEADER_SIZE + comp.size;
    unsigned char *pt = (unsigned char *)malloc(ptsz);
    if (!pt) { free(comp.data); file_buffer_free(&buf); return EXIT_ERR_CRYPTO; }
    memcpy(pt, hdr, HEADER_SIZE);
    memcpy(pt + HEADER_SIZE, comp.data, comp.size);
    free(comp.data);

    size_t key_size = key ? strlen(key) : 0;
    Buffer out = {NULL, 0};
    ret = encrypt_data(pt, ptsz, algo, (const unsigned char *)key, key_size, &out);
    free(pt);
    if (ret != EXIT_OK) { file_buffer_free(&buf); return ret; }

    printf("[encrypt] %s (%s) %zu bytes -> %s (%zu bytes)\n",
           input, algo_name(algo), buf.size, output, out.size);
    ret = file_write(output, out.data, out.size);
    free(out.data);
    file_buffer_free(&buf);
    return ret;
}

ExitCode decrypt_file(const char *input, const char *output,
                      Algorithm algo, const char *key) {
    FileBuffer buf;
    ExitCode ret = file_read(input, &buf);
    if (ret != EXIT_OK) return ret;

    size_t key_size = key ? strlen(key) : 0;
    Buffer out = {NULL, 0};
    ret = decrypt_data(buf.data, buf.size, algo, (const unsigned char *)key, key_size, &out);
    if (ret != EXIT_OK) { file_buffer_free(&buf); return ret; }

    if (out.size >= HEADER_SIZE && out.data[0] == 1) {
        int comp_algo = out.data[1];
        if (comp_algo > COMPRESS_ID_NONE) {
            Buffer decomp = {0};
            ret = decompress_data(out.data + HEADER_SIZE, out.size - HEADER_SIZE,
                                   comp_algo, &decomp);
            if (ret == EXIT_OK) {
                free(out.data);
                out = decomp;
            }
        } else {
            size_t new_sz = out.size - HEADER_SIZE;
            unsigned char *new_d = (unsigned char *)malloc(new_sz);
            if (new_d) {
                memcpy(new_d, out.data + HEADER_SIZE, new_sz);
                free(out.data);
                out.data = new_d;
                out.size = new_sz;
            }
        }
    }

    printf("[decrypt] %s (%s) %zu bytes -> %s (%zu bytes)\n",
           input, algo_name(algo), buf.size, output, out.size);
    ret = file_write(output, out.data, out.size);
    free(out.data);
    file_buffer_free(&buf);
    return ret;
}
