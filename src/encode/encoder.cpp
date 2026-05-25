#include "encode/encoder.h"
#include "crypto/file_util.h"
#include "encode/base64.h"
#include "encode/base32.h"
#include "encode/base85.h"
#include "encode/ascii85.h"
#include "encode/hexcode.h"
#include "encode/xorcode.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *algo_name(Algorithm algo) {
    switch (algo) {
        case ALGO_BASE64:  return "base64";
        case ALGO_BASE32:  return "base32";
        case ALGO_BASE85:  return "base85";
        case ALGO_ASCII85: return "ascii85";
        case ALGO_HEX:     return "hex";
        case ALGO_XOR:     return "xor";
        default:           return "none";
    }
}

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

ExitCode encode_file(const char *input, const char *output,
                     Algorithm algo, const char *key) {
    FileBuffer buf;
    ExitCode ret = file_read(input, &buf);
    if (ret != EXIT_OK) return ret;

    size_t key_size = key ? strlen(key) : 0;

    Buffer out = {NULL, 0};
    ret = dispatch_encode(buf.data, buf.size, algo,
                          (const unsigned char *)key, key_size, &out);
    if (ret != EXIT_OK) {
        file_buffer_free(&buf);
        return ret;
    }

    printf("[encode] %s (%s) %zu bytes -> %s (%zu bytes)\n",
           input, algo_name(algo), buf.size, output, out.size);

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

    Buffer out = {NULL, 0};
    ret = dispatch_decode(buf.data, buf.size, algo,
                          (const unsigned char *)key, key_size, &out);
    if (ret != EXIT_OK) {
        file_buffer_free(&buf);
        return ret;
    }

    printf("[decode] %s (%s) %zu bytes -> %s (%zu bytes)\n",
           input, algo_name(algo), buf.size, output, out.size);

    ret = file_write(output, out.data, out.size);
    free(out.data);
    file_buffer_free(&buf);
    return ret;
}
