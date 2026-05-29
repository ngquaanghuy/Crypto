#include "crypto/cipher.h"
#include "crypto/file_util.h"
#include "crypto/compress.h"
#include "crypto/aes.h"
#include "crypto/chacha20.h"
#include "encode/xorcode.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static AesMode algo_to_aes_mode(Algorithm algo) {
    switch (algo) {
        case ALGO_AES_ECB: return AES_ECB;
        case ALGO_AES_CBC: return AES_CBC;
        case ALGO_AES_CTR: return AES_CTR;
        case ALGO_AES_GCM: return AES_GCM;
        default:           return AES_GCM;
    }
}

static int is_aes(Algorithm algo) {
    return algo == ALGO_AES_ECB || algo == ALGO_AES_CBC ||
           algo == ALGO_AES_CTR || algo == ALGO_AES_GCM;
}

static ExitCode dispatch_encrypt(const unsigned char *data, size_t size,
                                  Algorithm algo, const unsigned char *key,
                                  size_t key_size, Buffer *out) {
    if (is_aes(algo))
        return aes_encrypt(data, size, key, key_size, algo_to_aes_mode(algo), out);
    switch (algo) {
        case ALGO_CHACHA20: return chacha20_encrypt(data, size, key, key_size, out);
        case ALGO_ROLLING_XOR: return rolling_xor_encrypt(data, size, key, key_size, out);
        case ALGO_MULTI_PASS_XOR: return multi_pass_xor_encrypt(data, size, key, key_size, 3, out);
        case ALGO_PRNG_XOR: return prng_xor_encrypt(data, size, key, key_size, out);
        case ALGO_XOR:      return xor_transform(data, size, key, key_size, out);
        default:

            out->data = (unsigned char *)malloc(size);
            if (!out->data) return EXIT_ERR_CRYPTO;
            memcpy(out->data, data, size);
            out->size = size;
            return EXIT_OK;
    }
}

static ExitCode dispatch_decrypt(const unsigned char *data, size_t size,
                                  Algorithm algo, const unsigned char *key,
                                  size_t key_size, Buffer *out) {
    if (is_aes(algo))
        return aes_decrypt(data, size, key, key_size, algo_to_aes_mode(algo), out);
    switch (algo) {
        case ALGO_CHACHA20: return chacha20_decrypt(data, size, key, key_size, out);
        case ALGO_ROLLING_XOR: return rolling_xor_decrypt(data, size, key, key_size, out);
        case ALGO_MULTI_PASS_XOR: return multi_pass_xor_decrypt(data, size, key, key_size, 3, out);
        case ALGO_PRNG_XOR: return prng_xor_decrypt(data, size, key, key_size, out);
        case ALGO_XOR:      return xor_transform(data, size, key, key_size, out);
        default:

            out->data = (unsigned char *)malloc(size);
            if (!out->data) return EXIT_ERR_CRYPTO;
            memcpy(out->data, data, size);
            out->size = size;
            return EXIT_OK;
    }
}

#define HEADER_SIZE 4

ExitCode encrypt_file(const char *input, const char *output,
                      Algorithm algo, const char *key,
                      int compress_algo, int compress_level) {
    FileBuffer buf;
    ExitCode ret = file_read(input, &buf);
    if (ret != EXIT_OK) return ret;

    // Progress indicator for large files
    const size_t PROGRESS_THRESHOLD = 65536;
    if (buf.size >= PROGRESS_THRESHOLD)
        fprintf(stderr, "\r  [encrypt] processing %zu bytes...", buf.size);

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
        fprintf(stderr, "\r  [encrypt] encrypting...");

    Buffer out = {NULL, 0};
    ret = dispatch_encrypt(pt, ptsz, algo,
                           (const unsigned char *)key, key_size, &out);
    free(pt);
    if (ret != EXIT_OK) {
        file_buffer_free(&buf);
        return ret;
    }

    printf("[encrypt] %s (%s", input, algo_name(algo));
    if (compress_algo > COMPRESS_ID_NONE)
        printf("+%s", compress_name(compress_algo));
    printf(") %zu bytes -> %s (%zu bytes)\n", buf.size, output, out.size);

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

    const size_t PROGRESS_THRESHOLD = 65536;
    if (buf.size >= PROGRESS_THRESHOLD)
        fprintf(stderr, "\r  [decrypt] decrypting %zu bytes...", buf.size);

    Buffer out = {NULL, 0};
    ret = dispatch_decrypt(buf.data, buf.size, algo,
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
