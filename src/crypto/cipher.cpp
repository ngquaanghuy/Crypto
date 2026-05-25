#include "crypto/cipher.h"
#include "crypto/file_util.h"
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

static const char *algo_name(Algorithm algo) {
    switch (algo) {
        case ALGO_AES_ECB:  return "aes-256-ecb";
        case ALGO_AES_CBC:  return "aes-256-cbc";
        case ALGO_AES_CTR:  return "aes-256-ctr";
        case ALGO_AES_GCM:  return "aes-256-gcm";
        case ALGO_CHACHA20: return "chacha20";
        case ALGO_XOR:      return "xor";
        default:            return "none";
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
        case ALGO_XOR:      return xor_transform(data, size, key, key_size, out);
        default:
            out->data = (unsigned char *)malloc(size);
            if (!out->data) return EXIT_ERR_CRYPTO;
            memcpy(out->data, data, size);
            out->size = size;
            return EXIT_OK;
    }
}

ExitCode encrypt_file(const char *input, const char *output,
                      Algorithm algo, const char *key) {
    FileBuffer buf;
    ExitCode ret = file_read(input, &buf);
    if (ret != EXIT_OK) return ret;

    size_t key_size = key ? strlen(key) : 0;

    Buffer out = {NULL, 0};
    ret = dispatch_encrypt(buf.data, buf.size, algo,
                           (const unsigned char *)key, key_size, &out);
    if (ret != EXIT_OK) {
        file_buffer_free(&buf);
        return ret;
    }

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
    ret = dispatch_decrypt(buf.data, buf.size, algo,
                           (const unsigned char *)key, key_size, &out);
    if (ret != EXIT_OK) {
        file_buffer_free(&buf);
        return ret;
    }

    printf("[decrypt] %s (%s) %zu bytes -> %s (%zu bytes)\n",
           input, algo_name(algo), buf.size, output, out.size);

    ret = file_write(output, out.data, out.size);
    free(out.data);
    file_buffer_free(&buf);
    return ret;
}
