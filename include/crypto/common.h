#ifndef CRYPTO_COMMON_H
#define CRYPTO_COMMON_H

#include <stddef.h>

#define CRYPTO_VERSION    "1.2.0"
#define CRYPTO_NAME       "Crypto"
#define CRYPTO_DEFAULT_KEY "Crypto-Default-Key-v1.0"

typedef enum {
    EXIT_OK = 0,
    EXIT_ERR_ARGS = 1,
    EXIT_ERR_FILE = 2,
    EXIT_ERR_CRYPTO = 3,
    EXIT_ERR_INTERNAL = 4,
} ExitCode;

typedef enum {
    MODE_ENCODE,
    MODE_DECODE,
    MODE_ENCRYPT,
    MODE_DECRYPT,
    MODE_PROTECT,
    MODE_UNKNOWN,
} CommandMode;

typedef enum {
    ALGO_BASE64,
    ALGO_BASE32,
    ALGO_BASE85,
    ALGO_ASCII85,
    ALGO_HEX,
    ALGO_XOR,
    ALGO_ROLLING_XOR,
    ALGO_XOR_BIT_ROTATION,
    ALGO_MULTI_PASS_XOR,
    ALGO_PRNG_XOR,
    ALGO_AES_ECB,
    ALGO_AES_CBC,
    ALGO_AES_CTR,
    ALGO_AES_GCM,
    ALGO_CHACHA20,
    ALGO_NONE,
} Algorithm;


typedef struct {
    unsigned char *data;
    size_t         size;
} Buffer;

static inline const char *algo_name(Algorithm algo) {
    switch (algo) {
        case ALGO_BASE64:  return "base64";
        case ALGO_BASE32:  return "base32";
        case ALGO_BASE85:  return "base85";
        case ALGO_ASCII85: return "ascii85";
        case ALGO_HEX:     return "hex";
        case ALGO_XOR:     return "xor";
        case ALGO_ROLLING_XOR: return "rolling-xor";
        case ALGO_XOR_BIT_ROTATION: return "xor-bit-rotation";
        case ALGO_MULTI_PASS_XOR: return "multi-pass-xor";
        case ALGO_PRNG_XOR: return "prng-xor";
        case ALGO_AES_ECB:  return "aes-256-ecb";
        case ALGO_AES_CBC:  return "aes-256-cbc";
        case ALGO_AES_CTR:  return "aes-256-ctr";
        case ALGO_AES_GCM:  return "aes-256-gcm";
        case ALGO_CHACHA20: return "chacha20";
        default:            return "none";
    }
}

static inline int algo_needs_key(Algorithm algo) {
    return algo == ALGO_XOR || algo == ALGO_ROLLING_XOR ||
           algo == ALGO_MULTI_PASS_XOR || algo == ALGO_PRNG_XOR ||
           algo == ALGO_AES_ECB || algo == ALGO_AES_CBC ||
           algo == ALGO_AES_CTR || algo == ALGO_AES_GCM ||
           algo == ALGO_CHACHA20;
}

#endif
