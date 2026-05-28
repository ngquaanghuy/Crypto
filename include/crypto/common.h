#ifndef CRYPTO_COMMON_H
#define CRYPTO_COMMON_H

#include <stddef.h>

#define CRYPTO_VERSION    "1.1.0"
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

#endif
