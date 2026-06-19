#ifndef CRYPTO_COMMON_H
#define CRYPTO_COMMON_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ─── Exit codes ──────────────────────────────────────────── */
typedef enum {
    EXIT_OK          = 0,
    EXIT_ERR_ARGS    = 1,
    EXIT_ERR_FILE    = 2,
    EXIT_ERR_CRYPTO  = 3,
    EXIT_ERR_INTERNAL = 4,
} ExitCode;

/* ─── Algorithm enum ──────────────────────────────────────── */
typedef enum {
    ALGO_NONE = 0,
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
    ALGO_CHACHA20_POLY1305,
    ALGO_XCHACHA20_POLY1305,
} Algorithm;

/* ─── Command mode ────────────────────────────────────────── */
typedef enum {
    MODE_UNKNOWN = 0,
    MODE_ENCODE,
    MODE_DECODE,
    MODE_ENCRYPT,
    MODE_DECRYPT,
    MODE_PROTECT,
} CommandMode;

/* ─── AES mode ────────────────────────────────────────────── */
typedef enum {
    AES_ECB = 0,
    AES_CBC,
    AES_CTR,
    AES_GCM,
} AesMode;

/* ─── Buffer types ────────────────────────────────────────── */
typedef struct {
    unsigned char *data;
    size_t         size;
} Buffer;

typedef struct {
    unsigned char *data;
    size_t         size;
} FileBuffer;

/* ─── Compression algorithm IDs ───────────────────────────── */
#define COMPRESS_ID_NONE    0
#define COMPRESS_ID_ZLIB    1
#define COMPRESS_ID_LZMA    2
#define COMPRESS_ID_BZ2     3
#define COMPRESS_ID_BROTLI  4
#define COMPRESS_ID_GZIP    5
#define COMPRESS_ID_LZ4     6
#define COMPRESS_ID_SNAPPY  7
#define COMPRESS_ID_BLOSC   9

/* ─── Project metadata ────────────────────────────────────── */
#define CRYPTO_NAME      "Crypto"
#define CRYPTO_VERSION   "1.6.1"
#define CRYPTO_DEFAULT_KEY ""

/* ─── Algorithm helpers ───────────────────────────────────── */
const char *algo_name(Algorithm algo);
int         algo_needs_key(Algorithm algo);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_COMMON_H */
