#include "crypto/cipher.h"
#include "crypto/aes.h"
#include "crypto/chacha20.h"
#include "crypto/chacha20_poly1305.h"
#include "crypto/xchacha20_poly1305.h"
#include "encode/xorcode.h"
#include "encode/base64.h"
#include "encode/base32.h"
#include "encode/base85.h"
#include "encode/ascii85.h"
#include "encode/hexcode.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ─── Algorithm name lookup ──────────────────────────────── */
const char *algo_name(Algorithm algo) {
    switch (algo) {
        case ALGO_BASE64:   return "base64";
        case ALGO_BASE32:   return "base32";
        case ALGO_BASE85:   return "base85";
        case ALGO_ASCII85:  return "ascii85";
        case ALGO_HEX:      return "hex";
        case ALGO_XOR:      return "xor";
        case ALGO_ROLLING_XOR:  return "rolling-xor";
        case ALGO_XOR_BIT_ROTATION: return "xor-bit-rotation";
        case ALGO_MULTI_PASS_XOR:   return "multi-pass-xor";
        case ALGO_PRNG_XOR:         return "prng-xor";
        case ALGO_AES_ECB:  return "aes-ecb";
        case ALGO_AES_CBC:  return "aes-cbc";
        case ALGO_AES_CTR:  return "aes-ctr";
        case ALGO_AES_GCM:  return "aes-gcm";
        case ALGO_CHACHA20: return "chacha20";
        case ALGO_CHACHA20_POLY1305: return "chacha20-poly1305";
        case ALGO_XCHACHA20_POLY1305: return "xchacha20-poly1305";
        default:            return "unknown";
    }
}

/* ─── Does algorithm require a key? ───────────────────────── */
int algo_needs_key(Algorithm algo) {
    switch (algo) {
        case ALGO_BASE64:
        case ALGO_BASE32:
        case ALGO_BASE85:
        case ALGO_ASCII85:
        case ALGO_HEX:
            return 0;
        default:
            return 1;
    }
}

/* ─── Dispatch: encrypt ──────────────────────────────────── */
ExitCode encrypt_data(const unsigned char *pt, size_t ptsz,
                      Algorithm algo, const unsigned char *key,
                      size_t key_len, Buffer *out) {
    switch (algo) {
        case ALGO_AES_ECB:
            return aes_encrypt(pt, ptsz, key, key_len, AES_ECB, out);
        case ALGO_AES_CBC:
            return aes_encrypt(pt, ptsz, key, key_len, AES_CBC, out);
        case ALGO_AES_CTR:
            return aes_encrypt(pt, ptsz, key, key_len, AES_CTR, out);
        case ALGO_AES_GCM:
            return aes_encrypt(pt, ptsz, key, key_len, AES_GCM, out);
        case ALGO_CHACHA20:
            return chacha20_encrypt(pt, ptsz, key, key_len, out);
        case ALGO_CHACHA20_POLY1305:
            return chacha20_poly1305_encrypt(pt, ptsz, key, key_len, out);
        case ALGO_XCHACHA20_POLY1305:
            return xchacha20_poly1305_encrypt(pt, ptsz, key, key_len, out);
        case ALGO_XOR:
            return xor_transform(pt, ptsz, key, key_len, out);
        case ALGO_BASE64:
            return base64_encode(pt, ptsz, out);
        case ALGO_BASE32:
            return base32_encode(pt, ptsz, out);
        case ALGO_BASE85:
            return base85_encode(pt, ptsz, out);
        case ALGO_ASCII85:
            return ascii85_encode(pt, ptsz, out);
        case ALGO_HEX:
            return hex_encode(pt, ptsz, out);
        default:
            fprintf(stderr, "error: encrypt_data: unsupported algorithm\n");
            return EXIT_ERR_INTERNAL;
    }
}

/* ─── Dispatch: decrypt ──────────────────────────────────── */
ExitCode decrypt_data(const unsigned char *ct, size_t ctsz,
                      Algorithm algo, const unsigned char *key,
                      size_t key_len, Buffer *out) {
    switch (algo) {
        case ALGO_AES_ECB:
            return aes_decrypt(ct, ctsz, key, key_len, AES_ECB, out);
        case ALGO_AES_CBC:
            return aes_decrypt(ct, ctsz, key, key_len, AES_CBC, out);
        case ALGO_AES_CTR:
            return aes_decrypt(ct, ctsz, key, key_len, AES_CTR, out);
        case ALGO_AES_GCM:
            return aes_decrypt(ct, ctsz, key, key_len, AES_GCM, out);
        case ALGO_CHACHA20:
            return chacha20_decrypt(ct, ctsz, key, key_len, out);
        case ALGO_CHACHA20_POLY1305:
            return chacha20_poly1305_decrypt(ct, ctsz, key, key_len, out);
        case ALGO_XCHACHA20_POLY1305:
            return xchacha20_poly1305_decrypt(ct, ctsz, key, key_len, out);
        case ALGO_XOR:
            return xor_transform(ct, ctsz, key, key_len, out);
        case ALGO_BASE64:
            return base64_decode(ct, ctsz, out);
        case ALGO_BASE32:
            return base32_decode(ct, ctsz, out);
        case ALGO_BASE85:
            return base85_decode(ct, ctsz, out);
        case ALGO_ASCII85:
            return ascii85_decode(ct, ctsz, out);
        case ALGO_HEX:
            return hex_decode(ct, ctsz, out);
        default:
            fprintf(stderr, "error: decrypt_data: unsupported algorithm\n");
            return EXIT_ERR_INTERNAL;
    }
}
