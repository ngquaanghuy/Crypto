#ifndef CRYPTO_OBFUSCATE_XORGEN_H
#define CRYPTO_OBFUSCATE_XORGEN_H

#include "crypto/common.h"
#include <stddef.h>

#define OBFUSCATE_SALT_SIZE         16
#define OBFUSCATE_NONCE_SIZE        12
#define OBFUSCATE_CHACHA20_KEY_SIZE 32
#define OBFUSCATE_HMAC_KEY_SIZE     32
#define OBFUSCATE_TAG_SIZE          32

ExitCode xorgen_derive_keys(const unsigned char *master, size_t master_len,
                            const unsigned char *salt, size_t salt_len,
                            unsigned char *enc_key, size_t enc_key_size,
                            unsigned char *hmac_key, size_t hmac_key_size);

ExitCode xorgen_chacha20_encrypt(const unsigned char *plaintext,
                                 size_t plaintext_len,
                                 const unsigned char *key, size_t key_len,
                                 unsigned char **out, size_t *out_len);

ExitCode xorgen_chacha20_decrypt(const unsigned char *ciphertext,
                                 size_t ciphertext_len,
                                 const unsigned char *key, size_t key_len,
                                 unsigned char **out, size_t *out_len);

char *xorgen_generate_python_stub(const unsigned char *source,
                                  size_t source_len,
                                  const unsigned char *key, size_t key_len);

char *xorgen_generate_xor_stub(const unsigned char *source,
                               size_t source_len,
                               const unsigned char *key, size_t key_len);

#endif /* CRYPTO_OBFUSCATE_XORGEN_H */
