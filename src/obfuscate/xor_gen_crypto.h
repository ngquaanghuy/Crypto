#ifndef CRYPTO_OBFUSCATE_XOR_GEN_CRYPTO_H
#define CRYPTO_OBFUSCATE_XOR_GEN_CRYPTO_H

#include "crypto/obfuscate.h"

/* Internal: ChaCha20 key derivation, encryption/decryption.
 * Split from xor_gen.cpp for modularity.
 * Public API remains in obfuscate.h (umbrella). */

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

#endif /* CRYPTO_OBFUSCATE_XOR_GEN_CRYPTO_H */
