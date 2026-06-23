#ifndef CRYPTO_XORCODE_H
#define CRYPTO_XORCODE_H

#include "crypto/common.h"

#define XOR_KEY_SIZE      32
#define XOR_SALT_SIZE     16
#define XOR_HMAC_SIZE     32

ExitCode xor_transform(const unsigned char *in, size_t in_size,
                        const unsigned char *key, size_t key_size,
                        Buffer *out);

// Authenticated XOR with HMAC (recommended for production use)
ExitCode xor_transform_auth(const unsigned char *in, size_t in_size,
                            const unsigned char *key, size_t key_size,
                            Buffer *out);
ExitCode xor_decrypt_auth(const unsigned char *in, size_t in_size,
                           const unsigned char *key, size_t key_size,
                           Buffer *out);

ExitCode rolling_xor_encrypt(const unsigned char *in, size_t in_size,
                                 const unsigned char *key, size_t key_size,
                                 Buffer *out);

ExitCode rolling_xor_decrypt(const unsigned char *in, size_t in_size,
                                 const unsigned char *key, size_t key_size,
                                 Buffer *out);

ExitCode xor_bit_rotation_encrypt(const unsigned char *in, size_t in_size,
                                  const unsigned char *key, size_t key_size,
                                  Buffer *out);

ExitCode xor_bit_rotation_decrypt(const unsigned char *in, size_t in_size,
                                  const unsigned char *key, size_t key_size,
                                  Buffer *out);

ExitCode xor_encrypt_protect(const unsigned char *in, size_t in_size,

                               const unsigned char *pass, size_t pass_len,
                               Buffer *out);

ExitCode xor_decrypt_protect(const unsigned char *in, size_t in_size,
                               const unsigned char *pass, size_t pass_len,
                               Buffer *out);

ExitCode rolling_xor_encrypt_protect(const unsigned char *in, size_t in_size,
                                     const unsigned char *pass, size_t pass_len,
                                     Buffer *out);

ExitCode rolling_xor_decrypt_protect(const unsigned char *in, size_t in_size,
                                      const unsigned char *pass, size_t pass_len,
                                      Buffer *out);

ExitCode multi_pass_xor_encrypt(const unsigned char *in, size_t in_size,
                                 const unsigned char *key, size_t key_size,
                                 int num_passes,
                                 Buffer *out);

ExitCode multi_pass_xor_decrypt(const unsigned char *in, size_t in_size,
                                 const unsigned char *key, size_t key_size,
                                 int num_passes,
                                 Buffer *out);

ExitCode multi_pass_xor_encrypt_protect(const unsigned char *in, size_t in_size,
                                         const unsigned char *pass, size_t pass_len,
                                         Buffer *out);

ExitCode multi_pass_xor_decrypt_protect(const unsigned char *in, size_t in_size,
                                         const unsigned char *pass, size_t pass_len,
                                         Buffer *out);

ExitCode prng_xor_encrypt(const unsigned char *in, size_t in_size,
                           const unsigned char *key, size_t key_size,
                           Buffer *out);

ExitCode prng_xor_decrypt(const unsigned char *in, size_t in_size,
                           const unsigned char *key, size_t key_size,
                           Buffer *out);

ExitCode prng_xor_encrypt_protect(const unsigned char *in, size_t in_size,
                                   const unsigned char *pass, size_t pass_len,
                                   Buffer *out);

ExitCode prng_xor_decrypt_protect(const unsigned char *in, size_t in_size,
                                   const unsigned char *pass, size_t pass_len,
                                   Buffer *out);


#endif
