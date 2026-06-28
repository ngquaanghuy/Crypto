#ifndef CRYPTO_VM_SERIALIZE_H
#define CRYPTO_VM_SERIALIZE_H

#include "vm/vm_types.h"
#include "crypto/common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* VM binary serialization / deserialization + deprecated encrypt_blob.
 * Split from vm_compile.cpp for modularity. */

ExitCode vm_serialize(const VmProgram *prog, Buffer *out);
ExitCode vm_deserialize(const unsigned char *data, size_t size,
                        VmProgram *prog);

/* Deprecated: VM blob encryption now happens in protect.cpp.
 * Kept for API compatibility only — always returns -1. */
int vm_encrypt_blob(const unsigned char *plaintext, int plaintext_len,
                    unsigned char **ciphertext, int *ciphertext_len);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_VM_SERIALIZE_H */
