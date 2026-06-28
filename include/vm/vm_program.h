#ifndef CRYPTO_VM_PROGRAM_H
#define CRYPTO_VM_PROGRAM_H

#include "vm/vm_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* VmProgram lifecycle and default configuration.
 * Split from vm_compile.cpp for modularity. */

ExitCode vm_program_init(VmProgram *prog);
void     vm_program_free(VmProgram *prog);
void     vm_default_config(VmCompileConfig *cfg);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_VM_PROGRAM_H */
