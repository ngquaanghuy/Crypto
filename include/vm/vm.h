#ifndef CRYPTO_VM_H
#define CRYPTO_VM_H

// ─── Umbrella header — includes all VM sub-headers ───────────
// Types, flags, opcodes, structs → vm_types.h
// Program lifecycle + default config → vm_program.h
// Serialization → vm_serialize.h
// Remaining declarations (compilation, encoding, passes) stay here.

#include "vm/vm_types.h"
#include "vm/vm_program.h"
#include "vm/vm_serialize.h"

#ifdef __cplusplus
extern "C" {
#endif

// ─── Compilation ─────────────────────────────────────────────
ExitCode vm_compile_source(const char *source, size_t source_len,
                            VmProgram *prog, int opaque, int seed = -1);
ExitCode vm_compile_source_ex(const char *source, size_t source_len,
                               VmProgram *prog, VmCompileConfig *cfg);

// ─── Variable-length encoding ────────────────────────────────
typedef struct {
    uint8_t op_shuf;
    uint8_t rd;
    uint8_t rs1;
    uint8_t rs2;
    int32_t imm;
    int     size;      // encoded size in bytes
} VmDecodedInstr;

size_t vm_encode_var_length(uint8_t *out, size_t out_max,
                            uint8_t canonical_op,
                            uint8_t rd, uint8_t rs1, uint8_t rs2,
                            int32_t imm);
size_t vm_decode_var_length(const uint8_t *code, size_t code_len,
                            VmDecodedInstr *dec);
ExitCode vm_encode_program(const VmProgram *prog, Buffer *out);

// ─── Polymorphic encoding ────────────────────────────────────
// Polymorphic variant descriptors
typedef struct {
    uint8_t variant_id;     // 0-3
    int     class_tag;      // short=0, medium=1, long=2, extended=3
    int     size;           // encoded size in bytes (may differ from base class)
    int     bit_layout;     // layout identifier for decoder
} PolyVariant;

size_t vm_encode_polymorphic(uint8_t *out, size_t out_max,
                             uint8_t canonical_op,
                             uint8_t rd, uint8_t rs1, uint8_t rs2,
                             int32_t imm, int variant_id, int poly_seed);
size_t vm_decode_polymorphic(const uint8_t *code, size_t code_len,
                             VmDecodedInstr *dec);
ExitCode vm_encode_program_poly(const VmProgram *prog, Buffer *out);

// ─── Compilation passes ──────────────────────────────────────
ExitCode vm_pass_isa_expand(VmProgram *prog, VmCompileConfig *cfg);
ExitCode vm_pass_spill_registers(VmProgram *prog, VmCompileConfig *cfg);
ExitCode vm_pass_inject_self_modifying(VmProgram *prog, VmCompileConfig *cfg);
ExitCode vm_pass_obfuscate_conditions(VmProgram *prog, int strength);
ExitCode vm_pass_cfi(VmProgram *prog, VmCompileConfig *cfg);
ExitCode vm_pass_code_schedule(VmProgram *prog, VmCompileConfig *cfg);
ExitCode vm_pass_inject_vram_garble(VmProgram *prog, VmCompileConfig *cfg);

#ifdef __cplusplus
}
#endif

#endif
