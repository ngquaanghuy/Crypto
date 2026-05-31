#ifndef CRYPTO_VM_H
#define CRYPTO_VM_H

#include "crypto/common.h"
#include <stdint.h>

#define VM_SER_FLAG_VL_ENCODED       (1 << 0)
#define VM_SER_FLAG_CONST_ENCRYPTED  (1 << 1)
#define VM_SER_FLAG_CFI_ENABLED      (1 << 2)
#define VM_SER_FLAG_POLY_ENCODING    (1 << 3)

#define VM_INSTR_SIZE    8
#define VM_INSTR_SIZE_MIN 2
#define VM_INSTR_SIZE_MAX 64
#define VM_REGS          64
#define VM_MAX_CONSTS    256
#define VM_MAX_NAMES     256
#define VM_SPILL_STACK_MAX 128
#define VM_CFI_MAX_BLOCKS  64
#define VM_CONST_KEY_SIZE  16

typedef enum {
    // Base instructions (0-29)
    VM_NOP          = 0,
    VM_LOAD_CONST   = 1,
    VM_LOAD_NAME    = 2,
    VM_STORE_NAME   = 3,
    VM_LOAD_FAST    = 4,
    VM_STORE_FAST   = 5,
    VM_MOVE         = 6,
    VM_ADD          = 10,
    VM_SUB          = 11,
    VM_MUL          = 12,
    VM_DIV          = 13,
    VM_POW          = 14,
    VM_NEG          = 15,

    // Comparison (20-29)
    VM_CMP_EQ       = 20,
    VM_CMP_NE       = 21,
    VM_CMP_LT       = 22,
    VM_CMP_LE       = 23,
    VM_CMP_GT       = 24,
    VM_CMP_GE       = 25,

    // Control flow (30-39)
    VM_JMP          = 30,
    VM_JMP_IF_TRUE  = 31,
    VM_JMP_IF_FALSE = 32,
    VM_BINARY_SUBSCR = 33,

    // Call / return (40-49)
    VM_CALL         = 40,
    VM_CALL_NAME    = 41,
    VM_RETURN       = 42,
    VM_BUILD_TUPLE  = 43,
    VM_BUILD_LIST   = 44,

    // Subscr / store (50-59)
    VM_STORE_SUBSCR = 50,

    // Opaque predicates (52-53)
    VM_OPAQUE_TRUE  = 52,
    VM_OPAQUE_FALSE = 53,

    // Attribute / import (60-69)
    VM_LOAD_ATTR    = 60,
    VM_IMPORT_NAME  = 61,
    VM_FORMAT_SIMPLE = 62,
    VM_BUILD_STRING  = 63,

    // Iteration (70-79)
    VM_GET_ITER      = 70,
    VM_FOR_ITER      = 71,
    VM_LIST_EXTEND   = 72,
    VM_LIST_APPEND   = 75,

    // ─── INDIRECT & VIRTUAL CALL (80-89) ─────────────────────
    VM_CALL_INDIRECT = 80,
    VM_CALL_VTABLE   = 81,

    // ─── EXCEPTION HANDLING (90-99) ──────────────────────────
    VM_TRY           = 90,
    VM_CATCH         = 91,
    VM_THROW         = 92,
    VM_END_TRY       = 93,

    // ─── OBFUSCATED CONDITIONAL BRANCHING (100-115) ──────────
    VM_JMP_IF_TRUE_OBF  = 100,
    VM_JMP_IF_FALSE_OBF = 101,
    VM_JMP_EQ           = 102,
    VM_JMP_NE           = 103,
    VM_JMP_LT           = 104,
    VM_JMP_LE           = 105,
    VM_JMP_GT           = 106,
    VM_JMP_GE           = 107,
    VM_JMP_INDIRECT     = 108,
    VM_JMP_TABLE        = 109,

    // ─── REGISTER SPILLING (120-129) ─────────────────────────
    VM_SPILL        = 120,
    VM_RESTORE      = 121,
    VM_SPILL_MANY   = 122,
    VM_RESTORE_MANY = 123,

    // ─── SELF-MODIFYING CODE (130-139) ───────────────────────
    VM_PATCH_INSTR  = 130,
    VM_PATCH_OPCODE = 131,
    VM_ENCRYPT_SEG  = 132,
    VM_DECRYPT_SEG  = 133,

    // ─── DATA OBFUSCATION (140-149) ──────────────────────────
    VM_OBF_MOVE     = 140,
    VM_OBF_ADD      = 141,
    VM_OBF_XOR      = 142,

    // ─── CONTROL FLOW INTEGRITY (150-159) ─────────────────────
    VM_CFI_CHECK    = 150,
    VM_CFI_FAIL     = 151,
    VM_CFI_TABLE    = 152,

    // ─── CONSTANT DECRYPTION (160) ────────────────────────────
    VM_CONST_DECRYPT = 160,
} VmOpcode;

typedef struct __attribute__((packed)) {
    uint8_t  op;
    uint8_t  rd;
    uint8_t  rs1;
    uint8_t  rs2;
    int32_t  imm;
} VmInstr;

typedef enum {
    VL_CLASS_SHORT    = 0,
    VL_CLASS_MEDIUM   = 1,
    VL_CLASS_LONG     = 2,
    VL_CLASS_EXTENDED = 3,
} VlLengthClass;

typedef struct {
    VmInstr *instrs;
    int count;
    uint8_t *opcode_map;
    uint8_t *const_types;
    char   **const_strs;
    int      const_count;
    char   **names;
    int      name_count;
    // Variable-length encoded code (when encoding is applied)
    uint8_t *vl_code;
    int      vl_code_len;
    // Feature flags for this program
    int      flags;
    // Constant encryption key (16 bytes, used when VM_SER_FLAG_CONST_ENCRYPTED set)
    uint8_t  const_key[VM_CONST_KEY_SIZE];
    // Polymorphic encoding seed
    int      poly_seed;
    // CFI checksum table
    uint32_t *cfi_checksums;
    int       cfi_num_blocks;
    int      *cfi_block_starts;
    int      *cfi_block_lengths;
} VmProgram;

// Compilation configuration
typedef struct {
    int enable_opaque;
    int seed;

    // Feature flags
    int enable_indirect_calls;
    int enable_virtual_calls;
    int enable_exceptions;
    int enable_var_length_encoding;
    int enable_conditional_obfuscation;
    int enable_register_spilling;
    int enable_self_modifying_code;

    // Spilling config
    int spill_pressure_threshold;
    int spill_target_pressure;
    int spill_interval;
    float spill_probability;

    // Self-modification config
    int smc_min_interval;
    int smc_max_interval;

    // Conditional obfuscation config
    int cond_obfuscation_strength;

    // ─── New feature flags ─────────────────────────────────
    int enable_polymorphic_encoding;
    int enable_constant_encryption;
    int enable_cfi;
    int enable_code_scheduling;

    // CFI config
    int cfi_check_interval;

    // Code scheduling config
    int schedule_strength;
} VmCompileConfig;

// ─── VmProgram lifecycle ─────────────────────────────────────
ExitCode vm_program_init(VmProgram *prog);
void vm_program_free(VmProgram *prog);

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

// ─── Serialization ───────────────────────────────────────────
ExitCode vm_serialize(const VmProgram *prog, Buffer *out);
ExitCode vm_deserialize(const unsigned char *data, size_t size,
                         VmProgram *prog);

// ─── Encryption ──────────────────────────────────────────────
int vm_encrypt_blob(const unsigned char *plaintext, int plaintext_len,
                    unsigned char **ciphertext, int *ciphertext_len);

#endif
