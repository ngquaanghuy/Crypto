#ifndef CRYPTO_VM_H
#define CRYPTO_VM_H

#include "crypto/common.h"
#include <stdint.h>

#define VM_SER_FLAG_VL_ENCODED       (1 << 0)
#define VM_SER_FLAG_CONST_ENCRYPTED  (1 << 1)
#define VM_SER_FLAG_CFI_ENABLED      (1 << 2)
#define VM_SER_FLAG_POLY_ENCODING    (1 << 3)
#define VM_SER_FLAG_HAS_HEADER       (1 << 4)

// VM binary header (32 bytes) — written at start of serialized VM data
// Backward-compatible: legacy data starts with opcode_map (no magic)
#define VM_HEADER_MAGIC      0x0001564D  // "VM\x01\x00" (little-endian)
#define VM_HEADER_SIZE       32
#define VM_HEADER_VERSION_MAJOR 1

typedef struct __attribute__((packed)) {
    uint32_t magic;         // VM_HEADER_MAGIC
    uint32_t flags;         // VM_SER_FLAG_*
    uint32_t entry_point;   // initial instruction pointer
    uint32_t const_offset;  // byte offset to constants section (0 = immediately after header)
    uint32_t names_offset;  // byte offset to names section
    uint32_t code_offset;   // byte offset to code section
    uint32_t opmap_offset;  // byte offset to opcode map (256 bytes)
    uint32_t total_size;    // total VM data size (including header)
} VmHeader;

#define VM_INSTR_SIZE    8
#define VM_INSTR_SIZE_MIN 2
#define VM_INSTR_SIZE_MAX 64
#define VM_REGS          64
#define VM_MAX_CONSTS    256
#define VM_MAX_NAMES     256
#define VM_SPILL_STACK_MAX 128
#define VM_CFI_MAX_BLOCKS  64
#define VM_CONST_KEY_SIZE  16

// ─── Virtual RAM (vRAM) ─────────────────────────────────────
#define VM_RAM_SIZE        4096  // 4 KB virtual RAM
#define VM_RAM_KEY_SIZE     16   // 16-byte XOR key for RAM garbling

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

    // Bitwise / extended arithmetic (16-19)
    VM_BIT_OR       = 16,
    VM_BIT_AND      = 17,
    VM_BIT_XOR      = 18,
    VM_LSHIFT       = 19,

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

    // Extended arithmetic cont'd (34-36)
    VM_RSHIFT       = 34,
    VM_FLOOR_DIV    = 35,
    VM_MOD          = 36,

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

    // MAKE_FUNCTION (54)
    VM_MAKE_FUNCTION = 54,

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

    // ═══════════════════════════════════════════════════════════
    // DATA STRUCTURES (161-179)
    // ═══════════════════════════════════════════════════════════
    VM_BINARY_SLICE    = 161, // obj[start:stop]
    VM_DELETE_SUBSCR   = 162, // del obj[key]
    VM_STORE_SLICE     = 163, // obj[start:stop] = val
    VM_BUILD_MAP       = 164, // dict literal {...}
    VM_BUILD_SET       = 165, // set literal {...}
    VM_BUILD_SLICE     = 166, // slice(start, stop[, step])
    VM_COPY            = 167, // Shallow copy (Py 3.14+)
    VM_DICT_MERGE      = 168, // dict |= other
    VM_DICT_UPDATE     = 169, // dict.update(other)
    VM_MAP_ADD         = 170, // dict[key] = value (dict comp)
    VM_SET_ADD         = 171, // set.add(item)
    VM_SET_UPDATE      = 172, // set.update(other)

    // ═══════════════════════════════════════════════════════════
    // ITERATOR / GENERATOR / ASYNC (180-199)
    // ═══════════════════════════════════════════════════════════
    VM_END_SEND              = 180,
    VM_GET_AITER             = 181,
    VM_GET_ANEXT             = 182,
    VM_GET_YIELD_FROM_ITER   = 183,
    VM_LOAD_BUILD_CLASS      = 184,
    VM_RETURN_GENERATOR      = 185,
    VM_COPY_FREE_VARS        = 186,
    VM_DELETE_DEREF          = 187,
    VM_END_ASYNC_FOR         = 188,
    VM_GET_AWAITABLE         = 189,
    VM_LOAD_DEREF            = 190,
    VM_MAKE_CELL             = 191,
    VM_SEND                  = 192,
    VM_STORE_DEREF           = 193,
    VM_YIELD_VALUE           = 194,
    VM_LOAD_CLOSURE          = 195,

    // ═══════════════════════════════════════════════════════════
    // EXCEPTION HANDLING (200-219)
    // ═══════════════════════════════════════════════════════════
    VM_CHECK_EG_MATCH     = 200,
    VM_CHECK_EXC_MATCH    = 201,
    VM_CLEANUP_THROW      = 202,
    VM_POP_EXCEPT         = 203,
    VM_PUSH_EXC_INFO      = 204,
    VM_WITH_EXCEPT_START  = 205,
    VM_RERAISE            = 206,
    VM_POP_BLOCK          = 207,
    VM_SETUP_CLEANUP      = 208,
    VM_SETUP_FINALLY      = 209,
    VM_SETUP_WITH         = 210,

    // ═══════════════════════════════════════════════════════════
    // PATTERN MATCHING (220-229)
    // ═══════════════════════════════════════════════════════════
    VM_MATCH_KEYS       = 220,
    VM_MATCH_MAPPING    = 221,
    VM_MATCH_SEQUENCE   = 222,
    VM_MATCH_CLASS      = 223,

    // ═══════════════════════════════════════════════════════════
    // CONTROL FLOW — PYTHON 3.14+ (230-239)
    // ═══════════════════════════════════════════════════════════
    VM_POP_ITER                    = 230,
    VM_JUMP_BACKWARD_NO_INTERRUPT  = 231,
    VM_JUMP                        = 232,
    VM_JUMP_IF_FALSE               = 233,
    VM_JUMP_IF_TRUE                = 234,
    VM_JUMP_NO_INTERRUPT           = 235,

    // ═══════════════════════════════════════════════════════════
    // ATTRIBUTE OPERATIONS (240-244)
    // ═══════════════════════════════════════════════════════════
    VM_DELETE_ATTR      = 240,
    VM_LOAD_SUPER_ATTR  = 241,
    VM_STORE_ATTR       = 242,

    // ═══════════════════════════════════════════════════════════
    // CALL VARIANTS (245-249)
    // ═══════════════════════════════════════════════════════════
    VM_CALL_FUNCTION_EX  = 245,
    VM_CALL_INTRINSIC_1  = 246,
    VM_CALL_INTRINSIC_2  = 247,
    VM_CALL_KW           = 248,

    // ═══════════════════════════════════════════════════════════
    // NAME OPERATIONS — DELETE (250-255)
    // ═══════════════════════════════════════════════════════════
    VM_DELETE_FAST             = 250,
    VM_DELETE_GLOBAL           = 251,
    VM_DELETE_NAME             = 252,
    VM_LOAD_FROM_DICT_OR_DEREF  = 253,
    VM_LOAD_FROM_DICT_OR_GLOBALS = 254,

    // ═══════════════════════════════════════════════════════════
    // VIRTUAL RAM (143-147) — uses existing opcode range (0-255)
    // ═══════════════════════════════════════════════════════════
    VM_LOAD_B       = 143,  // load byte from vRAM[rs1] → rd
    VM_STORE_B      = 144,  // store byte rd → vRAM[rs2]
    VM_LOAD_W       = 145,  // load 32-bit word from vRAM[rs1] → rd
    VM_STORE_W      = 146,  // store 32-bit word rd → vRAM[rs2]
    VM_RAM_GARBLE   = 147,  // re-key entire vRAM (rotate XOR keys)

    // ═══════════════════════════════════════════════════════════
    // UNARY / BITWISE (256-259)
    // ═══════════════════════════════════════════════════════════
    VM_UNARY_INVERT = 7,
    VM_UNARY_NOT    = 8,

    // ═══════════════════════════════════════════════════════════
    // TYPE SYSTEM (260-269)
    // ═══════════════════════════════════════════════════════════
    VM_SETUP_ANNOTATIONS     = 9,
    VM_CONVERT_VALUE         = 110,
    VM_LOAD_COMMON_CONSTANT  = 111,
    VM_LOAD_SPECIAL          = 112,
    VM_ANNOTATIONS_PLACEHOLDER = 113,

    // ═══════════════════════════════════════════════════════════
    // OTHER / MISC (270-289)
    // ═══════════════════════════════════════════════════════════
    VM_BUILD_TEMPLATE        = 114,
    VM_END_FOR               = 115,
    VM_EXIT_INIT_CHECK       = 116,
    VM_FORMAT_WITH_SPEC      = 117,
    VM_RESERVED              = 118,
    VM_GET_LEN               = 119,
    VM_INTERPRETER_EXIT      = 124,
    VM_BUILD_INTERPOLATION   = 125,
    VM_CONTAINS_OP           = 126,
    VM_IS_OP                 = 127,
    VM_LOAD_FAST_CHECK       = 128,
    VM_RAISE_VARARGS         = 129,
    VM_STORE_FAST_LOAD_FAST  = 134,
    VM_STORE_FAST_STORE_FAST = 135,
    VM_UNPACK_EX             = 136,
    VM_UNPACK_SEQUENCE       = 137,
    VM_ENTER_EXECUTOR        = 138,
    VM_STORE_FAST_MAYBE_NULL = 139,
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

    // Virtual RAM garble config
    int enable_vram_garble;
    int vram_garble_min_interval;
    int vram_garble_max_interval;
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
ExitCode vm_pass_inject_vram_garble(VmProgram *prog, VmCompileConfig *cfg);

// ─── Serialization ───────────────────────────────────────────
ExitCode vm_serialize(const VmProgram *prog, Buffer *out);
ExitCode vm_deserialize(const unsigned char *data, size_t size,
                         VmProgram *prog);

// ─── Encryption ──────────────────────────────────────────────
int vm_encrypt_blob(const unsigned char *plaintext, int plaintext_len,
                    unsigned char **ciphertext, int *ciphertext_len);

#endif
