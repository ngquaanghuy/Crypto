#ifndef CRYPTO_VM_H
#define CRYPTO_VM_H

#include "crypto/common.h"
#include <stdint.h>

#define VM_INSTR_SIZE    8
#define VM_REGS          64
#define VM_MAX_CONSTS    256
#define VM_MAX_NAMES     256

typedef enum {
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
    VM_CMP_EQ       = 20,
    VM_CMP_NE       = 21,
    VM_CMP_LT       = 22,
    VM_CMP_LE       = 23,
    VM_CMP_GT       = 24,
    VM_CMP_GE       = 25,
    VM_STORE_SUBSCR = 50,
    VM_JMP          = 30,
    VM_JMP_IF_TRUE  = 31,
    VM_JMP_IF_FALSE = 32,
    VM_BINARY_SUBSCR = 33,
    VM_CALL         = 40,
    VM_CALL_NAME    = 41,
    VM_RETURN       = 42,
    VM_BUILD_TUPLE  = 43,
    VM_BUILD_LIST   = 44,
    VM_OPAQUE_TRUE  = 52,
    VM_OPAQUE_FALSE = 53,
    VM_LOAD_ATTR    = 60,
    VM_IMPORT_NAME  = 61,
    VM_FORMAT_SIMPLE = 62,
    VM_BUILD_STRING  = 63,
    VM_GET_ITER      = 70,
    VM_FOR_ITER      = 71,
    VM_LIST_EXTEND   = 72,
    VM_LIST_APPEND   = 75,
} VmOpcode;

typedef struct __attribute__((packed)) {
    uint8_t  op;
    uint8_t  rd;
    uint8_t  rs1;
    uint8_t  rs2;
    int32_t  imm;
} VmInstr;

typedef struct {
    VmInstr *instrs;
    int count;
    // Opcode mapping for obfuscation
    uint8_t *opcode_map;
    // Constant pool
    uint8_t *const_types;
    char   **const_strs;  // all constants serialized as strings
    int      const_count;
    // Name pool
    char   **names;
    int      name_count;
} VmProgram;

ExitCode vm_program_init(VmProgram *prog);
void vm_program_free(VmProgram *prog);

// Compile Python source → VM program (calls Python via temp files)
ExitCode vm_compile_source(const char *source, size_t source_len,
                            VmProgram *prog, int opaque, int seed = -1);

// Serialize VM program to binary blob
ExitCode vm_serialize(const VmProgram *prog, Buffer *out);

// Deserialize binary blob → VM program
ExitCode vm_deserialize(const unsigned char *data, size_t size,
                         VmProgram *prog);

// Encrypt & HMAC VM blob for storage in stub
// Plaintext format: opcode_map[256] + consts + names + code
// Output format: IV[16] + AES-256-CTR ciphertext + HMAC-SHA256[32]
int vm_encrypt_blob(const unsigned char *plaintext, int plaintext_len,
                    unsigned char **ciphertext, int *ciphertext_len);

#endif
