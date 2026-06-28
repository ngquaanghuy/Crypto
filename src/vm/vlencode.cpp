#include "vm/vm.h"
#include <cstdlib>
#include <cstring>
#include <vector>

// ─── Polymorphic program encoder ──────────────────────────
// Encodes entire program using vm_encode_polymorphic with variants.
ExitCode vm_encode_program_poly(const VmProgram *prog, Buffer *out) {
    if (!prog || !out) return EXIT_ERR_ARGS;
    if (!prog->instrs || prog->count == 0) {
        out->data = (unsigned char *)malloc(1);
        if (!out->data) return EXIT_ERR_CRYPTO;
        out->size = 0;
        return EXIT_OK;
    }

    // First pass: compute size
    size_t total_size = 0;
    for (int i = 0; i < prog->count; i++) {
        const VmInstr *inst = &prog->instrs[i];
        uint8_t tmp[16];
        size_t sz = vm_encode_polymorphic(tmp, sizeof(tmp), inst->op, inst->rd,
                                          inst->rs1, inst->rs2, inst->imm,
                                          -1, prog->poly_seed + i);
        if (sz == 0) sz = 8;
        total_size += sz;
    }

    out->data = (unsigned char *)malloc(total_size);
    if (!out->data) return EXIT_ERR_CRYPTO;

    size_t pos = 0;
    for (int i = 0; i < prog->count; i++) {
        const VmInstr *inst = &prog->instrs[i];
        size_t sz = vm_encode_polymorphic(out->data + pos, total_size - pos,
                                          inst->op, inst->rd, inst->rs1,
                                          inst->rs2, inst->imm,
                                          -1, prog->poly_seed + i);
        if (sz == 0) {
            out->data[pos] = 0x80;
            out->data[pos + 1] = inst->op;
            out->data[pos + 2] = inst->rd;
            out->data[pos + 3] = inst->rs1;
            out->data[pos + 4] = inst->rs2;
            out->data[pos + 5] = (uint8_t)(inst->imm & 0xFF);
            out->data[pos + 6] = (uint8_t)((inst->imm >> 8) & 0xFF);
            out->data[pos + 7] = (uint8_t)((inst->imm >> 16) & 0xFF);
            out->data[pos + 8] = (uint8_t)((inst->imm >> 24) & 0xFF);
            sz = 9;
        }
        pos += sz;
    }

    out->size = pos;
    return EXIT_OK;
}

// ─── Encode entire program to variable-length bytecode ──────
// Produces a packed byte array in Buffer out.
ExitCode vm_encode_program(const VmProgram *prog, Buffer *out) {
    if (!prog || !out) return EXIT_ERR_ARGS;
    if (!prog->instrs || prog->count == 0) {
        out->data = (unsigned char *)malloc(1);
        if (!out->data) return EXIT_ERR_CRYPTO;
        out->size = 0;
        return EXIT_OK;
    }

    // First pass: compute total encoded size
    size_t total_size = 0;
    for (int i = 0; i < prog->count; i++) {
        const VmInstr *inst = &prog->instrs[i];
        uint8_t tmp[16];
        size_t sz = vm_encode_var_length(tmp, sizeof(tmp),
                                         inst->op, inst->rd, inst->rs1,
                                         inst->rs2, inst->imm);
        if (sz == 0) {
            // Fallback: long format
            sz = 8;
        }
        total_size += sz;
    }

    // Allocate output buffer
    out->data = (unsigned char *)malloc(total_size);
    if (!out->data) return EXIT_ERR_CRYPTO;

    // Second pass: encode
    size_t pos = 0;
    for (int i = 0; i < prog->count; i++) {
        const VmInstr *inst = &prog->instrs[i];
        size_t sz = vm_encode_var_length(out->data + pos, total_size - pos,
                                         inst->op, inst->rd, inst->rs1,
                                         inst->rs2, inst->imm);
        if (sz == 0) {
            // Long fallback: 9 bytes with tag 0x80
            out->data[pos] = 0x80;
            out->data[pos + 1] = inst->op;
            out->data[pos + 2] = inst->rd;
            out->data[pos + 3] = inst->rs1;
            out->data[pos + 4] = inst->rs2;
            out->data[pos + 5] = (uint8_t)(inst->imm & 0xFF);
            out->data[pos + 6] = (uint8_t)((inst->imm >> 8) & 0xFF);
            out->data[pos + 7] = (uint8_t)((inst->imm >> 16) & 0xFF);
            out->data[pos + 8] = (uint8_t)((inst->imm >> 24) & 0xFF);
            sz = 9;
        }
        pos += sz;
    }

    out->size = pos;
    return EXIT_OK;
}
