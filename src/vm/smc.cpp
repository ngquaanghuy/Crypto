#include "vm/vm.h"
#include <cstdlib>
#include <cstring>
#include <vector>
#include <algorithm>

// ─── Self-Modifying Code Pass ───────────────────────────────
// Injects PATCH_INSTR, PATCH_OPCODE, and ENCRYPT_SEG/DECRYPT_SEG
// instructions at pseudo-random intervals in the instruction stream.
//
// Safety: SMC instructions are placed at positions where they modify
// code regions that are NOT the currently executing instruction.
// The interpreter also enforces a safety window of 16 bytes.

ExitCode vm_pass_inject_self_modifying(VmProgram *prog, VmCompileConfig *cfg) {
    if (!prog || !cfg) return EXIT_ERR_ARGS;
    if (!prog->instrs || prog->count == 0) return EXIT_OK;

    int min_interval = cfg->smc_min_interval;
    if (min_interval <= 0) min_interval = 20;
    int max_interval = cfg->smc_max_interval;
    if (max_interval <= 0) max_interval = 50;
    if (max_interval < min_interval) max_interval = min_interval + 10;

    int seed = cfg->seed >= 0 ? cfg->seed : (int)rand();
    srand(seed);

    std::vector<VmInstr> out;
    out.reserve(prog->count + 10);

    int smc_counter = 0;
    int next_smc = min_interval + rand() % (max_interval - min_interval + 1);

    for (int i = 0; i < prog->count; i++) {
        out.push_back(prog->instrs[i]);
        smc_counter++;

        // Check if we should insert SMC after this instruction
        if (smc_counter >= next_smc && i < prog->count - 2) {
            smc_counter = 0;
            next_smc = min_interval + rand() % (max_interval - min_interval + 1);

            int smc_type = rand() % 3;
            // Choose a target instruction that's far enough away
            int target_idx = (i + 3 + rand() % 8) % prog->count;
            if (target_idx >= prog->count) target_idx = prog->count - 1;
            if (target_idx < 0) target_idx = 0;

            // Ensure target != current position
            if (target_idx == i) target_idx = (i + 1) % prog->count;

            if (smc_type == 0) {
                // VM_PATCH_INSTR: XOR-patch 8 bytes at target location
                // Uses a key derived from the target index and random value
                VmInstr patch;
                patch.op = VM_PATCH_INSTR;
                patch.rd = 0;          // offset will be loaded into rd first
                patch.rs1 = 1;         // length in rs1
                patch.rs2 = 2;         // key in rs2

                // Need to load the offset, length, and key into registers first.
                // We'll use LOAD_CONST instructions to set up the parameters.
                VmInstr load_off;
                load_off.op = VM_LOAD_CONST;
                load_off.rd = patch.rd;
                load_off.rs1 = 0;
                load_off.rs2 = 0;
                load_off.imm = target_idx * (int)sizeof(VmInstr);

                VmInstr load_len;
                load_len.op = VM_LOAD_CONST;
                load_len.rd = patch.rs1;
                load_len.rs1 = 0;
                load_len.rs2 = 0;
                load_len.imm = 8;

                VmInstr load_key;
                load_key.op = VM_LOAD_CONST;
                load_key.rd = patch.rs2;
                load_key.rs1 = 0;
                load_key.rs2 = 0;
                load_key.imm = rand() ^ target_idx;

                out.push_back(load_off);
                out.push_back(load_len);
                out.push_back(load_key);
                out.push_back(patch);
            }
            else if (smc_type == 1) {
                // VM_PATCH_OPCODE: remap an opcode at runtime
                VmInstr patch_op;
                patch_op.op = VM_PATCH_OPCODE;
                patch_op.rd = (uint8_t)(rand() % 256);  // shuffled opcode to remap
                patch_op.rs1 = (uint8_t)(rand() % 60);   // new canonical opcode
                patch_op.rs2 = 0;
                patch_op.imm = 0;
                out.push_back(patch_op);
            }
            else {
                // VM_DECRYPT_SEG: decrypt a code segment
                VmInstr decrypt;
                decrypt.op = VM_DECRYPT_SEG;
                decrypt.rd = 0;
                decrypt.rs1 = 1;
                decrypt.rs2 = 2;

                int seg_len = 8 + rand() % 24;  // 8-32 byte segment

                VmInstr load_off;
                load_off.op = VM_LOAD_CONST;
                load_off.rd = decrypt.rd;
                load_off.rs1 = 0;
                load_off.rs2 = 0;
                load_off.imm = target_idx * (int)sizeof(VmInstr);

                VmInstr load_len;
                load_len.op = VM_LOAD_CONST;
                load_len.rd = decrypt.rs1;
                load_len.rs1 = 0;
                load_len.rs2 = 0;
                load_len.imm = seg_len;

                VmInstr load_key;
                load_key.op = VM_LOAD_CONST;
                load_key.rd = decrypt.rs2;
                load_key.rs1 = 0;
                load_key.rs2 = 0;
                load_key.imm = (int)(rand() ^ target_idx ^ seg_len);

                out.push_back(load_off);
                out.push_back(load_len);
                out.push_back(load_key);
                out.push_back(decrypt);
            }
        }
    }

    // Replace prog instruction array
    VmInstr *nd = (VmInstr *)realloc(prog->instrs, out.size() * sizeof(VmInstr));
    if (nd || out.size() == 0) {
        if (nd) prog->instrs = nd;
        memcpy(prog->instrs, out.data(), out.size() * sizeof(VmInstr));
        prog->count = (int)out.size();
    }

    return EXIT_OK;
}
