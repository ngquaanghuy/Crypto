#include "vm/vm.h"
#include <cstdlib>
#include <cstring>
#include <vector>

// ─── Obfuscated Condition Pass ──────────────────────────────
// Replaces direct conditional jumps with obfuscated versions.
// At strength 1: replaces opcodes with obfuscated equivalents.
// At strength 2: inserts arithmetic obfuscation instructions before branches.

ExitCode vm_pass_obfuscate_conditions(VmProgram *prog, int strength) {
    if (!prog || !prog->instrs || prog->count == 0) return EXIT_ERR_ARGS;
    if (strength <= 0) return EXIT_OK;

    for (int i = 0; i < prog->count; i++) {
        VmInstr *inst = &prog->instrs[i];

        // Replace JMP_IF_TRUE → JMP_IF_TRUE_OBF
        if (inst->op == VM_JMP_IF_TRUE) {
            inst->op = VM_JMP_IF_TRUE_OBF;
        }
        // Replace JMP_IF_FALSE → JMP_IF_FALSE_OBF
        else if (inst->op == VM_JMP_IF_FALSE) {
            inst->op = VM_JMP_IF_FALSE_OBF;
        }
        // Replace comparison results → obfuscated branches when followed by JMP
        else if (strength >= 2) {
            // If we have a CMP instruction followed by JMP_IF_TRUE/FALSE,
            // replace the pair with an obfuscated conditional jump
            int op = inst->op;
            if (op >= VM_CMP_EQ && op <= VM_CMP_GE) {
                // Map comparison opcode to obfuscated jump opcode
                static const int cmp_to_jmp[] = {
                    VM_JMP_EQ,  // VM_CMP_EQ = 20 → VM_JMP_EQ = 102
                    VM_JMP_NE,  // VM_CMP_NE = 21 → VM_JMP_NE = 103
                    VM_JMP_LT,  // VM_CMP_LT = 22 → VM_JMP_LT = 104
                    VM_JMP_LE,  // VM_CMP_LE = 23 → VM_JMP_LE = 105
                    VM_JMP_GT,  // VM_CMP_GT = 24 → VM_JMP_GT = 106
                    VM_JMP_GE,  // VM_CMP_GE = 25 → VM_JMP_GE = 107
                };
                int idx = op - VM_CMP_EQ;
                if (idx >= 0 && idx < 6) {
                    // Look ahead for JMP_IF_TRUE/FALSE consuming this result
                    if (i + 1 < prog->count) {
                        VmInstr *next = &prog->instrs[i + 1];
                        if (next->op == VM_JMP_IF_TRUE || next->op == VM_JMP_IF_FALSE_OBF) {
                            // Merge CMP + JMP into obfuscated conditional jump
                            inst->op = cmp_to_jmp[idx];
                            inst->imm = next->imm;  // Use JMP target from next instr
                            // Also preserve the rs2 as comparison source
                            inst->rs2 = next->rd;   // The condition register to test
                            // Remove the next instruction by marking it NOP
                            next->op = VM_NOP;
                            next->rd = 0;
                            next->rs1 = 0;
                            next->rs2 = 0;
                            next->imm = 0;
                        }
                    }
                }
            }
        }
    }

    // Compact: remove NOPs inserted by merge
    if (strength >= 2) {
        std::vector<VmInstr> compact;
        compact.reserve(prog->count);
        for (int i = 0; i < prog->count; i++) {
            if (prog->instrs[i].op != VM_NOP) {
                compact.push_back(prog->instrs[i]);
            }
        }
        VmInstr *nd = (VmInstr *)realloc(prog->instrs, compact.size() * sizeof(VmInstr));
        if (nd || compact.size() == 0) {
            if (nd) prog->instrs = nd;
            memcpy(prog->instrs, compact.data(), compact.size() * sizeof(VmInstr));
            prog->count = (int)compact.size();
        }
    }

    return EXIT_OK;
}
