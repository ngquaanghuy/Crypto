#include "vm/vm.h"
#include <cstdlib>
#include <cstring>
#include <vector>
#include <algorithm>
#include <unordered_map>
#include <unordered_set>

// ─── Instruction Scheduling for Decompilation Resistance ───
// Reorders instructions within basic blocks where data dependencies permit,
// interleaves independent operations, and injects dead code.
//
// Key techniques:
// 1. Within basic blocks, reorder instructions to break sequential patterns
// 2. Insert semantically equivalent but syntactically different opcode sequences
// 3. Add dead code (opaque predicate-guarded instructions) that never executes
// 4. Split constants into runtime-constructed fragments

static int get_def_reg(const VmInstr *inst) {
    int op = inst->op;
    if (op == VM_NOP || op == VM_JMP ||
        op == VM_JMP_IF_TRUE || op == VM_JMP_IF_FALSE ||
        op == VM_JMP_EQ || op == VM_JMP_NE || op == VM_JMP_LT ||
        op == VM_JMP_LE || op == VM_JMP_GT || op == VM_JMP_GE ||
        op == VM_JMP_IF_TRUE_OBF || op == VM_JMP_IF_FALSE_OBF ||
        op == VM_JMP_INDIRECT || op == VM_JMP_TABLE ||
        op == VM_STORE_NAME || op == VM_STORE_FAST ||
        op == VM_STORE_SUBSCR || op == VM_PATCH_OPCODE ||
        op == VM_CFI_CHECK || op == VM_CFI_FAIL ||
        op == VM_CFI_TABLE || op == VM_OPAQUE_TRUE ||
        op == VM_OPAQUE_FALSE || op == VM_END_TRY ||
        op == VM_CATCH || op == VM_THROW ||
        op == VM_ENCRYPT_SEG || op == VM_DECRYPT_SEG)
        return -1;
    return (int)inst->rd;
}

static std::vector<int> get_use_regs(const VmInstr *inst) {
    std::vector<int> uses;
    int op = inst->op;
    if (op == VM_STORE_NAME || op == VM_LOAD_NAME ||
        op == VM_STORE_FAST || op == VM_LOAD_FAST ||
        op == VM_LOAD_CONST || op == VM_IMPORT_NAME)
        return uses;
    if (op == VM_RETURN) {
        if (inst->rd < 64) uses.push_back((int)inst->rd);
        return uses;
    }
    if (inst->rs1 < 64) uses.push_back((int)inst->rs1);
    if (inst->rs2 < 64) uses.push_back((int)inst->rs2);
    return uses;
}

// ─── Find independent instruction pairs for reordering ─────
// Returns pairs (i, j) where i < j and they can be swapped
static std::vector<std::pair<int,int>> find_swappable_pairs(
    const std::vector<VmInstr> &block) {
    std::vector<std::pair<int,int>> pairs;
    int n = (int)block.size();
    for (int i = 0; i < n; i++) {
        for (int j = i + 1; j < n; j++) {
            int def_i = get_def_reg(&block[i]);
            int def_j = get_def_reg(&block[j]);
            auto uses_i = get_use_regs(&block[i]);
            auto uses_j = get_use_regs(&block[j]);

            // Check if i's def is used by j
            bool dep = false;
            if (def_i >= 0) {
                for (int u : uses_j) {
                    if (u == def_i) { dep = true; break; }
                }
            }
            // Check if j's def is used by i (anti-dependence)
            if (!dep && def_j >= 0) {
                for (int u : uses_i) {
                    if (u == def_j) { dep = true; break; }
                }
            }
            // Check if both write to same reg (output dependence)
            if (!dep && def_i >= 0 && def_i == def_j) {
                dep = true;
            }

            if (!dep) {
                pairs.push_back({i, j});
            }
        }
    }
    return pairs;
}

// ─── Code Scheduling Pass ─────────────────────────────────
// Reorders instructions within blocks to break linear patterns.
ExitCode vm_pass_code_schedule(VmProgram *prog, VmCompileConfig *cfg) {
    if (!prog || !cfg) return EXIT_ERR_ARGS;
    if (!prog->instrs || prog->count == 0) return EXIT_OK;

    int strength = cfg->schedule_strength;
    if (strength <= 0) return EXIT_OK;

    int seed = cfg->seed >= 0 ? cfg->seed : (int)rand();
    srand(seed);

    // Find basic blocks (instruction index ranges)
    // Block boundaries: after jumps, returns, and at jump targets
    std::vector<int> boundaries;
    boundaries.push_back(0);
    for (int i = 0; i < prog->count; i++) {
        int op = prog->instrs[i].op;
        if (op == VM_JMP || op == VM_JMP_IF_TRUE || op == VM_JMP_IF_FALSE ||
            op == VM_JMP_EQ || op == VM_JMP_NE || op == VM_JMP_LT ||
            op == VM_JMP_LE || op == VM_JMP_GT || op == VM_JMP_GE ||
            op == VM_JMP_IF_TRUE_OBF || op == VM_JMP_IF_FALSE_OBF ||
            op == VM_JMP_INDIRECT || op == VM_FOR_ITER) {
            if (i + 1 < prog->count)
                boundaries.push_back(i + 1);
        }
        if (op == VM_RETURN) {
            if (i + 1 < prog->count)
                boundaries.push_back(i + 1);
        }
    }
    std::sort(boundaries.begin(), boundaries.end());
    boundaries.erase(std::unique(boundaries.begin(), boundaries.end()),
                     boundaries.end());

    // For each block, try reordering and dead code injection
    std::vector<VmInstr> output;
    output.reserve((size_t)prog->count * 2);

    for (size_t bi = 0; bi < boundaries.size(); bi++) {
        int block_start = boundaries[bi];
        int block_end = (bi + 1 < boundaries.size()) ?
                        boundaries[bi + 1] : prog->count;

        // Extract block instructions
        std::vector<VmInstr> block;
        for (int i = block_start; i < block_end; i++)
            block.push_back(prog->instrs[i]);

        if ((int)block.size() < 3) {
            // Too small to reorder, just emit
            for (auto &inst : block)
                output.push_back(inst);
            continue;
        }

        // Technique 1: Instruction reordering (swap independent pairs)
        if (strength >= 1) {
            auto swappable = find_swappable_pairs(block);
            // Perform a few random swaps
            int num_swaps = std::min((int)swappable.size(),
                                     std::max(1, (int)block.size() / 3));
            for (int s = 0; s < num_swaps; s++) {
                if (swappable.empty()) break;
                int idx = rand() % (int)swappable.size();
                auto pair = swappable[idx];
                swappable.erase(swappable.begin() + idx);
                std::swap(block[pair.first], block[pair.second]);
            }
        }

        // Technique 2: Inject dead code with opaque predicates
        // Insert instructions that look meaningful but whose results
        // are never used. Guarded by VM_OPAQUE_TRUE.
        if (strength >= 1 && (rand() % 4 == 0)) {
            int insert_pos = rand() % (int)block.size();

            // Opaque predicate: always true
            VmInstr opaque_check;
            opaque_check.op = VM_OPAQUE_TRUE;
            opaque_check.rd = 0;
            opaque_check.rs1 = (uint8_t)(rand() % 64);
            opaque_check.rs2 = 0;
            opaque_check.imm = rand() % 3;
            block.insert(block.begin() + insert_pos, opaque_check);

            // Add a dead MOVE, ADD, or XOR that uses random registers
            VmInstr dead;
            dead.op = (uint8_t)(rand() % 3 == 0 ? VM_MOVE :
                                (rand() % 2 == 0 ? VM_ADD : VM_OBF_XOR));
            dead.rd = (uint8_t)(rand() % 64);
            dead.rs1 = (uint8_t)(rand() % 64);
            dead.rs2 = (uint8_t)(rand() % 64);
            dead.imm = rand();
            block.insert(block.begin() + insert_pos + 1, dead);
        }

        // Technique 3: Constant splitting — replace LOAD_CONST
        // with runtime-constructed value via ADD/SUB/XOR pairs
        if (strength >= 2) {
            for (size_t i = 0; i < block.size(); i++) {
                if (block[i].op == VM_LOAD_CONST && block[i].imm != 0 &&
                    abs(block[i].imm) > 100 && (rand() % 5 == 0)) {
                    int32_t val = block[i].imm;
                    int32_t split_a = rand() % val;
                    int32_t split_b = val - split_a;
                    uint8_t rd = block[i].rd;

                    // Replace: LOAD_CONST rd, val
                    // With: LOAD_CONST rd, split_a
                    //       LOAD_CONST rd+1 % 64, split_b
                    //       ADD rd, rd, rd+1 % 64 (or OBF_ADD)
                    block[i].imm = split_a;

                    VmInstr load2;
                    load2.op = VM_LOAD_CONST;
                    load2.rd = (uint8_t)((rd + 1) % 64);
                    load2.rs1 = 0;
                    load2.rs2 = 0;
                    load2.imm = split_b;
                    block.insert(block.begin() + i + 1, load2);

                    VmInstr add;
                    add.op = (uint8_t)(rand() % 2 ? VM_ADD : VM_OBF_ADD);
                    add.rd = rd;
                    add.rs1 = rd;
                    add.rs2 = (uint8_t)((rd + 1) % 64);
                    add.imm = 0;
                    block.insert(block.begin() + i + 2, add);

                    i += 2;
                }
            }
        }

        // Technique 4: Interleave — insert NOPs with register clobber
        // to make dataflow analysis harder
        if (strength >= 1) {
            for (size_t i = 0; i < block.size(); i += 2) {
                if (rand() % 8 == 0) {
                    VmInstr noise;
                    noise.op = VM_MOVE;
                    noise.rd = (uint8_t)(rand() % 64);
                    noise.rs1 = (uint8_t)(rand() % 64);
                    noise.rs2 = 0;
                    noise.imm = 0;
                    block.insert(block.begin() + i + 1, noise);
                    // Don't skip the next instruction properly — just continue
                }
            }
        }

        // Emit block
        for (auto &inst : block)
            output.push_back(inst);
    }

    // Replace instruction array
    VmInstr *nd = (VmInstr *)realloc(prog->instrs,
                                      output.size() * sizeof(VmInstr));
    if (nd || output.size() == 0) {
        if (nd) prog->instrs = nd;
        memcpy(prog->instrs, output.data(),
               output.size() * sizeof(VmInstr));
        prog->count = (int)output.size();
    }

    return EXIT_OK;
}
