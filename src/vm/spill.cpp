#include "vm/vm.h"
#include <cstdlib>
#include <cstring>
#include <vector>
#include <algorithm>
#include <random>

// ─── Liveness Analysis ──────────────────────────────────────
// Simple backward liveness: returns set of live registers at each instruction index.
static std::vector<std::vector<bool>> compute_liveness(VmInstr *instrs, int count) {
    std::vector<std::vector<bool>> live_in(count);

    // Initialize all as false
    for (int i = 0; i < count; i++) {
        live_in[i].resize(64, false);
    }

    // Backward fixed-point liveness
    // def: rd, use: rs1, rs2
    bool changed = true;
    while (changed) {
        changed = false;
        for (int i = count - 1; i >= 0; i--) {
            VmInstr *inst = &instrs[i];
            std::vector<bool> live(64, false);

            // Start with live-out = next instruction's live-in (or empty for last)
            if (i + 1 < count) {
                for (int r = 0; r < 64; r++) {
                    if (live_in[i + 1][r]) live[r] = true;
                }
            }

            // If this instruction reads rs1 or rs2, they're live before this instr
            // Remove rd (killed by this instruction)
            if (inst->rd < 64) live[inst->rd] = false;
            if (inst->rs1 < 64) live[inst->rs1] = true;
            if (inst->rs2 < 64) live[inst->rs2] = true;

            // For control flow: JMP makes target's live-in propagate
            if (inst->op == VM_JMP || inst->op == VM_JMP_IF_TRUE ||
                inst->op == VM_JMP_IF_FALSE || inst->op == VM_JMP_IF_TRUE_OBF ||
                inst->op == VM_JMP_IF_FALSE_OBF) {
                int target = inst->imm;
                if (target >= 0 && target < count) {
                    for (int r = 0; r < 64; r++) {
                        if (live_in[target][r]) live[r] = true;
                    }
                }
            }

            // Check if changed
            for (int r = 0; r < 64; r++) {
                if (live[r] != live_in[i][r]) {
                    changed = true;
                    live_in[i][r] = live[r];
                }
            }
        }
    }

    return live_in;
}

// ─── Register Spilling Pass ─────────────────────────────────
// Inserts SPILL/RESTORE instructions at pseudo-random intervals
// to obscure data flow and increase register pressure.
ExitCode vm_pass_spill_registers(VmProgram *prog, VmCompileConfig *cfg) {
    if (!prog || !cfg) return EXIT_ERR_ARGS;
    if (!prog->instrs || prog->count == 0) return EXIT_OK;

    int pressure_threshold = cfg->spill_pressure_threshold;
    if (pressure_threshold <= 0) pressure_threshold = 12;
    int target_pressure = cfg->spill_target_pressure;
    if (target_pressure <= 0) target_pressure = 8;
    int spill_interval = cfg->spill_interval;
    if (spill_interval <= 0) spill_interval = 10;
    float spill_prob = cfg->spill_probability;
    if (spill_prob <= 0.0f) spill_prob = 0.3f;

    // Compute liveness
    auto liveness = compute_liveness(prog->instrs, prog->count);

    // Build new instruction sequence
    std::vector<VmInstr> out;
    out.reserve(prog->count * 2);

    int spill_pressure = 0;
    int seed = cfg->seed >= 0 ? cfg->seed : (int)rand();
    srand(seed);

    for (int i = 0; i < prog->count; i++) {
        int cycle = i;

        // Count live registers
        int live_count = 0;
        for (int r = 0; r < 64; r++) {
            if (liveness[i][r]) live_count++;
        }
        (void)live_count;

        // Find candidate registers to spill (live registers)
        std::vector<int> candidates;
        for (int r = 0; r < 64; r++) {
            if (liveness[i][r]) candidates.push_back(r);
        }

        // Trigger 1: Register pressure threshold
        if ((int)candidates.size() > pressure_threshold) {
            int excess = (int)candidates.size() - target_pressure;
            // Shuffle candidates and pick excess to spill
            std::shuffle(candidates.begin(), candidates.end(), std::default_random_engine(rand()));
            int spill_count = std::min(excess, (int)candidates.size());

            if (spill_count > 0) {
                // Emit SPILL_MANY
                VmInstr spill;
                spill.op = VM_SPILL_MANY;
                spill.rd = candidates[0]; // base register
                spill.rs1 = 0;
                spill.rs2 = 0;
                // Build mask for excess registers
                int mask = 0;
                for (int j = 0; j < spill_count && j < 16; j++) {
                    int reg_off = candidates[j] - candidates[0];
                    if (reg_off >= 0 && reg_off < 16) {
                        mask |= (1 << reg_off);
                    }
                }
                spill.imm = mask;
                out.push_back(spill);
                spill_pressure += spill_count;
            }
        }

        // Trigger 2: Pseudo-random interval
        if (cycle % spill_interval == 0 && !candidates.empty()) {
            float rv = (float)rand() / (float)RAND_MAX;
            if (rv < spill_prob) {
                int spill_count = std::min(1 + rand() % 3, (int)candidates.size());
                std::shuffle(candidates.begin(), candidates.end(), std::default_random_engine(rand()));

                VmInstr spill;
                spill.op = VM_SPILL_MANY;
                spill.rd = candidates[0];
                spill.rs1 = 0;
                spill.rs2 = 0;
                int mask = 0;
                for (int j = 0; j < spill_count && j < 16; j++) {
                    int reg_off = candidates[j] - candidates[0];
                    if (reg_off >= 0 && reg_off < 16) {
                        mask |= (1 << reg_off);
                    }
                }
                spill.imm = mask;
                out.push_back(spill);
                spill_pressure += spill_count;
            }
        }

        // Emit original instruction
        out.push_back(prog->instrs[i]);

        // Restore balancing: restore some spilled registers
        if (spill_pressure > 0) {
            float rv = (float)rand() / (float)RAND_MAX;
            if (rv < 0.3f) { // 30% restore chance
                int restore_count = std::min(spill_pressure, 1 + rand() % 3);
                VmInstr restore;
                restore.op = VM_RESTORE_MANY;
                restore.rd = 0;
                restore.rs1 = 0;
                restore.rs2 = 0;
                restore.imm = restore_count & 0xFF;
                out.push_back(restore);
                spill_pressure -= restore_count;
                if (spill_pressure < 0) spill_pressure = 0;
            }
        }
    }

    // Final restore of any remaining spills
    if (spill_pressure > 0) {
        VmInstr restore;
        restore.op = VM_RESTORE_MANY;
        restore.rd = 0;
        restore.rs1 = 0;
        restore.rs2 = 0;
        restore.imm = spill_pressure & 0xFF;
        out.push_back(restore);
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
