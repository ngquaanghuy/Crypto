#include "vm/vm.h"
#include <cstdlib>
#include <cstring>
#include <vector>

// ─── Helper: build instruction array ────────────────────────
struct InstrArray {
    VmInstr *data;
    int      count;
    int      capacity;

    InstrArray() : data(nullptr), count(0), capacity(0) {}
    ~InstrArray() { free(data); }

    void push(const VmInstr &inst) {
        if (count >= capacity) {
            int new_cap = capacity ? capacity * 2 : 128;
            VmInstr *nd = (VmInstr *)realloc(data, new_cap * sizeof(VmInstr));
            if (!nd) return;
            data = nd;
            capacity = new_cap;
        }
        data[count++] = inst;
    }
};

// ─── ISA Expansion Pass ─────────────────────────────────────
// Transforms CALL patterns into CALL_INDIRECT / CALL_VTABLE.
// Also inserts obfuscation-only exception handling frames.
ExitCode vm_pass_isa_expand(VmProgram *prog, VmCompileConfig *cfg) {
    if (!prog || !cfg) return EXIT_ERR_ARGS;
    if (!prog->instrs || prog->count == 0) return EXIT_OK;

    InstrArray out;

    // Track last LOAD_ATTR target register for CALL conversion
    int last_attr_reg = -1;
    int last_attr_name_idx = -1;

    for (int i = 0; i < prog->count; i++) {
        VmInstr inst = prog->instrs[i];

        // Track LOAD_ATTR → register mapping for CALL detection
        if (inst.op == VM_LOAD_ATTR) {
            last_attr_reg = inst.rd;
            last_attr_name_idx = inst.imm;
        }

        // Convert CALL to CALL_INDIRECT when function register was
        // loaded by LOAD_ATTR (method call pattern)
        if (inst.op == VM_CALL && cfg->enable_indirect_calls) {
            if (inst.rs1 == last_attr_reg && last_attr_reg >= 0) {
                // This is a method call: obj.method(args)
                // Convert to CALL_INDIRECT
                inst.op = VM_CALL_INDIRECT;
                last_attr_reg = -1;
                last_attr_name_idx = -1;
            }
        }

        // Insert synthetic exception handling frames
        if (cfg->enable_exceptions && (inst.op == VM_CALL || inst.op == VM_CALL_INDIRECT)) {
            if (rand() % 3 == 0) { // 33% chance
                VmInstr try_inst;
                try_inst.op = VM_TRY;
                try_inst.rd = 0;
                try_inst.rs1 = 0;
                try_inst.rs2 = 0;
                try_inst.imm = 3 + rand() % 5; // span a few instructions
                out.push(try_inst);

                out.push(inst);

                VmInstr end_inst;
                end_inst.op = VM_END_TRY;
                end_inst.rd = 0;
                end_inst.rs1 = 0;
                end_inst.rs2 = 0;
                end_inst.imm = 0;
                out.push(end_inst);
                continue;
            }
        }

        // Convert CALL to CALL_VTABLE when followed by certain patterns
        if (inst.op == VM_CALL && cfg->enable_virtual_calls) {
            // Heuristic: if function register was loaded via LOAD_ATTR
            // in the last 3 instructions, convert to CALL_VTABLE
            if (last_attr_reg >= 0 && inst.rs1 == last_attr_reg) {
                // Insert vtable load before call
                VmInstr vt_load;
                vt_load.op = VM_LOAD_ATTR;
                vt_load.rd = inst.rs1 + 1; // vtable in next reg
                vt_load.rs1 = last_attr_reg;
                vt_load.rs2 = 0;
                vt_load.imm = last_attr_name_idx;
                out.push(vt_load);

                inst.op = VM_CALL_VTABLE;
                // imm low 16 = method index, high 16 = arg count
                int argc = inst.imm & 0xFFFF;
                inst.imm = (last_attr_name_idx & 0xFFFF) | ((argc & 0xFFFF) << 16);
                last_attr_reg = -1;
            }
        }

        out.push(inst);
    }

    // Replace prog instruction array
    free(prog->instrs);
    prog->instrs = out.data;
    prog->count = out.count;
    out.data = nullptr; // prevent double free
    out.count = 0;

    return EXIT_OK;
}
