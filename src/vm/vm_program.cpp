#include "vm/vm.h"
#include "vm/vm_program.h"
#include <stdlib.h>
#include <string.h>

// ─── VmProgram lifecycle ─────────────────────────────────────

ExitCode vm_program_init(VmProgram *prog) {
    memset(prog, 0, sizeof(*prog));
    return EXIT_OK;
}

void vm_program_free(VmProgram *prog) {
    free(prog->instrs);
    free(prog->opcode_map);
    free(prog->vl_code);
    if (prog->const_types) free(prog->const_types);
    if (prog->const_strs) {
        for (int i = 0; i < prog->const_count; i++)
            free(prog->const_strs[i]);
        free(prog->const_strs);
    }
    if (prog->names) {
        for (int i = 0; i < prog->name_count; i++)
            free(prog->names[i]);
        free(prog->names);
    }
    free(prog->cfi_checksums);
    free(prog->cfi_block_starts);
    free(prog->cfi_block_lengths);
    memset(prog, 0, sizeof(*prog));
}

// ─── Default compile config ─────────────────────────────────

void vm_default_config(VmCompileConfig *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->enable_opaque = 1;
    cfg->seed = -1;
    cfg->enable_var_length_encoding = 1;
    cfg->enable_register_spilling = 1;
    cfg->enable_self_modifying_code = 1;
    cfg->enable_conditional_obfuscation = 1;
    cfg->spill_pressure_threshold = 12;
    cfg->spill_target_pressure = 8;
    cfg->spill_interval = 10;
    cfg->spill_probability = 0.3f;
    cfg->smc_min_interval = 20;
    cfg->smc_max_interval = 50;
    cfg->cond_obfuscation_strength = 1;
    cfg->enable_indirect_calls = 1;
    cfg->enable_virtual_calls = 0;
    cfg->enable_exceptions = 0;
    cfg->enable_polymorphic_encoding = 0;
    cfg->enable_constant_encryption = 0;
    cfg->enable_cfi = 0;
    cfg->enable_code_scheduling = 0;
    cfg->cfi_check_interval = 20;
    cfg->schedule_strength = 1;
    cfg->enable_vram = 0;
    cfg->vram_size = VM_RAM_SIZE;
    cfg->enable_vram_garble = 0;
    cfg->vram_garble_min_interval = 80;
    cfg->vram_garble_max_interval = 200;
}
