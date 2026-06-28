#include "vm/vm.h"
#include "vm/vm_program.h"
#include "vm/vm_serialize.h"
#include "vm/vm_py.h"
#include "crypto/file_util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>

// ─── Compile Python source → VmProgram (via Python subprocess) ──
static ExitCode compile_through_python(const char *source, size_t source_len,
                                       VmProgram *prog, int opaque, int seed) {
    char *tmpdir = tmpdir_create();
    if (!tmpdir) return EXIT_ERR_CRYPTO;

    char *script_path = tmpdir_path(tmpdir, "script.py");
    char *in_path     = tmpdir_path(tmpdir, "in.py");
    char *out_path    = tmpdir_path(tmpdir, "out.bin");
    if (!script_path || !in_path || !out_path) {
        free(script_path); free(in_path); free(out_path);
        tmpdir_destroy(tmpdir);
        return EXIT_ERR_CRYPTO;
    }

    /* Secure file creation with O_EXCL|O_NOFOLLOW to prevent race/symlink attacks */
    int fd_s = open(script_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    int fd_i = open(in_path,     O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    int fd_o = open(out_path,    O_RDWR   | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd_s < 0 || fd_i < 0 || fd_o < 0) {
        if (fd_s >= 0) close(fd_s);
        if (fd_i >= 0) close(fd_i);
        if (fd_o >= 0) close(fd_o);
        free(script_path); free(in_path); free(out_path);
        tmpdir_destroy(tmpdir);
        return EXIT_ERR_CRYPTO;
    }

    {
    size_t slen = strlen(VM_COMPILE_SCRIPT);
    if (write(fd_s, VM_COMPILE_SCRIPT, slen) != (ssize_t)slen ||
        write(fd_i, source, source_len) != (ssize_t)source_len) {
        close(fd_s); close(fd_i); close(fd_o);
        free(script_path); free(in_path); free(out_path);
        tmpdir_destroy(tmpdir);
        return EXIT_ERR_FILE;
    }
    }

    close(fd_s); close(fd_i); fd_s = fd_i = -1;

    pid_t pid = fork();
    if (pid == -1) {
        close(fd_o); free(script_path); free(in_path); free(out_path);
        tmpdir_destroy(tmpdir);
        return EXIT_ERR_CRYPTO;
    }
    if (pid == 0) {
        int fd_in = open(in_path, O_RDONLY);
        if (fd_in >= 0) { dup2(fd_in, STDIN_FILENO); close(fd_in); }
        /* Output file was already created by parent with O_EXCL, so child just reopens
         * Use O_NOFOLLOW|O_TRUNC to prevent symlink attacks and truncate existing content */
        int fd_out = open(out_path, O_WRONLY | O_NOFOLLOW | O_TRUNC, 0644);
        if (fd_out >= 0) { dup2(fd_out, STDOUT_FILENO); close(fd_out); }
        const char *argv[16];
        int ai = 0;
        argv[ai++] = "python3";
        argv[ai++] = script_path;
        char seed_arg[16] = {0};
        if (seed >= 0) {
            argv[ai++] = "--seed";
            snprintf(seed_arg, sizeof(seed_arg), "%d", seed);
            argv[ai++] = seed_arg;
        }
        if (opaque) argv[ai++] = "--opaque";
        argv[ai] = NULL;
        execvp("python3", (char *const *)argv);
        _exit(127);
    }
    int status;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        close(fd_o); free(script_path); free(in_path); free(out_path);
        tmpdir_destroy(tmpdir);
        return EXIT_ERR_CRYPTO;
    }

    off_t fsz = lseek(fd_o, 0, SEEK_END);
    if (fsz <= 0) {
        close(fd_o); free(script_path); free(in_path); free(out_path);
        tmpdir_destroy(tmpdir);
        return EXIT_ERR_CRYPTO;
    }
    lseek(fd_o, 0, SEEK_SET);

    unsigned char *buf = (unsigned char *)malloc((size_t)fsz);
    if (!buf) {
        close(fd_o); free(script_path); free(in_path); free(out_path);
        tmpdir_destroy(tmpdir);
        return EXIT_ERR_CRYPTO;
    }

    ssize_t nr = read(fd_o, buf, (size_t)fsz);
    close(fd_o);

    if (nr != fsz) {
        free(buf); free(script_path); free(in_path); free(out_path);
        tmpdir_destroy(tmpdir);
        return EXIT_ERR_FILE;
    }

    // Prepend dummy opcode_map (256 bytes) + zero flags (4 bytes) before deserializing.
    // Magic=0 means vm_deserialize uses the legacy sequential path:
    //   [0:256]=opmap, [256:260]=flags, [260:...]=consts
    size_t header_pad = 256 + 4;
    unsigned char *full_buf = (unsigned char *)malloc((size_t)nr + header_pad);
    if (!full_buf) {
        free(buf); free(script_path); free(in_path); free(out_path);
        tmpdir_destroy(tmpdir);
        return EXIT_ERR_CRYPTO;
    }
    memset(full_buf, 0, header_pad);
    memcpy(full_buf + header_pad, buf, (size_t)nr);
    free(buf);

    ExitCode ret = vm_deserialize(full_buf, (size_t)nr + header_pad, prog);
    free(full_buf);
    free(script_path); free(in_path); free(out_path);
    tmpdir_destroy(tmpdir);
    return ret;
}

// ─── Apply opcode obfuscation (shuffle) ─────────────────────
static ExitCode apply_opcode_shuffle(VmProgram *prog) {
    if (!prog || !prog->instrs || prog->count == 0) return EXIT_OK;

    uint8_t forward_map[256];
    for (int i = 0; i < 256; i++) forward_map[i] = (uint8_t)i;
    for (int i = 255; i > 0; i--) {
        int j = rand() % (i + 1);
        uint8_t tmp = forward_map[i];
        forward_map[i] = forward_map[j];
        forward_map[j] = tmp;
    }

    for (int i = 0; i < prog->count; i++) {
        prog->instrs[i].op = forward_map[prog->instrs[i].op];
    }

    prog->opcode_map = (uint8_t *)malloc(256);
    if (!prog->opcode_map) return EXIT_ERR_CRYPTO;
    for (int i = 0; i < 256; i++) {
        prog->opcode_map[forward_map[i]] = (uint8_t)i;
    }

    // Also shuffle bytecode if variable-length encoded
    if (prog->vl_code && prog->vl_code_len > 0) {
        // VL code already has opcodes embedded - we handle this
        // by re-encoding after shuffle (done in vm_compile_source_ex)
    }

    return EXIT_OK;
}

// ─── Legacy compile (backward compatible) ───────────────────
ExitCode vm_compile_source(const char *source, size_t source_len,
                            VmProgram *prog, int opaque, int seed) {
    VmCompileConfig cfg;
    vm_default_config(&cfg);
    cfg.enable_opaque = opaque;
    cfg.seed = seed;
    cfg.enable_var_length_encoding = 0;
    cfg.enable_register_spilling = 0;
    cfg.enable_self_modifying_code = 0;
    cfg.enable_conditional_obfuscation = 0;
    return vm_compile_source_ex(source, source_len, prog, &cfg);
}

// ─── Extended compile with full pipeline ────────────────────
ExitCode vm_compile_source_ex(const char *source, size_t source_len,
                               VmProgram *prog, VmCompileConfig *cfg) {
    if (!source || !prog) return EXIT_ERR_ARGS;

    VmCompileConfig local_cfg;
    if (!cfg) {
        vm_default_config(&local_cfg);
        cfg = &local_cfg;
    }

    vm_program_init(prog);

    // Random constant encryption key - stored in blob, protected by VM blob encryption
    for (int i = 0; i < VM_CONST_KEY_SIZE; i++)
        prog->const_key[i] = (uint8_t)(rand() & 0xFF);
    prog->poly_seed = (cfg->seed >= 0) ? cfg->seed : (int)rand();

    // Step 1: Basic compilation via Python
    ExitCode ret = compile_through_python(source, source_len, prog,
                                          cfg->enable_opaque, cfg->seed);
    if (ret != EXIT_OK) return ret;

    // Step 2: ISA Expansion
    if (cfg->enable_indirect_calls || cfg->enable_virtual_calls || cfg->enable_exceptions) {
        ret = vm_pass_isa_expand(prog, cfg);
        if (ret != EXIT_OK) return ret;
    }

    // Step 3: Code Scheduling (Decompilation Resistance)
    if (cfg->enable_code_scheduling) {
        ret = vm_pass_code_schedule(prog, cfg);
        if (ret != EXIT_OK) return ret;
    }

    // Step 4: Conditional Branch Obfuscation
    if (cfg->enable_conditional_obfuscation && cfg->cond_obfuscation_strength > 0) {
        ret = vm_pass_obfuscate_conditions(prog, cfg->cond_obfuscation_strength);
        if (ret != EXIT_OK) return ret;
    }

    // Step 5: Register Spilling
    if (cfg->enable_register_spilling) {
        ret = vm_pass_spill_registers(prog, cfg);
        if (ret != EXIT_OK) return ret;
    }

    // Step 6: Self-Modifying Code Injection
    if (cfg->enable_self_modifying_code) {
        ret = vm_pass_inject_self_modifying(prog, cfg);
        if (ret != EXIT_OK) return ret;
    }

    // Step 7: Virtual RAM Garble Injection (re-keys vRAM periodically)
    if (cfg->enable_vram && cfg->enable_vram_garble) {
        ret = vm_pass_inject_vram_garble(prog, cfg);
        if (ret != EXIT_OK) return ret;
    }

    // Step 8: Apply opcode shuffle BEFORE encoding
    ret = apply_opcode_shuffle(prog);
    if (ret != EXIT_OK) return ret;

    // Step 9: Variable-Length or Polymorphic Encoding
    bool do_poly = cfg->enable_polymorphic_encoding;
    bool do_vl = cfg->enable_var_length_encoding || do_poly;

    if (do_vl) {
        Buffer vl_buf = {0};
        if (do_poly) {
            ret = vm_encode_program_poly(prog, &vl_buf);
            prog->flags |= VM_SER_FLAG_POLY_ENCODING;
        } else {
            ret = vm_encode_program(prog, &vl_buf);
            prog->flags |= VM_SER_FLAG_VL_ENCODED;
        }
        if (ret != EXIT_OK) return ret;

        prog->vl_code = vl_buf.data;
        prog->vl_code_len = (int)vl_buf.size;
    }

    // Step 10: Virtual RAM flag + size — embed in serialized flags for runtime detection
    if (cfg->enable_vram) {
        prog->flags |= VM_SER_FLAG_VRAM_ENABLED;
        int vram_units = cfg->vram_size / VM_SER_FLAG_VRAM_SIZE_UNIT;
        if (vram_units < 0) vram_units = 0;
        if (vram_units > VM_SER_FLAG_VRAM_SIZE_MASK) vram_units = VM_SER_FLAG_VRAM_SIZE_MASK;
        prog->flags |= (vram_units & VM_SER_FLAG_VRAM_SIZE_MASK) << VM_SER_FLAG_VRAM_SIZE_SHIFT;
    }

    // Step 11: Constant Pool Encryption (must happen after encoding, before serialization)
    if (cfg->enable_constant_encryption) {
        prog->flags |= VM_SER_FLAG_CONST_ENCRYPTED;
    }

    // Step 11: Control Flow Integrity pass (operates on encoded bytecode)
    if (cfg->enable_cfi) {
        ret = vm_pass_cfi(prog, cfg);
        if (ret != EXIT_OK) return ret;
    }

    return EXIT_OK;
}
