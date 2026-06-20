#include "vm/vm.h"
#include "vm/vm_py.h"
#include "crypto/file_util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <vector>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>


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

    int fd_s = open(script_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    int fd_i = open(in_path,     O_WRONLY | O_CREAT | O_TRUNC, 0600);
    int fd_o = open(out_path,    O_RDWR   | O_CREAT | O_TRUNC, 0600);
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
        int fd_out = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
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

    // Generate random constant encryption key
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

// ─── Serialize (with VM header, constant encryption & CFI table) ───
ExitCode vm_serialize(const VmProgram *prog, Buffer *out) {
    if (!prog || !out) return EXIT_ERR_ARGS;

    int flags = prog->flags | VM_SER_FLAG_HAS_HEADER;
    bool encrypt_consts = (flags & VM_SER_FLAG_CONST_ENCRYPTED) != 0;
    bool has_cfi = (flags & VM_SER_FLAG_CFI_ENABLED) != 0;

    const size_t hdr_sz = VM_HEADER_SIZE;
    size_t map_size = 256;
    size_t flags_dup_size = 4;  // duplicate flags after opmap for legacy fallback
    size_t const_key_size = encrypt_consts ? VM_CONST_KEY_SIZE : 0;
    size_t cfi_table_size = has_cfi ? (size_t)(4 + prog->cfi_num_blocks * 12) : 0;

    size_t consts_size = 4;
    for (int i = 0; i < prog->const_count; i++) {
        consts_size += 1 + 4;
        if (prog->const_strs[i])
            consts_size += strlen(prog->const_strs[i]);
    }

    size_t names_size = 4;
    for (int i = 0; i < prog->name_count; i++) {
        names_size += 2;
        if (prog->names[i])
            names_size += strlen(prog->names[i]);
    }

    size_t code_section_size;
    bool is_vl = (flags & (VM_SER_FLAG_VL_ENCODED | VM_SER_FLAG_POLY_ENCODING)) != 0 && prog->vl_code;

    if (is_vl) {
        code_section_size = 4 + (size_t)prog->vl_code_len;
    } else {
        code_section_size = 4 + (size_t)prog->count * VM_INSTR_SIZE;
    }

    size_t total = hdr_sz + map_size + flags_dup_size + const_key_size
                  + cfi_table_size + consts_size + names_size + code_section_size;
    out->data = (unsigned char *)malloc(total);
    if (!out->data) return EXIT_ERR_CRYPTO;

    // ─── Compute section offsets ───
    size_t off_opmap = hdr_sz;
    size_t off_flags = off_opmap + 256;
    size_t off_const_key = off_flags + 4;
    size_t off_cfi = off_const_key + const_key_size;
    size_t off_consts = off_cfi + cfi_table_size;
    size_t off_names = off_consts + consts_size;
    size_t off_code = off_names + names_size;

    // ─── Write VM header (32 bytes) ───
    VmHeader hdr;
    hdr.magic   = VM_HEADER_MAGIC;
    hdr.flags   = (uint32_t)flags;
    hdr.entry_point = 0;  // always start at 0 for now
    hdr.const_offset  = (uint32_t)off_consts;
    hdr.names_offset  = (uint32_t)off_names;
    hdr.code_offset   = (uint32_t)off_code;
    hdr.opmap_offset  = (uint32_t)off_opmap;
    hdr.total_size    = (uint32_t)total;
    memcpy(out->data, &hdr, hdr_sz);

    size_t pos = off_opmap;

    // Opcode map (256 bytes)
    if (prog->opcode_map) {
        memcpy(out->data + pos, prog->opcode_map, 256);
    } else {
        memset(out->data + pos, 0, 256);
    }
    pos += 256;

    // Flags (4 bytes) — duplicate after opmap for legacy fallback
    uint32_t flags_val = (uint32_t)flags;
    memcpy(out->data + pos, &flags_val, 4);
    pos += 4;

    // Constant encryption key (if enabled)
    if (encrypt_consts) {
        memcpy(out->data + pos, prog->const_key, VM_CONST_KEY_SIZE);
        pos += VM_CONST_KEY_SIZE;
    }

    // CFI checksum table (if enabled)
    if (has_cfi) {
        uint32_t nb = (uint32_t)prog->cfi_num_blocks;
        memcpy(out->data + pos, &nb, 4); pos += 4;
        for (int i = 0; i < prog->cfi_num_blocks; i++) {
            uint32_t start = (uint32_t)prog->cfi_block_starts[i];
            uint32_t len = (uint32_t)prog->cfi_block_lengths[i];
            uint32_t csum = prog->cfi_checksums[i];
            memcpy(out->data + pos, &start, 4); pos += 4;
            memcpy(out->data + pos, &len, 4); pos += 4;
            memcpy(out->data + pos, &csum, 4); pos += 4;
        }
    }

    // Const count + data (XOR-encrypt string constants if enabled)
    pos = off_consts;
    uint32_t cc = (uint32_t)prog->const_count;
    memcpy(out->data + pos, &cc, 4); pos += 4;
    for (int i = 0; i < prog->const_count; i++) {
        out->data[pos++] = prog->const_types[i];
        size_t sl = prog->const_strs[i] ? strlen(prog->const_strs[i]) : 0;
        uint32_t sl32 = (uint32_t)sl;
        memcpy(out->data + pos, &sl32, 4); pos += 4;
        if (sl > 0) {
            if (encrypt_consts && prog->const_types[i] == 4) {
                for (size_t j = 0; j < sl; j++) {
                    out->data[pos + j] = (uint8_t)(prog->const_strs[i][j] ^
                                                    prog->const_key[j % VM_CONST_KEY_SIZE]);
                }
            } else {
                memcpy(out->data + pos, prog->const_strs[i], sl);
            }
            pos += sl;
        }
    }

    // Name count + data (plaintext, not encrypted)
    pos = off_names;
    uint32_t nc = (uint32_t)prog->name_count;
    memcpy(out->data + pos, &nc, 4); pos += 4;
    for (int i = 0; i < prog->name_count; i++) {
        size_t sl = prog->names[i] ? strlen(prog->names[i]) : 0;
        uint16_t sl16 = (uint16_t)sl;
        memcpy(out->data + pos, &sl16, 2); pos += 2;
        if (sl > 0) {
            memcpy(out->data + pos, prog->names[i], sl); pos += sl;
        }
    }

    // Code section
    pos = off_code;
    if (is_vl) {
        uint32_t code_sz = (uint32_t)prog->vl_code_len;
        memcpy(out->data + pos, &code_sz, 4); pos += 4;
        memcpy(out->data + pos, prog->vl_code, code_sz);
        pos += code_sz;
    } else {
        uint32_t ic = (uint32_t)prog->count;
        memcpy(out->data + pos, &ic, 4); pos += 4;
        memcpy(out->data + pos, prog->instrs, (size_t)prog->count * VM_INSTR_SIZE);
        pos += (size_t)prog->count * VM_INSTR_SIZE;
    }

    out->size = pos;
    return EXIT_OK;
}

// ─── Deserialize (with VM header, constant decryption & CFI table) ──
ExitCode vm_deserialize(const unsigned char *data, size_t size,
                         VmProgram *prog) {
    vm_program_init(prog);

    size_t pos = 0;

    // ─── Detect format: check for VM header magic ───
    bool has_header = false;
    size_t off_opmap, off_const_key, off_cfi, off_consts, off_names, off_code;
    size_t off_flags;
    uint32_t hdr_flags = 0;
    bool encrypt_consts = false, has_cfi = false, is_vl = false;
    uint8_t const_key[VM_CONST_KEY_SIZE] = {0};

    if (size >= VM_HEADER_SIZE) {
        uint32_t magic;
        memcpy(&magic, data, 4);
        if (magic == VM_HEADER_MAGIC) {
            has_header = true;
            // Parse header
            VmHeader hdr;
            memcpy(&hdr, data, VM_HEADER_SIZE);
            hdr_flags = hdr.flags;
            prog->flags = (int)hdr_flags;
            off_opmap  = hdr.opmap_offset;
            off_consts = hdr.const_offset;
            off_names  = hdr.names_offset;
            off_code   = hdr.code_offset;
            off_flags  = off_opmap + 256;  // flags follow opmap
            off_const_key = off_flags + 4;

            is_vl = (hdr_flags & (VM_SER_FLAG_VL_ENCODED | VM_SER_FLAG_POLY_ENCODING)) != 0;
            encrypt_consts = (hdr_flags & VM_SER_FLAG_CONST_ENCRYPTED) != 0;
            has_cfi = (hdr_flags & VM_SER_FLAG_CFI_ENABLED) != 0;
            off_cfi = off_const_key + (encrypt_consts ? VM_CONST_KEY_SIZE : 0);
        }
    }

    if (!has_header) {
        // Legacy format — sequential: opcode_map(256) + flags(4) + ...
        off_opmap = 0;
        off_flags = 256;
        off_const_key = off_flags + 4;

        // Copy raw first 4 bytes to tentatively read flags
        if (size >= 260) {
            uint32_t fv;
            memcpy(&fv, data + 256, 4);
            hdr_flags = fv;
            prog->flags = (int)fv;
        }
        is_vl = (hdr_flags & (VM_SER_FLAG_VL_ENCODED | VM_SER_FLAG_POLY_ENCODING)) != 0;
        encrypt_consts = (hdr_flags & VM_SER_FLAG_CONST_ENCRYPTED) != 0;
        has_cfi = (hdr_flags & VM_SER_FLAG_CFI_ENABLED) != 0;
        off_cfi = off_const_key + (encrypt_consts ? VM_CONST_KEY_SIZE : 0);
        off_consts = off_cfi + (has_cfi ? (4 + 12) : 0);  // approximate
        off_names = 0;  // computed below
        off_code = 0;
    }

    // ─── Opcode map ───
    if (off_opmap + 256 > size) return EXIT_ERR_CRYPTO;
    prog->opcode_map = (uint8_t *)malloc(256);
    if (!prog->opcode_map) return EXIT_ERR_CRYPTO;
    memcpy(prog->opcode_map, data + off_opmap, 256);

    // Flags already read from header

    // Constant encryption key (if present)
    if (encrypt_consts) {
        if (off_const_key + VM_CONST_KEY_SIZE > size) return EXIT_ERR_CRYPTO;
        memcpy(const_key, data + off_const_key, VM_CONST_KEY_SIZE);
        memcpy(prog->const_key, const_key, VM_CONST_KEY_SIZE);
    }

    // CFI table (if present)
    if (has_cfi) {
        if (off_cfi + 4 > size) return EXIT_ERR_CRYPTO;
        uint32_t nb;
        memcpy(&nb, data + off_cfi, 4);
        size_t cfi_pos = off_cfi + 4;
        prog->cfi_num_blocks = (int)nb;
        if (nb > 0 && nb <= VM_CFI_MAX_BLOCKS) {
            prog->cfi_checksums = (uint32_t *)calloc(nb, sizeof(uint32_t));
            prog->cfi_block_starts = (int *)calloc(nb, sizeof(int));
            prog->cfi_block_lengths = (int *)calloc(nb, sizeof(int));
            if (!prog->cfi_checksums || !prog->cfi_block_starts || !prog->cfi_block_lengths)
                return EXIT_ERR_CRYPTO;
            for (uint32_t i = 0; i < nb; i++) {
                if (cfi_pos + 12 > size) return EXIT_ERR_CRYPTO;
                uint32_t s, l, c;
                memcpy(&s, data + cfi_pos, 4); cfi_pos += 4;
                memcpy(&l, data + cfi_pos, 4); cfi_pos += 4;
                memcpy(&c, data + cfi_pos, 4); cfi_pos += 4;
                prog->cfi_block_starts[i] = (int)s;
                prog->cfi_block_lengths[i] = (int)l;
                prog->cfi_checksums[i] = c;
            }
        }
        if (!has_header) {
            // Legacy: CFI table ends where consts begin
            off_consts = cfi_pos;
        }
    } else if (!has_header) {
        // Legacy, no CFI: consts start right after const_key area
        size_t ck_end = off_const_key + (encrypt_consts ? VM_CONST_KEY_SIZE : 0);
        off_consts = ck_end;
    }

    // If no header offsets, compute them as running sequential scan (legacy)
    if (!has_header) {
        // Scan consts to find names offset, then names to find code offset
        // But we need to know all sizes first. Use the known sequential layout.
        // We already have off_consts. Read consts, then compute names/code offsets.
    }

    // ─── Constants ───
    pos = off_consts;
    if (pos + 4 > size) return EXIT_ERR_CRYPTO;
    uint32_t cc;
    memcpy(&cc, data + pos, 4); pos += 4;
    prog->const_count = (int)cc;
    if (cc > 0) {
        prog->const_types = (uint8_t *)malloc(cc);
        prog->const_strs = (char **)calloc(cc, sizeof(char *));
        if (!prog->const_types || !prog->const_strs)
            return EXIT_ERR_CRYPTO;
        for (uint32_t i = 0; i < cc; i++) {
            if (pos + 1 > size) return EXIT_ERR_CRYPTO;
            prog->const_types[i] = data[pos++];
            if (pos + 4 > size) return EXIT_ERR_CRYPTO;
            uint32_t sl;
            memcpy(&sl, data + pos, 4); pos += 4;
            if (pos + sl > size) return EXIT_ERR_CRYPTO;
            if (sl > 0) {
                prog->const_strs[i] = (char *)malloc(sl + 1);
                if (!prog->const_strs[i]) return EXIT_ERR_CRYPTO;
                if (encrypt_consts && prog->const_types[i] == 4) {
                    for (uint32_t j = 0; j < sl; j++) {
                        prog->const_strs[i][j] = (char)(data[pos + j] ^
                                                        const_key[j % VM_CONST_KEY_SIZE]);
                    }
                } else {
                    memcpy(prog->const_strs[i], data + pos, sl);
                }
                prog->const_strs[i][sl] = '\0';
                pos += sl;
            }
        }
    }

    // ─── Names ───
    if (!has_header) {
        // Legacy: names follow consts sequentially
        off_names = pos;
    }
    pos = off_names;
    if (pos + 4 > size) return EXIT_ERR_CRYPTO;
    uint32_t nc;
    memcpy(&nc, data + pos, 4); pos += 4;
    prog->name_count = (int)nc;
    if (nc > 0) {
        prog->names = (char **)calloc(nc, sizeof(char *));
        if (!prog->names) return EXIT_ERR_CRYPTO;
        for (uint32_t i = 0; i < nc; i++) {
            if (pos + 2 > size) return EXIT_ERR_CRYPTO;
            uint16_t sl;
            memcpy(&sl, data + pos, 2); pos += 2;
            if (pos + sl > size) return EXIT_ERR_CRYPTO;
            if (sl > 0) {
                prog->names[i] = (char *)malloc(sl + 1);
                if (!prog->names[i]) return EXIT_ERR_CRYPTO;
                memcpy(prog->names[i], data + pos, sl);
                prog->names[i][sl] = '\0';
                pos += sl;
            }
        }
    }

    // ─── Code section ───
    if (!has_header) {
        // Legacy: code follows names sequentially
        off_code = pos;
    }
    pos = off_code;
    if (is_vl) {
        if (pos + 4 > size) return EXIT_ERR_CRYPTO;
        uint32_t code_sz;
        memcpy(&code_sz, data + pos, 4); pos += 4;
        if (pos + code_sz > size) return EXIT_ERR_CRYPTO;
        prog->vl_code = (uint8_t *)malloc(code_sz);
        if (!prog->vl_code && code_sz > 0) return EXIT_ERR_CRYPTO;
        memcpy(prog->vl_code, data + pos, code_sz);
        prog->vl_code_len = (int)code_sz;
        pos += code_sz;
        prog->count = 0;
        prog->instrs = NULL;
    } else {
        if (pos + 4 > size) return EXIT_ERR_CRYPTO;
        uint32_t ic;
        memcpy(&ic, data + pos, 4); pos += 4;
        prog->count = (int)ic;
        if (ic > 0) {
            size_t instr_bytes = (size_t)ic * VM_INSTR_SIZE;
            if (pos + instr_bytes > size) return EXIT_ERR_CRYPTO;
            prog->instrs = (VmInstr *)malloc(instr_bytes);
            if (!prog->instrs) return EXIT_ERR_CRYPTO;
            memcpy(prog->instrs, data + pos, instr_bytes);
            pos += instr_bytes;
        }
    }

    return EXIT_OK;
}

// ─── Encrypt blob ───────────────────────────────────────────
int vm_encrypt_blob(const unsigned char *plaintext, int plaintext_len,
                           unsigned char **ciphertext, int *ciphertext_len) {
    unsigned char key[32] = "hardened_vm_key_2026_super_se"; 
    unsigned char iv[16];
    if (RAND_bytes(iv, sizeof(iv)) != 1) return -1;

    unsigned char op_key[32];
    if (RAND_bytes(op_key, 32) != 1) return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len;
    int total_plaintext_len = 32 + plaintext_len;
    unsigned char *full_plaintext = (unsigned char *)malloc(total_plaintext_len);
    if (!full_plaintext) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    memcpy(full_plaintext, op_key, 32);
    memcpy(full_plaintext + 32, plaintext, plaintext_len);

    int total_len = total_plaintext_len + 16 + 32;
    unsigned char *out = (unsigned char *)malloc(total_len);
    if (!out) {
        free(full_plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    memcpy(out, iv, 16);

    if (EVP_EncryptUpdate(ctx, out + 16, &len, full_plaintext, total_plaintext_len) != 1) {
        free(full_plaintext);
        free(out);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    int ciphertext_len_actual = len;

    if (EVP_EncryptFinal_ex(ctx, out + 16 + len, &len) != 1) {
        free(full_plaintext);
        free(out);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len_actual += len;

    unsigned int hmac_len;
    HMAC(EVP_sha256(), key, 32, out, 16 + ciphertext_len_actual,
         out + 16 + ciphertext_len_actual, &hmac_len);

    *ciphertext = out;
    *ciphertext_len = 16 + ciphertext_len_actual + 32;

    free(full_plaintext);
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}
