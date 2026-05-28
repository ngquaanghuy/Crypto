#include "vm/vm.h"
#include "vm/vm_py.h"
#include "crypto/file_util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>

ExitCode vm_program_init(VmProgram *prog) {
    memset(prog, 0, sizeof(*prog));
    return EXIT_OK;
}

void vm_program_free(VmProgram *prog) {
    free(prog->instrs);
    free(prog->hot_src);
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
    memset(prog, 0, sizeof(*prog));
}

ExitCode vm_compile_source(const char *source, size_t source_len,
                            VmProgram *prog, int opaque) {
    // Use Python script via temp files (same pattern as obfuscate_source)
    char script_tmpl[] = "/tmp/vm_cmp_XXXXXX.py";
    char in_tmpl[]     = "/tmp/vm_in_XXXXXX.py";
    char out_tmpl[]    = "/tmp/vm_out_XXXXXX.bin";

    int fd_s = mkstemps(script_tmpl, 3);
    int fd_i = mkstemps(in_tmpl, 3);
    int fd_o = mkstemps(out_tmpl, 4);

    if (fd_s < 0 || fd_i < 0 || fd_o < 0) {
        if (fd_s >= 0) { close(fd_s); unlink(script_tmpl); }
        if (fd_i >= 0) { close(fd_i); unlink(in_tmpl); }
        if (fd_o >= 0) { close(fd_o); unlink(out_tmpl); }
        return EXIT_ERR_CRYPTO;
    }

    size_t slen = strlen(VM_COMPILE_SCRIPT);
    if (write(fd_s, VM_COMPILE_SCRIPT, slen) != (ssize_t)slen ||
        write(fd_i, source, source_len) != (ssize_t)source_len) {
        close(fd_s); close(fd_i); close(fd_o);
        unlink(script_tmpl); unlink(in_tmpl); unlink(out_tmpl);
        return EXIT_ERR_FILE;
    }
    close(fd_s); close(fd_i);

    // Run python3 script with fork/exec (no shell, no command injection)
    pid_t pid = fork();
    if (pid == -1) {
        close(fd_o); unlink(script_tmpl); unlink(in_tmpl); unlink(out_tmpl);
        return EXIT_ERR_CRYPTO;
    }
    if (pid == 0) {
        // Child: redirect stdio
        int fd_in = open(in_tmpl, O_RDONLY);
        if (fd_in >= 0) { dup2(fd_in, STDIN_FILENO); close(fd_in); }
        int fd_out = open(out_tmpl, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd_out >= 0) { dup2(fd_out, STDOUT_FILENO); close(fd_out); }
        char err_tmpl[sizeof(out_tmpl) + 8];
        snprintf(err_tmpl, sizeof(err_tmpl), "%s.err", out_tmpl);
        int fd_err = open(err_tmpl, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd_err >= 0) { dup2(fd_err, STDERR_FILENO); close(fd_err); }
        // Build argv
        const char *argv[16];
        int ai = 0;
        argv[ai++] = "python3";
        argv[ai++] = script_tmpl;
        if (opaque) argv[ai++] = "--opaque";
        argv[ai] = NULL;
        execvp("python3", (char *const *)argv);
        _exit(127);
    }
    int status;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        close(fd_o); unlink(script_tmpl); unlink(in_tmpl); unlink(out_tmpl);
        return EXIT_ERR_CRYPTO;
    }

    off_t fsz = lseek(fd_o, 0, SEEK_END);
    if (fsz <= 0) {
        close(fd_o); unlink(script_tmpl); unlink(in_tmpl); unlink(out_tmpl);
        return EXIT_ERR_CRYPTO;
    }
    lseek(fd_o, 0, SEEK_SET);

    unsigned char *buf = (unsigned char *)malloc((size_t)fsz);
    if (!buf) {
        close(fd_o); unlink(script_tmpl); unlink(in_tmpl); unlink(out_tmpl);
        return EXIT_ERR_CRYPTO;
    }

    ssize_t nr = read(fd_o, buf, (size_t)fsz);
    close(fd_o);
    unlink(script_tmpl); unlink(in_tmpl); unlink(out_tmpl);

    if (nr != fsz) { free(buf); return EXIT_ERR_FILE; }

    // Parse serialized output
    ExitCode ret = vm_deserialize(buf, (size_t)nr, prog);
    free(buf);
    return ret;
}

ExitCode vm_serialize(const VmProgram *prog, Buffer *out) {
    // Compute sizes
    size_t hot_len = prog->hot_src ? strlen(prog->hot_src) : 0;

    // Const table size
    size_t consts_size = 4; // count
    for (int i = 0; i < prog->const_count; i++) {
        consts_size += 1 + 4; // type + len
        if (prog->const_strs[i])
            consts_size += strlen(prog->const_strs[i]);
    }

    // Name table size
    size_t names_size = 4; // count
    for (int i = 0; i < prog->name_count; i++) {
        names_size += 2; // len
        if (prog->names[i])
            names_size += strlen(prog->names[i]);
    }

    // Instrs size
    size_t instrs_size = 4 + (size_t)prog->count * VM_INSTR_SIZE;

    size_t total = 4 + hot_len + consts_size + names_size + instrs_size;
    out->data = (unsigned char *)malloc(total);
    if (!out->data) return EXIT_ERR_CRYPTO;

    size_t pos = 0;

    // Hot source length + data
    uint32_t hl = (uint32_t)hot_len;
    memcpy(out->data + pos, &hl, 4); pos += 4;
    if (hot_len > 0) {
        memcpy(out->data + pos, prog->hot_src, hot_len); pos += hot_len;
    }

    // Const count
    uint32_t cc = (uint32_t)prog->const_count;
    memcpy(out->data + pos, &cc, 4); pos += 4;
    for (int i = 0; i < prog->const_count; i++) {
        out->data[pos++] = prog->const_types[i];
        size_t sl = prog->const_strs[i] ? strlen(prog->const_strs[i]) : 0;
        uint32_t sl32 = (uint32_t)sl;
        memcpy(out->data + pos, &sl32, 4); pos += 4;
        if (sl > 0) {
            memcpy(out->data + pos, prog->const_strs[i], sl); pos += sl;
        }
    }

    // Name count
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

    // Instr count + data
    uint32_t ic = (uint32_t)prog->count;
    memcpy(out->data + pos, &ic, 4); pos += 4;
    memcpy(out->data + pos, prog->instrs, (size_t)prog->count * VM_INSTR_SIZE);
    pos += (size_t)prog->count * VM_INSTR_SIZE;

    out->size = pos;
    return EXIT_OK;
}

ExitCode vm_deserialize(const unsigned char *data, size_t size,
                         VmProgram *prog) {
    vm_program_init(prog);

    size_t pos = 0;
    if (pos + 4 > size) return EXIT_ERR_CRYPTO;

    // Hot source
    uint32_t hot_len;
    memcpy(&hot_len, data + pos, 4); pos += 4;
    if (pos + hot_len > size) return EXIT_ERR_CRYPTO;
    if (hot_len > 0) {
        prog->hot_src = (char *)malloc(hot_len + 1);
        if (!prog->hot_src) return EXIT_ERR_CRYPTO;
        memcpy(prog->hot_src, data + pos, hot_len);
        prog->hot_src[hot_len] = '\0';
        pos += hot_len;
    }

    // Consts
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
                memcpy(prog->const_strs[i], data + pos, sl);
                prog->const_strs[i][sl] = '\0';
                pos += sl;
            }
        }
    }

    // Names
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

    // Instrs
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
    }

    return EXIT_OK;
}
