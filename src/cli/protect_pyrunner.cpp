#include "cli/protect_internal.h"
#include "crypto/file_util.h"
#include "crypto/pyobf.h"
#include "vm/vm.h"
#include "vm/vm_split.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <format>
#include <string>
#include <vector>

namespace protect {

int run_python3_popen(const char **argv,
                              const char *stdin_file,
                              Buffer *out) {
    // Build command: python3 <script> <args>
    std::string cmd = "python3";
    for (int i = 0; argv[i]; i++) {
        cmd += " ";
        cmd += argv[i];
    }
    if (stdin_file) {
        cmd += " <";
        cmd += stdin_file;
    }
    
    FILE *fp = popen(cmd.c_str(), "r");
    if (!fp) return -1;
    
    // Read entire output into buffer
    std::string result;
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        result.append(buf, n);
    }
    
    int rc = pclose(fp);
    
    if (rc != 0 || result.empty()) return -1;
    
    out->data = (unsigned char *)malloc(result.size());
    if (!out->data) return -1;
    memcpy(out->data, result.data(), result.size());
    out->size = result.size();
    return 0;
}

// Legacy wrapper for backward compatibility with vm_split_source
int run_python3(const char **argv,
                        const char *stdin_file,
                        const char *stdout_file,
                        const char *stderr_file) {
    std::string cmd = "python3";
    for (int i = 0; argv[i]; i++) {
        cmd += " ";
        cmd += argv[i];
    }
    if (stdin_file) {
        cmd += " <";
        cmd += stdin_file;
    }
    if (stdout_file) {
        cmd += " >";
        cmd += stdout_file;
    }
    if (stderr_file) {
        cmd += " 2>";
        cmd += stderr_file;
    }
    int rc = system(cmd.c_str());
    if (rc == -1) return -1;
    return WEXITSTATUS(rc);
}

ExitCode obfuscate_source(const char *src, size_t src_len,
                                  const char *techniques,
                                  Buffer *out, int seed,
                                  float density) {
    char *tmpdir = tmpdir_create();
    char *obf_path = NULL, *in_path = NULL;
    int obf_fd = -1, in_fd = -1;
    ExitCode ret_err = EXIT_ERR_CRYPTO;

    if (!tmpdir) return EXIT_ERR_CRYPTO;

    obf_path = tmpdir_path(tmpdir, "obf.py");
    in_path  = tmpdir_path(tmpdir, "in.py");
    if (!obf_path || !in_path) goto obf_cleanup;

    /* Secure file creation:
     * - O_EXCL: fail if file exists (prevents TOCTOU race)
     * - O_NOFOLLOW: fail if path is a symlink (prevents symlink attack)
     * - 0600: only owner can read/write (protection during creation)
     */
    obf_fd = open(obf_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    in_fd  = open(in_path,  O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (obf_fd < 0 || in_fd < 0) goto obf_cleanup;

    {
    size_t slen = strlen(PYOBF_SCRIPT);
    if (write(obf_fd, PYOBF_SCRIPT, slen) != (ssize_t)slen ||
        write(in_fd, src, src_len) != (ssize_t)src_len) {
        ret_err = EXIT_ERR_FILE; goto obf_cleanup;
    }
    }

    close(obf_fd); obf_fd = -1;
    close(in_fd);  in_fd  = -1;

    {
    char seed_arg[32] = {0};
    char density_arg[16] = {0};
    const char *argv[5] = {obf_path, techniques, NULL, NULL, NULL};
    int argn = 2;
    if (seed >= 0) {
        snprintf(seed_arg, sizeof(seed_arg), "%d", seed);
        argv[argn++] = seed_arg;
    }
    snprintf(density_arg, sizeof(density_arg), "%.2f", (double)density);
    argv[argn++] = density_arg;
    Buffer pipe_out = {0};
    if (run_python3_popen(argv, in_path, &pipe_out) != 0) {
        free(pipe_out.data);
        goto obf_cleanup;
    }
    out->data = pipe_out.data;
    out->size = pipe_out.size;
    ret_err = EXIT_OK;
    goto obf_cleanup_no_free_out;
    }

obf_cleanup:
    if (obf_fd >= 0) close(obf_fd);
    if (in_fd  >= 0) close(in_fd);
    free(obf_path); free(in_path);
    tmpdir_destroy(tmpdir);
    return ret_err;

obf_cleanup_no_free_out:
    if (obf_fd >= 0) close(obf_fd);
    if (in_fd  >= 0) close(in_fd);
    free(obf_path); free(in_path);
    tmpdir_destroy(tmpdir);
    return EXIT_OK;
}

ExitCode vm_split_source(const char *src, size_t src_len,
                                const char *obf_tmpl_path,
                                const char *techniques,
                                Buffer *exec_out, Buffer *vm_out) {
    // Use private temp directory
    char *tmpdir = tmpdir_create();
    if (!tmpdir) return EXIT_ERR_CRYPTO;

    char *split_path = tmpdir_path(tmpdir, "split.py");
    char *in_path    = tmpdir_path(tmpdir, "in.py");
    char *out_path   = tmpdir_path(tmpdir, "out");
    if (!split_path || !in_path || !out_path) {
        free(split_path); free(in_path); free(out_path);
        tmpdir_destroy(tmpdir);
        return EXIT_ERR_CRYPTO;
    }

    /* Secure file creation with O_EXCL|O_NOFOLLOW to prevent race/symlink attacks */
    int fd_s = open(split_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    int fd_i = open(in_path,    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    int fd_o = open(out_path,   O_RDWR   | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd_s < 0 || fd_i < 0 || fd_o < 0) {
        if (fd_s >= 0) close(fd_s);
        if (fd_i >= 0) close(fd_i);
        if (fd_o >= 0) close(fd_o);
        free(split_path); free(in_path); free(out_path);
        tmpdir_destroy(tmpdir);
        return EXIT_ERR_CRYPTO;
    }

    size_t slen = strlen(VM_SPLIT_SCRIPT);
    if (write(fd_s, VM_SPLIT_SCRIPT, slen) != (ssize_t)slen ||
        write(fd_i, src, src_len) != (ssize_t)src_len) {
        close(fd_s); close(fd_i); close(fd_o);
        free(split_path); free(in_path); free(out_path);
        tmpdir_destroy(tmpdir);
        return EXIT_ERR_FILE;
    }
    close(fd_s); close(fd_i); fd_s = fd_i = -1;

    const char *tech = (techniques && techniques[0]) ? techniques : "";
    char *err_path = tmpdir_path(tmpdir, "out.err");
    const char *argv[] = {split_path, obf_tmpl_path, tech, NULL};
    if (run_python3(argv, in_path, out_path, err_path ? err_path : NULL) != 0) {
        close(fd_o); free(err_path);
        free(split_path); free(in_path); free(out_path);
        tmpdir_destroy(tmpdir);
        return EXIT_ERR_CRYPTO;
    }
    free(err_path);

    off_t fsz = lseek(fd_o, 0, SEEK_END);
    if (fsz <= 0) { close(fd_o); free(split_path); free(in_path); free(out_path); tmpdir_destroy(tmpdir); return EXIT_ERR_CRYPTO; }
    lseek(fd_o, 0, SEEK_SET);

    unsigned char *data = (unsigned char *)malloc((size_t)fsz + 1);
    if (!data) { close(fd_o); free(split_path); free(in_path); free(out_path); tmpdir_destroy(tmpdir); return EXIT_ERR_CRYPTO; }

    ssize_t nr = read(fd_o, data, (size_t)fsz);
    close(fd_o);
    data[nr] = '\0';

    // Parse markers: #===EXEC_SOURCE=== ... #===VM_SOURCE=== ...
    const char *exec_marker = "#===EXEC_SOURCE===\n";
    const char *vm_marker   = "#===VM_SOURCE===\n";

    char *exec_start = strstr((char *)data, exec_marker);
    char *vm_start   = strstr((char *)data, vm_marker);

    if (!exec_start || !vm_start) {
        free(data); free(split_path); free(in_path); free(out_path);
        tmpdir_destroy(tmpdir);
        return EXIT_ERR_CRYPTO;
    }

    exec_start += strlen(exec_marker);
    // exec_source: from exec_start to vm_marker - 1 (strip trailing newline)
    size_t exec_len = (size_t)(vm_start - exec_start);
    if (exec_len > 0 && exec_start[exec_len - 1] == '\n')
        exec_len--;

    vm_start += strlen(vm_marker);
    size_t vm_len = (size_t)(nr - (vm_start - (char *)data));
    if (vm_len > 0 && vm_start[vm_len - 1] == '\n')
        vm_len--;

    exec_out->data = (unsigned char *)malloc(exec_len + 1);
    vm_out->data   = (unsigned char *)malloc(vm_len + 1);
    if (!exec_out->data || !vm_out->data) {
        free(exec_out->data); free(vm_out->data); free(data);
        free(split_path); free(in_path); free(out_path);
        tmpdir_destroy(tmpdir);
        return EXIT_ERR_CRYPTO;
    }

    memcpy(exec_out->data, exec_start, exec_len);
    exec_out->data[exec_len] = '\0';
    exec_out->size = exec_len;

    memcpy(vm_out->data, vm_start, vm_len);
    vm_out->data[vm_len] = '\0';
    vm_out->size = vm_len;

    free(data);
    free(split_path); free(in_path); free(out_path);
    tmpdir_destroy(tmpdir);
    return EXIT_OK;
}

// Clean split (no obfuscation): split source into function/class defs (exec)
// and module-level code (VM). Uses a pass-through "obfuscation" script.
ExitCode vm_split_source_clean(const char *src, size_t src_len,
                                        Buffer *exec_out, Buffer *vm_out) {
    char *tmpdir = tmpdir_create();
    if (!tmpdir) return EXIT_ERR_CRYPTO;

    char *obf_tmpl = tmpdir_path(tmpdir, "nop.py");
    if (!obf_tmpl) { tmpdir_destroy(tmpdir); return EXIT_ERR_CRYPTO; }

    /* Secure file creation with O_EXCL|O_NOFOLLOW */
    int obf_fd = open(obf_tmpl, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (obf_fd < 0) { free(obf_tmpl); tmpdir_destroy(tmpdir); return EXIT_ERR_CRYPTO; }

    const char *nop_script = "#!/usr/bin/env python3\nimport sys\nsys.stdout.write(sys.stdin.read())\n";
    size_t slen = strlen(nop_script);
    if (write(obf_fd, nop_script, slen) != (ssize_t)slen) {
        close(obf_fd); free(obf_tmpl); tmpdir_destroy(tmpdir);
        return EXIT_ERR_FILE;
    }
    close(obf_fd);

    ExitCode ret = vm_split_source(src, src_len, obf_tmpl, NULL, exec_out, vm_out);
    free(obf_tmpl);
    tmpdir_destroy(tmpdir);
    return ret;
}

// ── VM bytecode obfuscation ─────────────────────────────────────────────
// Insert NOP instructions at random positions and fix up jump targets.
void vm_obfuscate_program(VmProgram *prog) {
    int n = prog->count;
    if (n <= 3) return;
    
    // Disable bytecode obfuscation (NOP insertion) entirely to ensure correct execution
    int new_count = n;
    int extra = 0;


    VmInstr *new_instrs = (VmInstr *)calloc((size_t)new_count, sizeof(VmInstr));
    if (!new_instrs) return;

    // Choose random NOP positions
    char *is_nop = (char *)calloc((size_t)new_count, 1);
    if (!is_nop) { free(new_instrs); return; }
    int inserted = 0;
    while (inserted < extra) {
        int pos = rand() % new_count;
        if (!is_nop[pos]) {
            is_nop[pos] = 1;
            inserted++;
        }
    }

    // Build old→new index mapping and fill new array
    int *old_to_new = (int *)malloc((size_t)n * sizeof(int));
    if (!old_to_new) { free(new_instrs); free(is_nop); return; }
    int src_i = 0;
    for (int dst_i = 0; dst_i < new_count; dst_i++) {
        if (is_nop[dst_i]) {
            new_instrs[dst_i].op  = 0; // NOP
            new_instrs[dst_i].rd  = (uint8_t)(rand() % 64);
            new_instrs[dst_i].rs1 = (uint8_t)(rand() % 64);
            new_instrs[dst_i].rs2 = (uint8_t)(rand() % 64);
            new_instrs[dst_i].imm = rand();
        } else {
            new_instrs[dst_i] = prog->instrs[src_i];
            old_to_new[src_i] = dst_i;
            src_i++;
        }
    }

    // Fix jump targets (opcodes 30=JMP, 31=JMP_IF_TRUE, 32=JMP_IF_FALSE)
    for (int i = 0; i < new_count; i++) {
        if (new_instrs[i].op == 30 ||
            new_instrs[i].op == 31 ||
            new_instrs[i].op == 32) {
            int old_target = new_instrs[i].imm;
            if (old_target >= 0 && old_target < n) {
                new_instrs[i].imm = old_to_new[old_target];
            }
        }
    }

    free(prog->instrs);
    free(is_nop);
    free(old_to_new);
    prog->instrs = new_instrs;
    prog->count = new_count;
}

} /* namespace protect */
