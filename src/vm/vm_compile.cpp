#include "vm/vm.h"
#include "vm/vm_py.h"
#include "crypto/file_util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
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
                            VmProgram *prog, int opaque, int seed) {
    // Use Python script via private temp directory
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

    // Run python3 script with fork/exec (no shell, no command injection)
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
        // Build argv
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

    if (nr != fsz) { free(buf); free(script_path); free(in_path); free(out_path); tmpdir_destroy(tmpdir); return EXIT_ERR_FILE; }

    // Prepend dummy opcode_map (256 bytes) before deserializing
    unsigned char *full_buf = (unsigned char *)malloc((size_t)nr + 256);
    if (!full_buf) { free(buf); free(script_path); free(in_path); free(out_path); tmpdir_destroy(tmpdir); return EXIT_ERR_CRYPTO; }
    memset(full_buf, 0, 256);
    memcpy(full_buf + 256, buf, (size_t)nr);
    free(buf);

    ExitCode ret = vm_deserialize(full_buf, (size_t)nr + 256, prog);
    free(full_buf);
    free(script_path); free(in_path); free(out_path);
    tmpdir_destroy(tmpdir);
    if (ret != EXIT_OK) return ret;

    // Apply Opcode Obfuscation
    uint8_t forward_map[256];
    for (int i = 0; i < 256; i++) forward_map[i] = (uint8_t)i;
    // Shuffle forward map
    for (int i = 255; i > 0; i--) {
        int j = rand() % (i + 1);
        uint8_t tmp = forward_map[i];
        forward_map[i] = forward_map[j];
        forward_map[j] = tmp;
    }
    // Map instructions using forward_map
    for (int i = 0; i < prog->count; i++) {
        prog->instrs[i].op = forward_map[prog->instrs[i].op];
    }
    // Store inverse map (stub needs _map[shuffled_op] = original_op)
    prog->opcode_map = (uint8_t *)malloc(256);
    if (!prog->opcode_map) return EXIT_ERR_CRYPTO;
    for (int i = 0; i < 256; i++) {
        prog->opcode_map[forward_map[i]] = (uint8_t)i;
    }

    return EXIT_OK;
}

ExitCode vm_serialize(const VmProgram *prog, Buffer *out) {
    // Compute sizes
    
    // Opcode map size
    size_t map_size = 256;
    
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
    
    size_t total = map_size + consts_size + names_size + instrs_size;
    out->data = (unsigned char *)malloc(total);
    if (!out->data) return EXIT_ERR_CRYPTO;
    
    size_t pos = 0;
    
    // Opcode map
    memcpy(out->data + pos, prog->opcode_map, map_size); pos += map_size;
    
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

int vm_encrypt_blob(const unsigned char *plaintext, int plaintext_len,
                           unsigned char **ciphertext, int *ciphertext_len) {
    unsigned char key[32] = "hardened_vm_key_2026_super_se"; 
    unsigned char iv[16];
    if (RAND_bytes(iv, sizeof(iv)) != 1) return -1;

    // Opcode Key Stream (P1: Virtualization)
    unsigned char op_key[32];
    if (RAND_bytes(op_key, 32) != 1) return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len;
    // We need to store op_key inside the blob, so we add 32 bytes to plaintext
    // Format: [op_key (32)] [actual_plaintext]
    int total_plaintext_len = 32 + plaintext_len;
    unsigned char *full_plaintext = (unsigned char *)malloc(total_plaintext_len);
    if (!full_plaintext) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    memcpy(full_plaintext, op_key, 32);
    memcpy(full_plaintext + 32, plaintext, plaintext_len);

    int total_len = total_plaintext_len + 16 + 32; // IV + ciphertext + HMAC
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

    // HMAC-SHA256
    unsigned int hmac_len;
    HMAC(EVP_sha256(), key, 32, out, 16 + ciphertext_len_actual, out + 16 + ciphertext_len_actual, &hmac_len);

    *ciphertext = out;
    *ciphertext_len = 16 + ciphertext_len_actual + 32;

    free(full_plaintext);
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

ExitCode vm_deserialize(const unsigned char *data, size_t size,
                          VmProgram *prog) {
    vm_program_init(prog);
    
    size_t pos = 0;
    
    // Skip opcode_map (256 bytes) — written by vm_serialize
    if (pos + 256 > size) return EXIT_ERR_CRYPTO;
    prog->opcode_map = (uint8_t *)malloc(256);
    memcpy(prog->opcode_map, data + pos, 256);
    pos += 256;
    
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

