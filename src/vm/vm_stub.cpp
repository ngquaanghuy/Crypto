#include "vm/vm.h"
#include "vm/vm_interp_py.h"
#include "crypto/common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cstdarg>

// Append a string to the buffer at pos, updating pos
static void sb_append_str(char **pos, char *end, const char *s) {
    size_t n = strlen(s);
    if (*pos + n < end) {
        memcpy(*pos, s, n);
        *pos += n;
        **pos = 0;
    }
}

static void sb_printf(char **pos, char *end, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(*pos, (size_t)(end - *pos), fmt, ap);
    va_end(ap);
    if (n > 0) {
        size_t n2 = (size_t)n;
        if (*pos + n2 >= end) n2 = (size_t)(end - *pos - 1);
        *pos += n2;
        **pos = 0;
    }
}

// Generate VM-enhanced stub
// The stub includes:
// 1. VM interpreter (~80 lines Python)
// 2. Hot source exec (native speed)
// 3. Cold VM instruction run

ExitCode vm_generate_stub(const char *b64_data, size_t b64_sz,
                           const unsigned char *vm_blob, size_t vm_blob_sz,
                           const char *algo_id,
                           const char *obf_key, size_t obf_key_len,
                           const char *anti_code, size_t anti_len,
                           int xor_byte,
                           Buffer *out) {
    // Use SB_SZ similar to protect.cpp stub generation
    #define VM_SB_SZ (65536 * 4)
    char *buf = (char *)malloc(VM_SB_SZ);
    if (!buf) return EXIT_ERR_CRYPTO;
    char *p = buf;
    char *end = buf + VM_SB_SZ - 1;

    // Random names
    char n_h[16], n_m[16], n_b[16], n_s[16];
    char n_P[16], n_A[16], n_k[16], n_fn[16], n_9[16];
    char n_hot[16], n_code[16], n_consts[16], n_names[16];

    auto rand_name = [](char *buf, int sz) {
        int len = 3 + rand() % 6;
        char *p = buf; *p++ = '_';
        for (int i = 1; i < len && i < sz - 1; i++)
            *p++ = (char)('a' + rand() % 26);
        *p = '\0';
    };

    rand_name(n_h, sizeof(n_h));
    rand_name(n_m, sizeof(n_m));
    rand_name(n_b, sizeof(n_b));
    rand_name(n_s, sizeof(n_s));
    rand_name(n_P, sizeof(n_P));
    rand_name(n_A, sizeof(n_A));
    rand_name(n_k, sizeof(n_k));
    rand_name(n_fn, sizeof(n_fn));
    rand_name(n_9, sizeof(n_9));
    rand_name(n_hot, sizeof(n_hot));
    rand_name(n_code, sizeof(n_code));
    rand_name(n_consts, sizeof(n_consts));
    rand_name(n_names, sizeof(n_names));

    sb_printf(&p, end, "#!/usr/bin/env python3\n");
    sb_printf(&p, end, "import hashlib as %s, hmac as %s, base64 as %s, sys as %s\n",
              n_h, n_m, n_b, n_s);

    // Base64 of the VM blob
    sb_printf(&p, end, "%s = \"\"\"%s\"\"\"\n", n_P, b64_data);
    sb_printf(&p, end, "%s = %s\n", n_A, algo_id);

    // VM interpreter
    sb_printf(&p, end, "%s\n", VM_INTERP_SCRIPT);

    // Main function
    sb_printf(&p, end, "def %s():\n", n_fn);

    // Anti-analysis
    if (anti_len > 0) {
        // Patch __S__ in anti_code
        char *patched = (char *)malloc(anti_len + 256);
        if (patched) {
            size_t out_pos = 0;
            for (size_t i = 0; i < anti_len; i++) {
                if (i + 4 < anti_len && memcmp(anti_code + i, "__S__", 5) == 0) {
                    out_pos += snprintf(patched + out_pos, 256, "%s", n_s);
                    i += 4;
                } else {
                    patched[out_pos++] = anti_code[i];
                }
            }
            patched[out_pos] = '\0';
            sb_printf(&p, end, "%s\n", patched);
            free(patched);
        }
    }

    // Key deobfuscation
    sb_printf(&p, end, "    %s = bytes.fromhex(\"%s\")\n", n_k, obf_key);
    if (obf_key_len > 0) {
        sb_printf(&p, end, "    %s = bytes(_ ^ %d for _ in %s).decode()\n",
                  n_k, xor_byte, n_k);
    }

    // Decode VM blob
    sb_printf(&p, end, "    %s = %s.b64decode(%s)\n", n_9, n_b, n_P);

    // Decrypt (use algorithm dispatch similar to original stub)
    sb_printf(&p, end, "    if %s == %s:\n", n_A, algo_id);
    sb_printf(&p, end, "        pass\n");
    sb_printf(&p, end, "    else:\n");
    sb_printf(&p, end, "        %s.stderr.write('error: unsupported algorithm\\n'); %s.exit(1)\n",
              n_s, n_s);

    // Deserialize and run VM
    sb_printf(&p, end, "    %s, %s, %s, %s = _vm_deserialize(%s)\n",
              n_hot, n_code, n_consts, n_names, n_9);
    sb_printf(&p, end, "    exec(compile(%s, '<hot>', 'exec'), globals())\n", n_hot);
    sb_printf(&p, end, "    _vm_run(%s, %s, %s, globals(), locals())\n",
              n_code, n_consts, n_names);

    sb_printf(&p, end, "if __name__ == '__main__':\n  %s()\n", n_fn);

    out->data = (unsigned char *)buf;
    out->size = (size_t)(p - buf);
    #undef VM_SB_SZ
    return EXIT_OK;
}
