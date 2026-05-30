#include "vm/vm.h"
#include "vm/vm_interp_py.h"
#include "crypto/common.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <format>
#include <string_view>

// Append a string to the buffer at pos, updating pos
static void sb_append_str(char **pos, char *end, std::string_view s) {
    if (*pos + s.size() < end) {
        memcpy(*pos, s.data(), s.size());
        *pos += s.size();
        **pos = 0;
    }
}

static void sb_printf(char **pos, char *end, std::string_view fmt, const auto&... args) {
    auto result = std::vformat(fmt, std::make_format_args(args...));
    size_t n = result.size();
    if (*pos + n < end) {
        memcpy(*pos, result.data(), n);
        *pos += n;
        **pos = 0;
    }
}

// Generate VM-enhanced stub
ExitCode vm_generate_stub(const char *b64_data, size_t b64_sz,
                           const unsigned char *vm_blob, size_t vm_blob_sz,
                           const char *algo_id,
                           const char *obf_key, size_t obf_key_len,
                           const char *anti_code, size_t anti_len,
                           int xor_byte,
                           Buffer *out) {
    #define VM_SB_SZ (65536 * 4)
    char *buf = (char *)malloc(VM_SB_SZ);
    if (!buf) return EXIT_ERR_CRYPTO;
    char *p = buf;
    char *end = buf + VM_SB_SZ - 1;

    // Random names
    std::string n_h, n_m, n_b, n_s;
    std::string n_P, n_A, n_k, n_fn, n_9, n_ok;
    std::string n_hot, n_code, n_consts, n_names, n_map;

    auto rand_name = [&]() -> std::string {
        int len = 3 + rand() % 6;
        std::string r;
        r += '_';
        for (int i = 1; i < len; i++)
            r += static_cast<char>('a' + rand() % 26);
        return r;
    };

    n_h = rand_name(); n_m = rand_name(); n_b = rand_name(); n_s = rand_name();
    n_P = rand_name(); n_A = rand_name(); n_k = rand_name(); n_fn = rand_name();
    n_9 = rand_name(); n_ok = rand_name();
    n_hot = rand_name(); n_code = rand_name(); n_consts = rand_name();
    n_names = rand_name(); n_map = rand_name();

    sb_printf(&p, end, "#!/usr/bin/env python3\n");
    sb_printf(&p, end, "import hashlib as {}, hmac as {}, base64 as {}, sys as {}\n",
              n_h, n_m, n_b, n_s);
    sb_printf(&p, end, "{} = \"\"\"{}\"\"\"\n", n_P, b64_data);
    sb_printf(&p, end, "{} = {}\n", n_A, algo_id);
    sb_printf(&p, end, "{}\n", VM_INTERP_SCRIPT);
    sb_printf(&p, end, "def {}():\n", n_fn);

    // Anti-analysis
    if (anti_len > 0) {
        char *patched = (char *)malloc(anti_len + 256);
        if (patched) {
            size_t out_pos = 0;
            for (size_t i = 0; i < anti_len; i++) {
                if (i + 4 < anti_len && memcmp(anti_code + i, "__S__", 5) == 0) {
                    out_pos += snprintf(patched + out_pos, 256, "%s", n_s.c_str());
                    i += 4;
                } else {
                    patched[out_pos++] = anti_code[i];
                }
            }
            patched[out_pos] = '\0';
            sb_printf(&p, end, "{}\n", patched);
            free(patched);
        }
    }

    // Key deobfuscation
    sb_printf(&p, end, "    {} = bytes.fromhex(\"{}\")\n", n_k, obf_key);
    if (obf_key_len > 0) {
        sb_printf(&p, end, "    {} = bytes(_ ^ {} for _ in {}).decode()\n",
                  n_k, xor_byte, n_k);
    }

    // Decode VM blob
    sb_printf(&p, end, "    {} = {}.b64decode({})\n", n_9, n_b, n_P);

    // Decrypt (use algorithm dispatch)
    sb_printf(&p, end, "    if {} == {}:\n", n_A, algo_id);
    sb_printf(&p, end, "        pass\n");
    sb_printf(&p, end, "    else:\n");
    sb_printf(&p, end, "        {}.stderr.write('error: unsupported algorithm\\n'); {}.exit(1)\n",
              n_s, n_s);

    // Deserialize and run VM
    sb_printf(&p, end, "    {}, {}, {}, {}, {} = _vm_deserialize({})\n",
              n_code, n_consts, n_names, n_map, n_ok, n_9);
    sb_printf(&p, end, "    _vm_run({}, {}, {}, globals(), locals(), {}, {})\n",
              n_code, n_consts, n_names, n_map, n_ok);

    sb_printf(&p, end, "if __name__ == '__main__':\n  {}()\n", n_fn);

    out->data = (unsigned char *)buf;
    out->size = (size_t)(p - buf);
    #undef VM_SB_SZ
    return EXIT_OK;
}
