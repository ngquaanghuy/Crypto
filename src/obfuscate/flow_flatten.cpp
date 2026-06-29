#include "crypto/obfuscate.h"
#include "obfuscate/flow_flatten_opaque.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <string>
#include <openssl/rand.h>

/* ── Generate Python flattened state machine ── */
char *flowflatten_generate_python(const FlowFlattenPlan *plan,
                                  const unsigned char *hmac_key,
                                  size_t hmac_key_len) {
    if (!plan || plan->num_blocks < 2) return nullptr;

    std::string py;
    py.reserve(16384);

    char key_hex[65];
    for (size_t i = 0; i < hmac_key_len && i < 32; i++)
        snprintf(key_hex + i * 2, 3, "%02x", hmac_key[i]);
    key_hex[64] = '\0';

    unsigned char rnd[8];
    RAND_bytes(rnd, sizeof(rnd));
    uint64_t rseed = 0;
    for (int i = 0; i < 8; i++) rseed = (rseed << 8) | rnd[i];

    char svar[32], hfunc[32], vfunc[32], smap[32];
    snprintf(svar, sizeof(svar), "_S%lx", rseed & 0xFFFFFFF);
    snprintf(hfunc, sizeof(hfunc), "_H%lx", (rseed >> 28) & 0xFFFFFFF);
    snprintf(vfunc, sizeof(vfunc), "_V%lx", ((rseed >> 40) & 0xFFFFFFF));
    snprintf(smap, sizeof(smap), "_M%lx", ((rseed >> 52) & 0xFFFFFFF));

    std::string sv(svar), hf(hfunc), vf(vfunc), sm(smap);

    py += "import hashlib as _" + flowflatten_rand_var_name() + ", hmac as _" + flowflatten_rand_var_name() + "\n\n";

    py += hf + " = lambda _s: __import__('hashlib').sha256(\n";
    py += "    bytes.fromhex('" + std::string(key_hex) + "') +\n";
    py += "    str(_s).encode()\n";
    py += ").hexdigest()[:16]\n\n";

    py += vf + " = lambda _e,_r: " +
          flowflatten_gen_obfuscated_cmp("_e", hf + "(_r)") + "\n\n";

    py += sm + " = {\n";
    for (int i = 0; i < plan->num_blocks; i++) {
        py += "    '" + std::string(plan->blocks[i].state_encoded) + "': " +
              std::to_string(plan->blocks[i].state_id) + ",\n";
    }
    py += "}\n\n";

    py += "def _" + flowflatten_rand_var_name() + "():\n";
    py += "    " + sv + " = " + hf + "(0)\n";
    py += "    _" + flowflatten_rand_var_name() + " = None\n";
    py += "    while True:\n";

    for (int i = 0; i < plan->num_blocks; i++) {
        const char *kw = (i == 0) ? "if" : "elif";
        char *opaque = flowflatten_opaque_predicate();
        std::string cmp = flowflatten_gen_obfuscated_cmp(sv, hf + "(" + std::to_string(i) + ")");
        py += "        " + std::string(kw) + " " + cmp + " and (" +
              std::string(opaque) + "):\n";
        free(opaque);

        if (plan->blocks[i].block_code) {
            char *line = plan->blocks[i].block_code;
            while (*line) {
                char *nl = strchr(line, '\n');
                int linelen = nl ? (int)(nl - line) : (int)strlen(line);
                if (linelen > 0) {
                    py += "            ";
                    py.append(line, linelen);
                    py += "\n";
                }
                if (!nl) break;
                line = nl + 1;
            }
        }

        if (plan->blocks[i].next_state >= 0 && i != plan->blocks[i].next_state) {
            py += "            " + sv + " = " +
                  hf + "(" + std::to_string(plan->blocks[i].next_state) + ")\n";
        } else {
            py += "            return _" + flowflatten_rand_var_name() + "\n";
        }
    }

    py += "        else:\n";
    unsigned char branch_style;
    RAND_bytes(&branch_style, 1);
    if (branch_style % 2 == 0) {
        char *opaque_f = flowflatten_opaque_false_predicate();
        py += "            if " + std::string(opaque_f) + ":\n";
        free(opaque_f);
        py += "                pass\n";
    } else {
        py += "            pass\n";
    }
    py += "            break\n";
    py += "\n    return None\n\n";

    return strdup(py.c_str());
}
