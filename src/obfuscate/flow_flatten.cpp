#include "crypto/obfuscate.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <algorithm>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

/* ── Initialize flow flatten plan ── */
void flowflatten_plan_init(FlowFlattenPlan *plan, int num_blocks) {
    if (!plan) return;
    plan->blocks = (FlowBlock *)calloc(num_blocks, sizeof(FlowBlock));
    plan->num_blocks = num_blocks;
    plan->initial_state = 0;
    RAND_bytes(plan->key, sizeof(plan->key));
}

void flowflatten_plan_free(FlowFlattenPlan *plan) {
    if (!plan) return;
    for (int i = 0; i < plan->num_blocks; i++) {
        free(plan->blocks[i].block_code);
    }
    free(plan->blocks);
    plan->blocks = nullptr;
    plan->num_blocks = 0;
}

/* ── HMAC-encode a state value into hex string ── */
static void hmac_encode_state(int state, const unsigned char *key,
                              size_t key_len, char *out_hex, size_t out_max) {
    unsigned char digest[32];
    unsigned int digest_len = 32;
    char state_buf[16];
    snprintf(state_buf, sizeof(state_buf), "S%d", state);

    HMAC(EVP_sha256(), key, (int)key_len,
         (const unsigned char *)state_buf, strlen(state_buf),
         digest, &digest_len);

    for (unsigned int i = 0; i < 8 && (i * 2 + 2) < out_max; i++) {
        snprintf(out_hex + i * 2, 3, "%02x", digest[i]);
    }
}

int flowflatten_set_block(FlowFlattenPlan *plan, int idx,
                          const char *block_code, int next_state) {
    if (!plan || idx < 0 || idx >= plan->num_blocks) return 0;
    free(plan->blocks[idx].block_code);
    plan->blocks[idx].block_code = strdup(block_code);
    plan->blocks[idx].state_id = idx;
    plan->blocks[idx].next_state = next_state;
    hmac_encode_state(idx, plan->key, sizeof(plan->key),
                      plan->blocks[idx].state_encoded,
                      sizeof(plan->blocks[idx].state_encoded));
    return 1;
}

/* ── Generate opaque predicate (always true, data-dependent) ── */
static const char *opaque_true_templates[] = {
    "(lambda _: str(_) == str(_) and isinstance(_, int) and (_ + 1 > _))(0)",
    "(lambda _: abs(_) >= 0 and hash(str(_)) is not None)(hash(None))",
    "(lambda _: [x for x in (_) if x == x] == [_ for x in (_) if True])([None])",
    "(lambda _: len(str(_.__name__)) > 0 or not (_.__doc__ is None and False))({}.__class__)",
    "(lambda _: [None for __ in [_]][0] is None or len({}.__class__.__name__) < 0)(0)",
};

char *flowflatten_opaque_predicate(void) {
    unsigned char idx_buf;
    RAND_bytes(&idx_buf, 1);
    int idx = idx_buf % 5;
    return strdup(opaque_true_templates[idx]);
}

static const char *opaque_false_templates[] = {
    "(lambda _: _ != _ and isinstance({}, type(None)))(float('nan'))",
    "(lambda _: [x for x in [_] if False] == [None for x in [_] if True])(0)",
    "(lambda _: hash(str(_)) != hash(str(_)) or (_ + 1 == _))(1)",
};

char *flowflatten_opaque_false_predicate(void) {
    unsigned char idx_buf;
    RAND_bytes(&idx_buf, 1);
    int idx = idx_buf % 3;
    return strdup(opaque_false_templates[idx]);
}

/* ── Generate Python flattened state machine ── */
char *flowflatten_generate_python(const FlowFlattenPlan *plan,
                                  const unsigned char *hmac_key,
                                  size_t hmac_key_len) {
    if (!plan || plan->num_blocks < 2) return nullptr;

    std::string py;
    py.reserve(16384);

    /* Generate HMAC verification function */
    char key_hex[65];
    for (size_t i = 0; i < hmac_key_len && i < 32; i++)
        snprintf(key_hex + i * 2, 3, "%02x", hmac_key[i]);
    key_hex[64] = '\0';

    /* Random names for state var, HMAC function, dispatch */
    unsigned char rnd[8];
    RAND_bytes(rnd, sizeof(rnd));
    uint64_t rseed = 0;
    for (int i = 0; i < 8; i++) rseed = (rseed << 8) | rnd[i];

    char svar[32], hfunc[32], dtable[32];
    snprintf(svar, sizeof(svar), "_S%lx", rseed & 0xFFFFFFF);
    snprintf(hfunc, sizeof(hfunc), "_H%lx", (rseed >> 28) & 0xFFFFFFF);
    snprintf(dtable, sizeof(dtable), "_D%lx", (rseed >> 56) & 0xFFFFFFF);

    py += "import hashlib as _HL, hmac as _HM\n\n";

    /* HMAC state encoding function */
    py += std::string(hfunc) + " = lambda _s: _HM.new(\n";
    py += "    bytes.fromhex('" + std::string(key_hex) + "'),\n";
    py += "    str(_s).encode(), _HL.sha256\n";
    py += ").hexdigest()[:16]\n\n";

    /* State verification function */
    py += "def _VF(enc_state, raw_state):\n";
    py += "    return enc_state == " + std::string(hfunc) + "(raw_state)\n\n";

    /* Precompute all state hashes */
    py += "_SH = {\n";
    for (int i = 0; i < plan->num_blocks; i++) {
        py += "    " + std::string(plan->blocks[i].state_encoded) + ": " +
              std::to_string(plan->blocks[i].state_id) + ",\n";
    }
    py += "}\n\n";

    /* Main flattened function */
    py += "def _flattened_main():\n";
    py += "    " + std::string(svar) + " = '" +
          plan->blocks[0].state_encoded + "'\n";
    py += "    _R = None\n";
    py += "    while True:\n";

    /* Generate if-elif chain with opaque predicates */
    for (int i = 0; i < plan->num_blocks; i++) {
        const char *kw = (i == 0) ? "if" : "elif";
        char *opaque = flowflatten_opaque_predicate();

        py += "        " + std::string(kw) + " _VF(" + std::string(svar) +
              ", " + std::to_string(plan->blocks[i].state_id) + ")";
        py += " and " + std::string(opaque) + ":\n";
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
            py += "            " + std::string(svar) + " = '" +
                  plan->blocks[plan->blocks[i].next_state].state_encoded + "'\n";
        } else {
            py += "            return _R\n";
        }
    }

    py += "        else:\n";
    /* Opaque false branch — never taken */
    char *opaque_false = flowflatten_opaque_false_predicate();
    py += "            if " + std::string(opaque_false) + ":\n";
    free(opaque_false);
    py += "                pass\n";

    py += "            break\n";
    py += "\n    return _R\n\n";

    return strdup(py.c_str());
}