#include "crypto/obfuscate.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <algorithm>
#include <openssl/rand.h>

/* ─── Advanced CFG Flattening with Dispatcher ───────────────────────────────
 *
 * Dispatcher patterns:
 *   Type 0 — Dictionary Dispatcher: maps plain state → lambda via dict
 *   Type 1 — List Dispatcher:       list of functions, shuffled permutation index
 *   Type 2 — Computed Dispatcher:   if/elif chain with obfuscated comparisons
 *
 * Key features:
 *   - Blocks stored in permuted (random) order via permutation slot assignment
 *   - Dead blocks fill remaining unused slots
 *   - Multiple dispatcher patterns chosen randomly per invocation
 *   - Opaque predicates in state transitions and dead-block guards
 */

/* ── Random helpers ── */
static int rand_range(int lo, int hi) {
    if (lo >= hi) return lo;
    unsigned char buf;
    RAND_bytes(&buf, 1);
    return lo + (buf % (hi - lo + 1));
}

static std::string rand_var_name(void) {
    unsigned char len_buf;
    RAND_bytes(&len_buf, 1);
    int len = 6 + (len_buf % 10);
    std::string r;
    r += '_';
    for (int i = 1; i < len; i++) {
        unsigned char c;
        RAND_bytes(&c, 1);
        int aset = c % 3;
        if (aset == 0) r += 'a' + (c % 26);
        else if (aset == 1) r += 'A' + (c % 26);
        else r += '0' + (c % 10);
        if (i == 1 && aset == 2) r.back() = 'a' + (c % 26);
    }
    return r;
}

/* ── Helper: format a block's code with proper indentation ── */
static void append_block_code(std::string &out, const char *code, const std::string &indent) {
    if (!code) return;
    const char *p = code;
    while (*p) {
        const char *nl = strchr(p, '\n');
        int linelen = (nl) ? (int)(nl - p) : (int)strlen(p);
        if (linelen > 0) {
            out += indent;
            out.append(p, linelen);
            out += '\n';
        }
        if (!nl) break;
        p = nl + 1;
    }
}

/* ─────────────────────────────────────────────────────────────────────────
 * Plan API
 * ───────────────────────────────────────────────────────────────────────── */

void adv_flowflatten_plan_init(AdvFlowFlattenPlan *plan, int num_real_blocks) {
    if (!plan) return;

    int total = num_real_blocks + (num_real_blocks / 3) + 1; // ~33% dead slots
    if (total < 3) total = 3;

    plan->blocks = (AdvFlowBlock *)calloc(total, sizeof(AdvFlowBlock));
    plan->num_blocks = total;
    plan->real_blocks = 0;
    plan->num_dead_blocks = 0;

    unsigned char rnd[12];
    RAND_bytes(rnd, sizeof(rnd));
    plan->dispatcher_type = rnd[0] % 3; // 0=dict, 1=list, 2=arithmetic
    plan->state_xor_key   = (int)rnd[1] ^ ((int)rnd[2] << 8);
    plan->state_mul_key   = (int)rnd[3] * 3 + 1;
    plan->state_add_key   = (int)rnd[4] ^ ((int)rnd[5] << 8);
    plan->state_mod       = (total * 3) + 1;

    // Create permutation [0..total-1] for physical slot assignment
    plan->permutation = (int *)malloc(total * sizeof(int));
    for (int i = 0; i < total; i++)
        plan->permutation[i] = i;
    for (int i = total - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        int t = plan->permutation[i];
        plan->permutation[i] = plan->permutation[j];
        plan->permutation[j] = t;
    }

    RAND_bytes(plan->key, sizeof(plan->key));
}

void adv_flowflatten_plan_free(AdvFlowFlattenPlan *plan) {
    if (!plan) return;
    for (int i = 0; i < plan->num_blocks; i++)
        free(plan->blocks[i].block_code);
    free(plan->blocks);
    free(plan->permutation);
    plan->blocks = nullptr;
    plan->permutation = nullptr;
    plan->num_blocks = 0;
}

int adv_flowflatten_set_block(AdvFlowFlattenPlan *plan, int logical_idx,
                              const char *block_code, int next_logical_state) {
    if (!plan) return 0;
    int slot = plan->real_blocks;
    if (slot >= plan->num_blocks) return 0;

    int phys_idx = plan->permutation[slot];

    free(plan->blocks[phys_idx].block_code);
    plan->blocks[phys_idx].block_code = strdup(block_code ? block_code : "pass");
    plan->blocks[phys_idx].state_id = logical_idx;
    plan->blocks[phys_idx].logical_next = next_logical_state;
    plan->blocks[phys_idx].encoded_state = logical_idx ^ plan->state_xor_key;
    plan->blocks[phys_idx].dead_block = 0;
    plan->real_blocks++;

    return 1;
}

int adv_flowflatten_add_dead_block(AdvFlowFlattenPlan *plan, const char *block_code) {
    if (!plan) return -1;

    for (int i = 0; i < plan->num_blocks; i++) {
        if (plan->blocks[i].block_code == nullptr && !plan->blocks[i].dead_block) {
            free(plan->blocks[i].block_code);
            plan->blocks[i].block_code = strdup(block_code ? block_code : "pass  # dead");
            plan->blocks[i].state_id = -1;
            plan->blocks[i].logical_next = -1;
            plan->blocks[i].encoded_state = (rand_range(0, 99999)) ^ plan->state_xor_key;
            plan->blocks[i].dead_block = 1;
            plan->num_dead_blocks++;
            return i;
        }
    }
    return -1;
}

/* ─────────────────────────────────────────────────────────────────────────
 * Python code generation — 3 dispatcher patterns
 * All functions produce code indented at +4 from the function body level.
 * ───────────────────────────────────────────────────────────────────────── */

/* ── Pattern 0: Dictionary Dispatcher (indented 4 spaces) ── */
static std::string gen_dict_dispatcher(const AdvFlowFlattenPlan *plan,
                                        const std::string &sv, const std::string &dp) {
    std::string py;
    py += "    " + dp + " = {\n";
    for (int i = 0; i < plan->num_blocks; i++) {
        if (plan->blocks[i].dead_block || !plan->blocks[i].block_code) continue;
        py += "        " + std::to_string(plan->blocks[i].state_id) + ": _b" +
              std::to_string(plan->blocks[i].state_id) + ",\n";
    }
    for (int di = 0; di < 3; di++) {
        int fake_key = rand_range(1000, 99999);
        py += "        " + std::to_string(fake_key ^ plan->state_xor_key) + ": _b_exit,\n";
    }
    py += "    }\n";
    py += "    while True:\n";
    py += "        " + sv + " = " + dp + ".get(" + sv + ", _b_exit)(" + sv + ")\n";
    py += "        if " + sv + " < 0:\n";
    py += "            break\n";
    return py;
}

/* ── Pattern 1: List Dispatcher with shuffled permutation (indented 4 spaces) ── */
static std::string gen_list_dispatcher(const AdvFlowFlattenPlan *plan,
                                        const std::string &sv, const std::string &dp) {
    int real_count = 0;
    for (int i = 0; i < plan->num_blocks; i++)
        if (!plan->blocks[i].dead_block && plan->blocks[i].block_code)
            real_count++;
    if (real_count == 0) return std::string();

    int *perm = (int *)malloc(real_count * sizeof(int));
    for (int i = 0; i < real_count; i++) perm[i] = i;
    for (int i = real_count - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        int t = perm[i]; perm[i] = perm[j]; perm[j] = t;
    }

    std::string py;
    py += "    " + dp + " = [None] * " + std::to_string(real_count) + "\n";

    int blk_idx = 0;
    for (int i = 0; i < plan->num_blocks; i++) {
        if (plan->blocks[i].dead_block || !plan->blocks[i].block_code) continue;
        int shuffled_pos = perm[blk_idx];
        py += "    " + dp + "[" + std::to_string(shuffled_pos) + "] = _b" +
              std::to_string(plan->blocks[i].state_id) + "\n";
        blk_idx++;
    }

    std::string pm = rand_var_name();
    py += "    " + pm + " = [\n";
    for (int i = 0; i < real_count; i++) {
        py += "        " + std::to_string(perm[i]) + ",\n";
    }
    py += "    ]\n";
    free(perm);

    std::string idx_var = rand_var_name();
    py += "    while True:\n";
    py += "        " + idx_var + " = " + pm + "[" + sv + "]\n";
    py += "        " + sv + " = " + dp + "[" + idx_var + "](" + sv + ")\n";
    py += "        if " + sv + " < 0:\n";
    py += "            break\n";
    return py;
}

/* ── Pattern 2: Arithmetic Computed Dispatcher (indented 4 spaces) ── */
static std::string gen_arith_dispatcher(const AdvFlowFlattenPlan *plan,
                                          const std::string &sv, const std::string &dp) {
    std::string py;
    py += "    while True:\n";

    int first = 1;
    for (int i = 0; i < plan->num_blocks; i++) {
        if (plan->blocks[i].dead_block || !plan->blocks[i].block_code) continue;

        int sid = plan->blocks[i].state_id;
        const char *kw = first ? "if" : "elif";
        first = 0;

        unsigned char style;
        RAND_bytes(&style, 1);
        int s = style % 4;
        std::string cond;
        switch (s) {
            case 0: cond = sv + " == " + std::to_string(sid); break;
            case 1: cond = "not (" + sv + " != " + std::to_string(sid) + ")"; break;
            case 2: {
                char *opaque = flowflatten_opaque_predicate();
                cond = sv + " == " + std::to_string(sid) + " and (" + std::string(opaque) + ")";
                free(opaque);
                break;
            }
            case 3: {
                int fake = (sid ^ plan->state_xor_key);
                cond = "(" + sv + " ^ " + std::to_string(plan->state_xor_key) + ") == " +
                       std::to_string(fake);
                break;
            }
            default: cond = sv + " == " + std::to_string(sid); break;
        }

        py += "        " + std::string(kw) + " " + cond + ":\n";
        py += "            " + sv + " = _b" + std::to_string(sid) + "(" + sv + ")\n";
    }

    py += "        else:\n";
    py += "            break\n";
    return py;
}

/* ─────────────────────────────────────────────────────────────────────────
 * Main code generator
 * ───────────────────────────────────────────────────────────────────────── */

char *adv_flowflatten_generate_python(const AdvFlowFlattenPlan *plan) {
    if (!plan || plan->num_blocks < 2) return nullptr;

    std::string py;
    py.reserve(32768);

    std::string sv  = rand_var_name();
    std::string dp  = rand_var_name();
    std::string ef  = rand_var_name();

    py += "import hashlib as " + rand_var_name() + "\n";
    py += "import sys as " + rand_var_name() + "\n\n";

    py += ef + " = lambda _s: (_s ^ " + std::to_string(plan->state_xor_key) + ")\n";
    py += "\n";

    py += "def _b_exit(_s):\n";
    py += "    return -1\n";
    py += "\n";

    // Real block functions
    for (int i = 0; i < plan->num_blocks; i++) {
        if (plan->blocks[i].dead_block || !plan->blocks[i].block_code) continue;
        int sid = plan->blocks[i].state_id;

        py += "def _b" + std::to_string(sid) + "(_st):\n";
        append_block_code(py, plan->blocks[i].block_code, "    ");

        if (plan->blocks[i].logical_next >= 0 &&
            plan->blocks[i].logical_next != plan->blocks[i].state_id) {
            py += "    return " + std::to_string(plan->blocks[i].logical_next) + "\n";
        } else {
            py += "    return -1\n";
        }
        py += "\n";
    }

    // Dead block functions
    for (int i = 0; i < plan->num_blocks; i++) {
        if (!plan->blocks[i].dead_block || !plan->blocks[i].block_code) continue;
        std::string db_name = rand_var_name();
        py += "def " + db_name + "(" + rand_var_name() + "):\n";
        append_block_code(py, plan->blocks[i].block_code, "    ");
        py += "    return " + std::to_string(rand_range(0, 99999)) + "\n";
        py += "\n";
    }

    // Main function
    std::string main_fn = rand_var_name();
    py += "def " + main_fn + "():\n";
    py += "    " + sv + " = 0\n";
    py += "    " + rand_var_name() + " = 0\n";
    py += "\n";

    // Dispatcher (these generate code already indented at +4)
    switch (plan->dispatcher_type) {
        case 0: py += gen_dict_dispatcher(plan, sv, dp); break;
        case 1: py += gen_list_dispatcher(plan, sv, dp); break;
        case 2: py += gen_arith_dispatcher(plan, sv, dp); break;
        default: py += gen_dict_dispatcher(plan, sv, dp); break;
    }

    // Opaque predicates indented at +4
    unsigned char opaque_cnt;
    RAND_bytes(&opaque_cnt, 1);
    int num_opaques = 1 + (opaque_cnt % 3);
    for (int oi = 0; oi < num_opaques; oi++) {
        char *opaque = flowflatten_opaque_predicate();
        std::string ov = rand_var_name();
        py += "    " + ov + " = (" + std::string(opaque) + ")\n";
        free(opaque);
    }

    py += "\n    return\n\n";

    py += "if __name__ == '__main__':\n";
    py += "    " + main_fn + "()\n";

    return strdup(py.c_str());
}

/* ── Public wrapper ── */
char *adv_flowflatten_wrap_source(const char *source, int block_count, float density) {
    if (!source) return nullptr;

    int real_blocks = block_count;
    if (real_blocks < 3) real_blocks = 3;

    AdvFlowFlattenPlan plan;
    adv_flowflatten_plan_init(&plan, real_blocks);

    std::string src(source);
    std::vector<std::string> lines;
    size_t pos = 0;
    while (pos < src.size()) {
        size_t nl = src.find('\n', pos);
        if (nl == std::string::npos) {
            lines.push_back(src.substr(pos));
            break;
        }
        lines.push_back(src.substr(pos, nl - pos));
        pos = nl + 1;
    }

    int lines_per_block = std::max(1, (int)lines.size() / real_blocks);
    int line_idx = 0;
    for (int bi = 0; bi < real_blocks && line_idx < (int)lines.size(); bi++) {
        std::string block_code;
        for (int li = 0; li < lines_per_block && line_idx < (int)lines.size(); li++, line_idx++) {
            block_code += lines[line_idx] + "\n";
        }
        if (block_code.empty()) block_code = "pass";
        int next = (bi < real_blocks - 1) ? bi + 1 : -1;
        adv_flowflatten_set_block(&plan, bi, block_code.c_str(), next);
    }

    int dead_count = std::min((int)(density * 2.0f), plan.num_blocks - plan.real_blocks);
    for (int di = 0; di < dead_count; di++) {
        char dead_code[128];
        snprintf(dead_code, sizeof(dead_code),
                 "_ = sum([%d, %d, %d])  # dead",
                 rand_range(1, 999), rand_range(1, 999), rand_range(1, 999));
        adv_flowflatten_add_dead_block(&plan, dead_code);
    }

    char *result = adv_flowflatten_generate_python(&plan);
    adv_flowflatten_plan_free(&plan);
    return result;
}
