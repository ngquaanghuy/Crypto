#include "crypto/obfuscate.h"
#include "obfuscate/flow_flatten_opaque.h"
#include "obfuscate/flow_flatten_adv_plan.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <algorithm>
#include <openssl/rand.h>

/* ── Random helper ── */
static int rand_range(int lo, int hi) {
    if (lo >= hi) return lo;
    unsigned char buf;
    RAND_bytes(&buf, 1);
    return lo + (buf % (hi - lo + 1));
}

/* ── Helper: format a block's code with proper indentation ── */
void adv_flowflatten_append_block_code(std::string &out, const char *code,
                                        const std::string &indent) {
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

    int total = num_real_blocks + (num_real_blocks / 3) + 1;
    if (total < 3) total = 3;

    plan->blocks = (AdvFlowBlock *)calloc(total, sizeof(AdvFlowBlock));
    plan->num_blocks = total;
    plan->real_blocks = 0;
    plan->num_dead_blocks = 0;

    unsigned char rnd[12];
    RAND_bytes(rnd, sizeof(rnd));
    plan->dispatcher_type = rnd[0] % 3;
    plan->state_xor_key   = (int)rnd[1] ^ ((int)rnd[2] << 8);
    plan->state_mul_key   = (int)rnd[3] * 3 + 1;
    plan->state_add_key   = (int)rnd[4] ^ ((int)rnd[5] << 8);
    plan->state_mod       = (total * 3) + 1;

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
 * Dispatcher code generation — 3 patterns
 * All functions produce code indented at +4 from the function body level.
 * ───────────────────────────────────────────────────────────────────────── */

/* ── Pattern 0: Dictionary Dispatcher (indented 4 spaces) ── */
std::string adv_flowflatten_gen_dict_dispatcher(const AdvFlowFlattenPlan *plan,
                                                 const std::string &sv,
                                                 const std::string &dp) {
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
std::string adv_flowflatten_gen_list_dispatcher(const AdvFlowFlattenPlan *plan,
                                                 const std::string &sv,
                                                 const std::string &dp) {
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

    std::string pm = flowflatten_rand_var_name();
    py += "    " + pm + " = [\n";
    for (int i = 0; i < real_count; i++) {
        py += "        " + std::to_string(perm[i]) + ",\n";
    }
    py += "    ]\n";
    free(perm);

    std::string idx_var = flowflatten_rand_var_name();
    py += "    while True:\n";
    py += "        " + idx_var + " = " + pm + "[" + sv + "]\n";
    py += "        " + sv + " = " + dp + "[" + idx_var + "](" + sv + ")\n";
    py += "        if " + sv + " < 0:\n";
    py += "            break\n";
    return py;
}

/* ── Pattern 2: Arithmetic Computed Dispatcher (indented 4 spaces) ── */
std::string adv_flowflatten_gen_arith_dispatcher(const AdvFlowFlattenPlan *plan,
                                                   const std::string &sv,
                                                   const std::string &dp) {
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
