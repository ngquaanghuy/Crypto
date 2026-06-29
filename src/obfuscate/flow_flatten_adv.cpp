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

static int rand_range(int lo, int hi) {
    if (lo >= hi) return lo;
    unsigned char buf;
    RAND_bytes(&buf, 1);
    return lo + (buf % (hi - lo + 1));
}

/* ─────────────────────────────────────────────────────────────────────────
 * Main code generator
 * ───────────────────────────────────────────────────────────────────────── */

char *adv_flowflatten_generate_python(const AdvFlowFlattenPlan *plan) {
    if (!plan || plan->num_blocks < 2) return nullptr;

    std::string py;
    py.reserve(32768);

    std::string sv  = flowflatten_rand_var_name();
    std::string dp  = flowflatten_rand_var_name();
    std::string ef  = flowflatten_rand_var_name();

    py += "import hashlib as " + flowflatten_rand_var_name() + "\n";
    py += "import sys as " + flowflatten_rand_var_name() + "\n\n";

    py += ef + " = lambda _s: (_s ^ " + std::to_string(plan->state_xor_key) + ")\n";
    py += "\n";

    py += "def _b_exit(_s):\n";
    py += "    return -1\n";
    py += "\n";

    for (int i = 0; i < plan->num_blocks; i++) {
        if (plan->blocks[i].dead_block || !plan->blocks[i].block_code) continue;
        int sid = plan->blocks[i].state_id;

        py += "def _b" + std::to_string(sid) + "(_st):\n";
        adv_flowflatten_append_block_code(py, plan->blocks[i].block_code, "    ");

        if (plan->blocks[i].logical_next >= 0 &&
            plan->blocks[i].logical_next != plan->blocks[i].state_id) {
            py += "    return " + std::to_string(plan->blocks[i].logical_next) + "\n";
        } else {
            py += "    return -1\n";
        }
        py += "\n";
    }

    for (int i = 0; i < plan->num_blocks; i++) {
        if (!plan->blocks[i].dead_block || !plan->blocks[i].block_code) continue;
        std::string db_name = flowflatten_rand_var_name();
        py += "def " + db_name + "(" + flowflatten_rand_var_name() + "):\n";
        adv_flowflatten_append_block_code(py, plan->blocks[i].block_code, "    ");
        py += "    return " + std::to_string(rand_range(0, 99999)) + "\n";
        py += "\n";
    }

    std::string main_fn = flowflatten_rand_var_name();
    py += "def " + main_fn + "():\n";
    py += "    " + sv + " = 0\n";
    py += "    " + flowflatten_rand_var_name() + " = 0\n";
    py += "\n";

    switch (plan->dispatcher_type) {
        case 0: py += adv_flowflatten_gen_dict_dispatcher(plan, sv, dp); break;
        case 1: py += adv_flowflatten_gen_list_dispatcher(plan, sv, dp); break;
        case 2: py += adv_flowflatten_gen_arith_dispatcher(plan, sv, dp); break;
        default: py += adv_flowflatten_gen_dict_dispatcher(plan, sv, dp); break;
    }

    unsigned char opaque_cnt;
    RAND_bytes(&opaque_cnt, 1);
    int num_opaques = 1 + (opaque_cnt % 3);
    for (int oi = 0; oi < num_opaques; oi++) {
        char *opaque = flowflatten_opaque_predicate();
        std::string ov = flowflatten_rand_var_name();
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
