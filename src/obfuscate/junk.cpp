#include "crypto/obfuscate.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <algorithm>
#include <openssl/rand.h>

/* ── Junk templates ── */

/* Side-effect junk: memory ops that waste time but are safe */
static const char *side_effect_templates[] = {
    "_tmp = [None for _ in range(%d)]\n_ = _tmp[0] if _tmp else None\n",
    "_tmp = list(range(%d))\n_random.shuffle(_tmp)\n_ = _tmp[0] if _tmp else None\n",
    "_tmp = {str(_): _ for _ in range(%d)}\n_ = _tmp.get('0', None)\n",
    "_tmp = bytearray(%d)\nfor _i in range(len(_tmp)):\n    _tmp[_i] = (_i * 7 + 3) & 0xFF\n_ = bytes(_tmp)\n",
};

/* Context-independent junk (no variable references) */
static const char *simple_junk_templates[] = {
    "_ = (lambda _x: _x and not _x)(None)\n",
    "_ = [x for x in ()] == []\n",
    "_ = (lambda: sorted([3,1,2]) == [1,2,3])()\n",
    "_ = all([]) and not any([False])\n",
    "_ = str(bin(42)) == '0b101010'\n",
};

/* Template for if/else junk blocks */
static const char *if_else_template =
    "if %.17g < 0 or str(%d) == str(%d):\n"
    "    _junk_result = [x for x in range(%d) if x %% 2 == 0]\n"
    "    _junk_output = sum(_junk_result) - sum(_junk_result)\n"
    "else:\n"
    "    _junk_result = [x for x in range(%d) if x %% 2 == 1]\n"
    "    _junk_output = max(_junk_result) - max(_junk_result)\n"
    "_ = _junk_output\n";

/* Junk function template */
static const char *junk_function_template =
    "def _junk_%04x(_arg):\n"
    "    if not isinstance(_arg, (int, float)):\n"
    "        return None\n"
    "    _tmp = [(_arg + i) %% 65521 for i in range(%d)]\n"
    "    _acc = sum(_tmp) %% 65521\n"
    "    _acc = (_acc * 256 + len(_tmp)) %% 65521\n"
    "    return _acc if _acc > 0 else None\n";

/* ── Default config ── */
void junk_config_default(JunkConfig *cfg) {
    if (!cfg) return;
    cfg->variable_names = nullptr;
    cfg->num_variables = 0;
    cfg->include_side_effects = 1;
    cfg->include_both_branches = 1;
}

/* ── Generate a random integer in [lo, hi] ── */
static int rand_range(int lo, int hi) {
    unsigned char buf[4];
    RAND_bytes(buf, 4);
    uint32_t r = (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) |
                 ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24);
    return lo + (int)(r % (uint32_t)(hi - lo + 1));
}

/* ── Generate a single junk statement ── */
char *junk_generate_statement(const JunkConfig *cfg) {
    if (!cfg) return nullptr;

    unsigned char sel;
    RAND_bytes(&sel, 1);

    std::string result;

    if (cfg->include_side_effects && (sel & 1)) {
        int idx = sel % 4;
        int size = rand_range(4, 64);
        char buf[512];
        snprintf(buf, sizeof(buf), side_effect_templates[idx], size);
        result = buf;
    } else {
        int idx = sel % 5;
        result = simple_junk_templates[idx];
    }

    /* Optionally reference a real variable */
    if (cfg->variable_names && cfg->num_variables > 0 && (sel & 2)) {
        int vi = rand_range(0, cfg->num_variables - 1);
        result += std::string("_ = isinstance(") +
                  cfg->variable_names[vi] +
                  ", type(" + cfg->variable_names[vi] + "))\n";
    }

    return strdup(result.c_str());
}

/* ── Generate if/else junk block ── */
char *junk_generate_ifelse_block(const JunkConfig *cfg) {
    if (!cfg) return nullptr;

    char buf[1024];
    int a = rand_range(1, 10000);
    int b = rand_range(1, 10000);
    int size1 = rand_range(2, 32);
    int size2 = rand_range(2, 32);

    snprintf(buf, sizeof(buf), if_else_template,
             (double)rand_range(0, 1000000) / 1000.0,
             a, b, size1, size2);
    return strdup(buf);
}

/* ── Generate junk function ── */
char *junk_generate_function(const JunkConfig *cfg) {
    if (!cfg) return nullptr;

    char buf[1024];
    unsigned char rnd[2];
    RAND_bytes(rnd, 2);
    uint16_t tag = (uint16_t)rnd[0] | ((uint16_t)rnd[1] << 8);
    int size = rand_range(8, 128);

    snprintf(buf, sizeof(buf), junk_function_template, (unsigned int)tag, size);
    return strdup(buf);
}

/* ── Generate full junk section ── */
char *junk_generate_section(const JunkConfig *cfg, int count) {
    if (!cfg || count < 1) return nullptr;

    std::string result;
    result.reserve(count * 256);

    /* Start with a junk function definition */
    char *func = junk_generate_function(cfg);
    if (func) {
        result += func;
        result += "\n";
        free(func);
    }

    /* Add junk statements */
    for (int i = 0; i < count; i++) {
        unsigned char sel;
        RAND_bytes(&sel, 1);

        if (cfg->include_both_branches && (sel & 1)) {
            char *block = junk_generate_ifelse_block(cfg);
            if (block) {
                result += block;
                result += "\n";
                free(block);
            }
        } else {
            char *stmt = junk_generate_statement(cfg);
            if (stmt) {
                result += stmt;
                free(stmt);
            }
        }
    }

    return strdup(result.c_str());
}