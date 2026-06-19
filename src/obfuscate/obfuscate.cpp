#include "crypto/obfuscate.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <algorithm>
#include <openssl/rand.h>

/* ── Default configuration ── */
void obfuscate_config_default(ObfuscateConfig *cfg) {
    if (!cfg) return;
    cfg->use_rename = 1;
    cfg->use_flowflatten = 1;
    cfg->use_junk = 1;
    cfg->use_xorgenc = 1;
    cfg->use_antidebug = 1;
    cfg->use_decoys = 1;
    cfg->shuffle_order = 1;
    cfg->num_junk_statements = 30;
    cfg->num_decoys = 20;
    cfg->flowflatten_blocks = 10;
    cfg->density = 1.0f;
    cfg->input_source = nullptr;
    cfg->master_key = nullptr;
    cfg->master_key_len = 0;
    cfg->seed = -1;
}

/* ── Apply a single technique by name ── */
char *obfuscate_apply_technique(const char *technique,
                                const char *source,
                                const unsigned char *key,
                                size_t key_len,
                                int count,
                                int decoy_count,
                                int block_count) {
    if (!technique || !source) return strdup(source ? source : "");

    unsigned char local_key[32];
    if (!key || key_len == 0) {
        RAND_bytes(local_key, sizeof(local_key));
        key = local_key;
        key_len = sizeof(local_key);
    }

    if (strcmp(technique, "antidebug") == 0) {
        char *stub = anti_debug_generate_stub(1, 1);
        if (!stub) return strdup(source);
        std::string result = std::string(stub) + "\n" + source;
        free(stub);
        return strdup(result.c_str());
    }

    if (strcmp(technique, "rename") == 0) {
        RenameTable tbl;
        rename_table_init(&tbl, 64);

        /* Find and register all identifiers */
        std::string src(source);
        std::vector<std::string> words;
        std::string cur;
        for (size_t i = 0; i < src.size(); i++) {
            char c = src[i];
            if (isalnum(c) || c == '_') {
                cur += c;
            } else {
                if (!cur.empty()) {
                    if (isalpha(cur[0]) || cur[0] == '_') {
                        words.push_back(cur);
                    }
                    cur.clear();
                }
            }
        }
        if (!cur.empty() && (isalpha(cur[0]) || cur[0] == '_'))
            words.push_back(cur);

        /* Deduplicate and register */
        std::sort(words.begin(), words.end());
        words.erase(std::unique(words.begin(), words.end()), words.end());

        static const char *skip_words[] = {
            "import", "def", "class", "return", "if", "elif", "else",
            "for", "while", "try", "except", "finally", "with", "as",
            "from", "pass", "break", "continue", "raise", "yield",
            "lambda", "and", "or", "not", "in", "is", "True", "False",
            "None", "print", "range", "len", "str", "int", "float",
            "list", "dict", "tuple", "set", "type", "isinstance",
            "hasattr", "getattr", "setattr", "open", "read", "write",
            "global", "nonlocal", "del", "assert", "async", "await",
            "self", "cls", "super", "property", "staticmethod",
            "classmethod", nullptr
        };

        for (const auto &w : words) {
            int skip = 0;
            for (int i = 0; skip_words[i]; i++) {
                if (w == skip_words[i]) { skip = 1; break; }
            }
            if (w.size() >= 2 && w[0] == '_' && w[1] == '_') skip = 1;
            if (!skip) {
                rename_register(&tbl, w.c_str(), 0, "", key, key_len);
            }
        }

        if (1) { /* use_decoys */
            rename_generate_decoys(&tbl, decoy_count, key, key_len);
        }
        if (1) { /* shuffle */
            rename_shuffle_table(&tbl);
        }

        char *result = rename_generate_python(source, &tbl);
        rename_table_free(&tbl);
        if (!result) return strdup(source);
        return result;
    }

    if (strcmp(technique, "flowflatten") == 0) {
        FlowFlattenPlan plan;
        flowflatten_plan_init(&plan, block_count);

        for (int bi = 0; bi < plan.num_blocks - 1; bi++) {
            char label[32];
            snprintf(label, sizeof(label), "pass  # block %d", bi);
            flowflatten_set_block(&plan, bi, label, bi + 1);
        }
        char final_label[32];
        snprintf(final_label, sizeof(final_label), "pass  # block %d (terminal)", plan.num_blocks - 1);
        flowflatten_set_block(&plan, plan.num_blocks - 1, final_label, -1);

        char *result = flowflatten_generate_python(&plan, plan.key, 32);
        flowflatten_plan_free(&plan);
        if (!result) return strdup(source);

        /* Append: execute the flattened source after the original */
        std::string full = std::string(result) + "\n\n# Original source:\n" + source;
        free(result);
        return strdup(full.c_str());
    }

    if (strcmp(technique, "aflow") == 0) {
        float density = (float)count / 10.0f; // map junk count (10-30) to density (1-3)
        if (density < 0.5f) density = 0.5f;
        if (density > 5.0f) density = 5.0f;
        char *result = adv_flowflatten_wrap_source(source, block_count, density);
        if (!result) return strdup(source);

        std::string full = std::string(result) + "\n\n# Original source:\n" + source;
        free(result);
        return strdup(full.c_str());
    }

    if (strcmp(technique, "junk") == 0) {
        JunkConfig cfg;
        junk_config_default(&cfg);
        cfg.include_side_effects = (count > 20) ? 1 : 0;
        cfg.include_both_branches = (count > 50) ? 1 : 0;
        char *section = junk_generate_section(&cfg, count);
        if (!section) return strdup(source);
        std::string result = std::string(section) + "\n" + source;
        free(section);
        return strdup(result.c_str());
    }

    if (strcmp(technique, "xorgenc") == 0) {
        unsigned char derived_key[32];
        if (key_len >= 32) {
            memcpy(derived_key, key, 32);
        } else {
            RAND_bytes(derived_key, 32);
        }
        char *stub = xorgen_generate_python_stub(
            (const unsigned char *)source, strlen(source),
            derived_key, 32);
        if (!stub) return strdup(source);
        return stub;
    }

    if (strcmp(technique, "xor-stub") == 0) {
        unsigned char derived_key[32];
        if (key_len >= 32) {
            memcpy(derived_key, key, 32);
        } else {
            RAND_bytes(derived_key, 32);
        }
        char *stub = xorgen_generate_xor_stub(
            (const unsigned char *)source, strlen(source),
            derived_key, 32);
        if (!stub) return strdup(source);
        return stub;
    }

    return strdup(source);
}

/* ── Main pipeline ── */
char *obfuscate_pipeline(const ObfuscateConfig *cfg) {
    if (!cfg || !cfg->input_source) {
        const char *err = "error: obfuscate_pipeline: no input source\n";
        return strdup(err);
    }

    /* Setup random seed if provided */
    if (cfg->seed >= 0) {
        srand((unsigned int)cfg->seed);
    }

    std::string current_source = cfg->input_source;
    unsigned char pipeline_key[32];
    if (cfg->master_key && cfg->master_key_len >= 32) {
        memcpy(pipeline_key, cfg->master_key, 32);
    } else {
        RAND_bytes(pipeline_key, sizeof(pipeline_key));
    }

    /* Define pipeline order */
    struct Stage {
        const char *name;
        int enabled;
    };
    Stage stages[] = {
        {"antidebug",  cfg->use_antidebug},
        {"rename",     cfg->use_rename},
        {"flowflatten", cfg->use_flowflatten},
        {"junk",       cfg->use_junk},
        {"xorgenc",    cfg->use_xorgenc},
    };
    int num_stages = sizeof(stages) / sizeof(stages[0]);

    /* Optionally shuffle stage order */
    int order[8];
    for (int i = 0; i < num_stages; i++) order[i] = i;
    if (cfg->shuffle_order) {
        for (int i = num_stages - 1; i > 0; i--) {
            int j = rand() % (i + 1);
            int tmp = order[i];
            order[i] = order[j];
            order[j] = tmp;
        }
    }

    int density_extra = cfg->density > 1.0f ? (int)(cfg->density + 0.5f) : 1;

    for (int pass = 0; pass < density_extra; pass++) {
        for (int si = 0; si < num_stages; si++) {
            int idx = order[si];
            if (!stages[idx].enabled) continue;

            int count = (int)(cfg->num_junk_statements * cfg->density);
            int decoys = (int)(cfg->num_decoys * cfg->density);
            int blocks = (int)(cfg->flowflatten_blocks * cfg->density);
            if (count < 1) count = 1;
            if (decoys < 1) decoys = 1;
            if (blocks < 2) blocks = 2;

            char *result = obfuscate_apply_technique(
                stages[idx].name,
                current_source.c_str(),
                pipeline_key, sizeof(pipeline_key),
                count, decoys, blocks);

            if (result) {
                current_source = result;
                free(result);
            }
        }
    }

    return strdup(current_source.c_str());
}