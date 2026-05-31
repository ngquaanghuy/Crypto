#include "crypto/obfuscate.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cctype>
#include <string>
#include <vector>
#include <algorithm>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

/* ── HMAC-SHA256 context-aware name mangling ── */
char *rename_mangle_name(const char *original, int scope_depth,
                         const char *parent_scope, const unsigned char *key,
                         size_t key_len) {
    if (!original || !*original) return strdup("_");

    std::string ctx;
    ctx += std::to_string(scope_depth);
    ctx += ":";
    ctx += parent_scope ? parent_scope : "";
    ctx += ":";
    ctx += original;

    unsigned char digest[32];
    unsigned int digest_len = 32;
    HMAC(EVP_sha256(), key, (int)key_len,
         reinterpret_cast<const unsigned char *>(ctx.data()), ctx.size(),
         digest, &digest_len);

    char hex[65];
    for (int i = 0; i < 12; i++)
        snprintf(hex + i * 2, 3, "%02x", digest[i]);
    hex[24] = '\0';

    char *result = (char *)malloc(26);
    if (!result) return nullptr;
    result[0] = '_';
    memcpy(result + 1, hex, 24);
    result[25] = '\0';
    return result;
}

/* ── Rename table management ── */
void rename_table_init(RenameTable *tbl, size_t initial_cap) {
    if (!tbl) return;
    tbl->entries = (RenameEntry *)calloc(initial_cap, sizeof(RenameEntry));
    tbl->count = 0;
    tbl->capacity = initial_cap;
}

void rename_table_free(RenameTable *tbl) {
    if (!tbl) return;
    for (size_t i = 0; i < tbl->count; i++) {
        free(tbl->entries[i].original_name);
        free(tbl->entries[i].mangled_name);
        free(tbl->entries[i].parent_scope);
    }
    free(tbl->entries);
    tbl->entries = nullptr;
    tbl->count = 0;
    tbl->capacity = 0;
}

const char *rename_register(RenameTable *tbl, const char *original,
                            int scope_depth, const char *parent_scope,
                            const unsigned char *key, size_t key_len) {
    if (!tbl || !original) return nullptr;

    /* Deduplicate by (original, scope_depth, parent_scope) */
    for (size_t i = 0; i < tbl->count; i++) {
        if (strcmp(tbl->entries[i].original_name, original) == 0 &&
            tbl->entries[i].scope_depth == scope_depth) {
            if (!parent_scope && !tbl->entries[i].parent_scope) return tbl->entries[i].mangled_name;
            if (parent_scope && tbl->entries[i].parent_scope &&
                strcmp(tbl->entries[i].parent_scope, parent_scope) == 0)
                return tbl->entries[i].mangled_name;
        }
    }

    if (tbl->count >= tbl->capacity) {
        size_t new_cap = tbl->capacity ? tbl->capacity * 2 : 64;
        RenameEntry *new_entries = (RenameEntry *)realloc(tbl->entries, new_cap * sizeof(RenameEntry));
        if (!new_entries) return nullptr;
        tbl->entries = new_entries;
        tbl->capacity = new_cap;
    }

    size_t idx = tbl->count++;
    tbl->entries[idx].original_name = strdup(original);
    tbl->entries[idx].scope_depth = scope_depth;
    tbl->entries[idx].parent_scope = parent_scope ? strdup(parent_scope) : nullptr;
    tbl->entries[idx].mangled_name = rename_mangle_name(original, scope_depth, parent_scope, key, key_len);

    return tbl->entries[idx].mangled_name;
}

int rename_generate_decoys(RenameTable *tbl, int count,
                           const unsigned char *key, size_t key_len) {
    static const char *decoy_names[] = {
        "temp", "data", "value", "result", "buffer",
        "counter", "index", "total", "cache", "helper",
        "handler", "callback", "context", "session", "manager",
        nullptr
    };
    int generated = 0;
    for (int i = 0; i < count && decoy_names[i % 15]; i++) {
        const char *name = decoy_names[i % 15];
        int depth = (i % 3) + 1;
        char parent[32];
        snprintf(parent, sizeof(parent), "_decoy_scope_%d", i / 3);

        const char *mangled = rename_register(tbl, name, depth, parent, key, key_len);
        if (mangled) generated++;
    }
    return generated;
}

void rename_shuffle_table(RenameTable *tbl) {
    if (!tbl || tbl->count < 2) return;
    /* Fisher-Yates shuffle on the mangled_name field only */
    unsigned char seed_buf[32];
    RAND_bytes(seed_buf, sizeof(seed_buf));
    uint64_t seed = 0;
    for (int i = 0; i < 8; i++) seed = (seed << 8) | seed_buf[i];

    for (size_t i = tbl->count - 1; i > 0; i--) {
        size_t j = seed % (i + 1);
        seed /= (i + 1);
        /* Swap mangled names */
        char *tmp = tbl->entries[i].mangled_name;
        tbl->entries[i].mangled_name = tbl->entries[j].mangled_name;
        tbl->entries[j].mangled_name = tmp;
    }
}

/* ── Generate Python rename script ── */
char *rename_generate_python(const char *input_source,
                             const RenameTable *tbl) {
    if (!input_source || !tbl) return nullptr;

    std::string py;
    py.reserve(8192);

    py += "import ast, sys, copy\n\n";

    /* Build a Python rename transformer using the table */
    py += "class _Renamer(ast.NodeTransformer):\n";
    py += "    def __init__(self, name_map):\n";
    py += "        self.name_map = name_map\n";
    py += "        self.imported = set()\n";
    py += "    def _get(self, old, scope=''):\n";
    py += "        return self.name_map.get((old, scope), old)\n";
    py += "    def visit_FunctionDef(self, node):\n";
    py += "        scope = node.name\n";
    py += "        if (node.name, '') in self.name_map:\n";
    py += "            node.name = self.name_map[(node.name, '')]\n";
    py += "        self.generic_visit(node)\n";
    py += "        return node\n";
    py += "    def visit_AsyncFunctionDef(self, node):\n";
    py += "        return self.visit_FunctionDef(node)\n";
    py += "    def visit_Name(self, node):\n";
    py += "        if (node.id, '') in self.name_map and node.id not in self.imported:\n";
    py += "            node.id = self.name_map[(node.id, '')]\n";
    py += "        return node\n";
    py += "    def visit_arg(self, node):\n";
    py += "        if (node.arg, '') in self.name_map:\n";
    py += "            node.arg = self.name_map[(node.arg, '')]\n";
    py += "        return node\n";
    py += "    def visit_Import(self, node):\n";
    py += "        for a in node.names:\n";
    py += "            self.imported.add(a.asname or a.name.split('.')[0])\n";
    py += "        return node\n";
    py += "    def visit_ImportFrom(self, node):\n";
    py += "        for a in node.names:\n";
    py += "            self.imported.add(a.asname or a.name)\n";
    py += "        return node\n";
    py += "\n";

    /* Generate the name map as a Python dict literal */
    py += "_MAP = {\n";
    for (size_t i = 0; i < tbl->count; i++) {
        std::string esc_orig;
        for (const char *p = tbl->entries[i].original_name; *p; p++) {
            if (*p == '\'') esc_orig += "\\'";
            else esc_orig += *p;
        }
        py += "    ('" + esc_orig + "', '" +
              (tbl->entries[i].parent_scope ? tbl->entries[i].parent_scope : "") +
              "'): '" + (tbl->entries[i].mangled_name ? tbl->entries[i].mangled_name + 1 : "X") + "',\n";
    }
    /* Also add decoys that map to nothing (never used) */
    py += "}\n\n";

    py += "def _rename_source(source):\n";
    py += "    try:\n";
    py += "        tree = ast.parse(source)\n";
    py += "        tree = _Renamer(_MAP).visit(tree)\n";
    py += "        ast.fix_missing_locations(tree)\n";
    py += "        return ast.unparse(tree)\n";
    py += "    except SyntaxError as e:\n";
    py += "        sys.stderr.write(f'[obf] rename error: {e}\\n')\n";
    py += "        return source\n";
    py += "\n";

    /* Escape the input source for embedding */
    std::string escaped;
    escaped.reserve(strlen(input_source) * 2);
    for (const char *p = input_source; *p; p++) {
        if (*p == '\\') escaped += "\\\\";
        else if (*p == '\'') escaped += "\\'";
        else if (*p == '\n') escaped += "\\n";
        else if (*p == '\r') escaped += "\\r";
        else escaped += *p;
    }

    py += "import sys\n";
    py += "source = '''" + escaped + "'''\n";
    py += "sys.stdout.write(_rename_source(source))\n";

    return strdup(py.c_str());
}