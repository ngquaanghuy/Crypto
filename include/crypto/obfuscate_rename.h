#ifndef CRYPTO_OBFUSCATE_RENAME_H
#define CRYPTO_OBFUSCATE_RENAME_H

#include "crypto/common.h"
#include <stddef.h>

typedef struct {
    char *original_name;
    char *mangled_name;
    int   scope_depth;
    char *parent_scope;
} RenameEntry;

typedef struct {
    RenameEntry *entries;
    size_t       count;
    size_t       capacity;
} RenameTable;

void        rename_table_init(RenameTable *tbl, size_t capacity);
const char *rename_register(RenameTable *tbl, const char *name,
                            int scope_id, const char *scope_name,
                            const unsigned char *key, size_t key_len);
int         rename_generate_decoys(RenameTable *tbl, int count,
                                   const unsigned char *key, size_t key_len);
void        rename_shuffle_table(RenameTable *tbl);
char       *rename_generate_python(const char *source,
                                   const RenameTable *tbl);
void        rename_table_free(RenameTable *tbl);
char       *rename_mangle_name(const char *name, int scope_id,
                               const char *scope_name,
                               const unsigned char *key, size_t key_len);

#endif /* CRYPTO_OBFUSCATE_RENAME_H */
