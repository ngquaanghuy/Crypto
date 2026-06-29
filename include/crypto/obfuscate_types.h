#ifndef CRYPTO_OBFUSCATE_TYPES_H
#define CRYPTO_OBFUSCATE_TYPES_H

#include "crypto/common.h"
#include <stddef.h>

typedef struct {
    int use_rename;
    int use_flowflatten;
    int use_junk;
    int use_xorgenc;
    int use_antidebug;
    int use_decoys;
    int shuffle_order;
    int num_junk_statements;
    int num_decoys;
    int flowflatten_blocks;
    float density;
    const char *input_source;
    const unsigned char *master_key;
    size_t master_key_len;
    int seed;
} ObfuscateConfig;

void obfuscate_config_default(ObfuscateConfig *cfg);

char *obfuscate_apply_technique(const char *technique,
                                const char *source,
                                const unsigned char *key,
                                size_t key_len,
                                int count = 10,
                                int decoy_count = 8,
                                int block_count = 4);

char *obfuscate_pipeline(const ObfuscateConfig *cfg);

#endif /* CRYPTO_OBFUSCATE_TYPES_H */
