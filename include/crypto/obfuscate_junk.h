#ifndef CRYPTO_OBFUSCATE_JUNK_H
#define CRYPTO_OBFUSCATE_JUNK_H

#include "crypto/common.h"

typedef struct {
    char **variable_names;
    int    num_variables;
    int    include_side_effects;
    int    include_both_branches;
} JunkConfig;

void  junk_config_default(JunkConfig *cfg);
char *junk_generate_statement(const JunkConfig *cfg);
char *junk_generate_ifelse_block(const JunkConfig *cfg);
char *junk_generate_function(const JunkConfig *cfg);
char *junk_generate_section(const JunkConfig *cfg, int count);

#endif /* CRYPTO_OBFUSCATE_JUNK_H */
