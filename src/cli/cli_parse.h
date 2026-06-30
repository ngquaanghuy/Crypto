#ifndef CRYPTO_CLI_PARSE_H
#define CRYPTO_CLI_PARSE_H

#include "crypto/common.h"

char *generate_key(int len);
Algorithm parse_algorithm(const char *name);
CommandMode parse_command(const char *arg);
Algorithm default_algo_for_mode(CommandMode mode);
const char *default_output(const char *input, const char *suffix);
int is_valid_obf_techniques(const char *s);
const char *build_except_techniques(const char *exclude);
char *read_key_from_file(const char *path);

#endif
