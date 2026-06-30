#include "cli/cli_parse.h"
#include "crypto/common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <openssl/rand.h>

char *generate_key(int len) {
    static const char cs[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    static const int cs_len = (int)(sizeof(cs) - 1);
    static const int max_valid = (256 / cs_len) * cs_len;

    char *key = (char *)malloc((size_t)len + 1);
    if (!key) return NULL;

    unsigned char byte;
    for (int i = 0; i < len; i++) {
        do {
            if (RAND_bytes(&byte, 1) != 1) { free(key); return NULL; }
        } while (byte >= max_valid);
        key[i] = cs[byte % cs_len];
    }
    key[len] = '\0';
    return key;
}

Algorithm parse_algorithm(const char *name) {
    if (strcmp(name, "base64")  == 0) return ALGO_BASE64;
    if (strcmp(name, "base32")  == 0) return ALGO_BASE32;
    if (strcmp(name, "base85")  == 0) return ALGO_BASE85;
    if (strcmp(name, "ascii85") == 0) return ALGO_ASCII85;
    if (strcmp(name, "hex")     == 0) return ALGO_HEX;
    if (strcmp(name, "xor")      == 0) return ALGO_XOR;
    if (strcmp(name, "rolling-xor") == 0) return ALGO_ROLLING_XOR;
    if (strcmp(name, "xor-bit-rotation") == 0) return ALGO_XOR_BIT_ROTATION;
    if (strcmp(name, "multi-pass-xor") == 0) return ALGO_MULTI_PASS_XOR;
    if (strcmp(name, "prng-xor") == 0) return ALGO_PRNG_XOR;
    if (strcmp(name, "aes-ecb")  == 0) return ALGO_AES_ECB;
    if (strcmp(name, "aes-cbc")  == 0) return ALGO_AES_CBC;
    if (strcmp(name, "aes-ctr")  == 0) return ALGO_AES_CTR;
    if (strcmp(name, "aes-gcm")  == 0) return ALGO_AES_GCM;
    if (strcmp(name, "aes")      == 0) return ALGO_AES_GCM;
    if (strcmp(name, "chacha20")  == 0) return ALGO_CHACHA20;
    if (strcmp(name, "chacha20-poly1305")  == 0) return ALGO_CHACHA20_POLY1305;
    if (strcmp(name, "xchacha20-poly1305")  == 0) return ALGO_XCHACHA20_POLY1305;
    return ALGO_NONE;
}

const char *default_output(const char *input, const char *suffix) {
    const char *dot = strrchr(input, '.');
    if (!dot) dot = input + strlen(input);

    size_t len = (size_t)(dot - input) + strlen(suffix) + 1;
    char *out = (char *)malloc(len);
    if (!out) return NULL;

    snprintf(out, len, "%.*s%s", (int)(dot - input), input, suffix);
    return out;
}

int is_valid_obf_techniques(const char *s) {
    if (!s || !*s) return 0;
    char buf[256];
    size_t sl = strlen(s);
    if (sl >= sizeof(buf)) return 0;
    memcpy(buf, s, sl + 1);
    const char *valid[] = {"rename","strings","vstrings","cleanup",
                                "flow","aflow","opaque","junk","mutate",
                                "mba","apihash","funcenc","rolling-xor",
                                "xor-bit-rotation","multi-pass-xor","prng-xor","all", NULL};

    char *tok = strtok(buf, ",");
    if (!tok) return 0;
    while (tok) {
        int ok = 0;
        for (int i = 0; valid[i]; i++) {
            if (strcmp(tok, valid[i]) == 0) { ok = 1; break; }
        }
        if (!ok) return 0;
        tok = strtok(NULL, ",");
    }
    return 1;
}

const char *build_except_techniques(const char *exclude) {
    static std::string buf;
    const char *valid[] = {"rename","strings","vstrings","cleanup",
                                "flow","aflow","opaque","junk","mutate",
                                "mba","apihash","funcenc","rolling-xor",
                                "xor-bit-rotation","multi-pass-xor","prng-xor","all", NULL};

    buf.clear();
    int first = 1;
    for (int i = 0; valid[i]; i++) {
        if (strcmp(valid[i], "all") == 0) continue;
        if (strcmp(valid[i], exclude) == 0) continue;
        if (!first) buf += ",";
        buf += valid[i];
        first = 0;
    }
    return buf.c_str();
}

CommandMode parse_command(const char *arg) {
    if (strcmp(arg, "encode") == 0)  return MODE_ENCODE;
    if (strcmp(arg, "decode") == 0)  return MODE_DECODE;
    if (strcmp(arg, "encrypt") == 0) return MODE_ENCRYPT;
    if (strcmp(arg, "decrypt") == 0) return MODE_DECRYPT;
    if (strcmp(arg, "protect") == 0) return MODE_PROTECT;
    return MODE_UNKNOWN;
}

Algorithm default_algo_for_mode(CommandMode mode) {
    switch (mode) {
        case MODE_ENCODE:
        case MODE_DECODE:  return ALGO_BASE64;
        case MODE_ENCRYPT:
        case MODE_DECRYPT:
        case MODE_PROTECT:  return ALGO_AES_GCM;
        default:           return ALGO_NONE;
    }
}

char *read_key_from_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "error: cannot open keyfile '%s'\n", path); return NULL; }

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);

    if (sz <= 0) { fclose(f); fprintf(stderr, "error: keyfile '%s' is empty\n", path); return NULL; }

    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }

    size_t nread = fread(buf, 1, (size_t)sz, f);
    fclose(f);

    if ((long)nread != sz) { free(buf); fprintf(stderr, "error: failed to read keyfile '%s'\n", path); return NULL; }

    while (sz > 0 && (buf[sz - 1] == '\n' || buf[sz - 1] == '\r' || buf[sz - 1] == ' ' || buf[sz - 1] == '\t'))
        sz--;
    buf[sz] = '\0';

    if (sz == 0) { free(buf); fprintf(stderr, "error: keyfile '%s' is empty (after trim)\n", path); return NULL; }

    return buf;
}
