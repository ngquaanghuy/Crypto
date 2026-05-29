#include "cli/cli.h"
#include "cli/protect.h"
#include "crypto/common.h"
#include "crypto/compress.h"
#include "encode/encoder.h"
#include "crypto/cipher.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/rand.h>

static char *generate_key(int len) {
    static const char cs[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    char *key = (char *)malloc((size_t)len + 1);
    if (!key) return NULL;
    unsigned char *buf = (unsigned char *)malloc((size_t)len);
    if (!buf) { free(key); return NULL; }
    if (RAND_bytes(buf, len) != 1) { free(buf); free(key); return NULL; }
    for (int i = 0; i < len; i++)
        key[i] = cs[buf[i] % (sizeof(cs) - 1)];
    key[len] = '\0';
    free(buf);
    return key;
}

static void print_usage(void) {
    printf("Usage: crypto [options] <command> [<args>]\n");
    printf("\n");
    printf("Commands:\n");
    printf("  encode <file>       Encode Python source file\n");
    printf("  decode <file>       Decode encoded file\n");
    printf("  encrypt <file>      Encrypt Python source file\n");
    printf("  decrypt <file>      Decrypt encrypted file\n");
    printf("  protect <file>      Encrypt + package into self-decrypting Python script\n");
    printf("\n");
    printf("Options:\n");
    printf("  -a, --algorithm <algo>  Algorithm: base64, base32, base85,\n");
    printf("                          ascii85, hex, xor, rolling-xor, xor-bit-rotation,\n");
    printf("                          multi-pass-xor, prng-xor,\n");
    printf("                          aes-ecb, aes-cbc, aes-ctr, aes-gcm, chacha20\n");
    printf("                          (default: aes-gcm for encrypt/protect)\n");
    printf("  -k, --key <key>         Encryption/encoding key\n");
    printf("      --keyfile <file>    Read key from file\n");
    printf("      --keyenv <var>      Read key from environment variable\n");
    printf("      --keygen [<len>]    Generate random key (default 32, max 1024)\n");
    printf("      --obf <tech>        Obfuscation techniques: rename,strings,\n");
    printf("                          vstrings,cleanup,flow,aflow,opaque,\n");
    printf("                          mutate,mba,junk,apihash,funcenc,\n");
    printf("                          rolling-xor,multi-pass-xor,prng-xor,all\n");
    printf("                          (comma-separated, protect only)\n");
    printf("\n");
    printf("      --obf-none <tech>   Enable all obfuscation EXCEPT <tech>\n");
    printf("                          (mutually exclusive with --obf)\n");
    printf("      --anti-analysis <t> Anti-analysis protection: debug,\n");
    printf("                          hook, scramble, opaque (comma-separated,\n");
    printf("                          protect only)\n");
    printf("      --compress <algo>   Compression algorithm: zlib, lzma, bz2,\n");
    printf("                          brotli, zstd, gzip, lz4, snappy,\n");
    printf("                          zopfli, blosc (default: zlib for protect,\n");
    printf("                          none for encode/encrypt)\n");
    printf("      --compress-level <n> Compression level (1-9, default 6)\n");
    printf("      --no-compress       Disable compression\n");
    printf("      --vm                Enable Register VM protection\n");
    printf("                          (when --vm is active, --obf all uses\n");
    printf("                          full obfuscation via code-split pipeline)\n");
    printf("  -o, --output <file>     Output file\n");
    printf("  -v, --version           Show version\n");
    printf("  -h, --help              Show this help\n");
    printf("\n");
    printf("Key priority: -k > --keygen > --keyfile > --keyenv > built-in default\n");
}

static void print_version(void) {

    printf("%s v%s\n", CRYPTO_NAME, CRYPTO_VERSION);
}

static Algorithm parse_algorithm(const char *name) {
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
    return ALGO_NONE;
}


static const char *algo_name(Algorithm algo) {
    switch (algo) {
        case ALGO_BASE64:  return "base64";
        case ALGO_BASE32:  return "base32";
        case ALGO_BASE85:  return "base85";
        case ALGO_ASCII85: return "ascii85";
        case ALGO_HEX:     return "hex";
        case ALGO_XOR:      return "xor";
        case ALGO_ROLLING_XOR: return "rolling-xor";
        case ALGO_XOR_BIT_ROTATION: return "xor-bit-rotation";
        case ALGO_MULTI_PASS_XOR: return "multi-pass-xor";
        case ALGO_PRNG_XOR: return "prng-xor";
        case ALGO_AES_ECB:  return "aes-ecb";
        case ALGO_AES_CBC:  return "aes-cbc";
        case ALGO_AES_CTR:  return "aes-ctr";
        case ALGO_AES_GCM:  return "aes-gcm";
        case ALGO_CHACHA20: return "chacha20";
        default:           return "none";
    }
}

static const char *default_output(const char *input, const char *suffix) {
    const char *dot = strrchr(input, '.');
    if (!dot) dot = input + strlen(input);

    size_t len = (size_t)(dot - input) + strlen(suffix) + 1;
    char *out = (char *)malloc(len);
    if (!out) return NULL;

    snprintf(out, len, "%.*s%s", (int)(dot - input), input, suffix);
    return out;
}

static int is_valid_obf_techniques(const char *s) {
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

static const char *build_except_techniques(const char *exclude) {
    static char buf[256];
    const char *valid[] = {"rename","strings","vstrings","cleanup",
                                "flow","aflow","opaque","junk","mutate",
                                "mba","apihash","funcenc","rolling-xor",
                                "xor-bit-rotation","multi-pass-xor","prng-xor","all", NULL};


    buf[0] = '\0';
    int first = 1;
    for (int i = 0; valid[i]; i++) {
        if (strcmp(valid[i], "all") == 0) continue;
        if (strcmp(valid[i], exclude) == 0) continue;
        if (!first) strcat(buf, ",");
        strcat(buf, valid[i]);
        first = 0;
    }
    return buf;
}

static CommandMode parse_command(const char *arg) {
    if (strcmp(arg, "encode") == 0)  return MODE_ENCODE;
    if (strcmp(arg, "decode") == 0)  return MODE_DECODE;
    if (strcmp(arg, "encrypt") == 0) return MODE_ENCRYPT;
    if (strcmp(arg, "decrypt") == 0) return MODE_DECRYPT;
    if (strcmp(arg, "protect") == 0) return MODE_PROTECT;
    return MODE_UNKNOWN;
}

static Algorithm default_algo_for_mode(CommandMode mode) {
    switch (mode) {
        case MODE_ENCODE:
        case MODE_DECODE:  return ALGO_BASE64;
        case MODE_ENCRYPT:
        case MODE_DECRYPT:
        case MODE_PROTECT:  return ALGO_AES_GCM;
        default:           return ALGO_NONE;
    }
}

static char *read_key_from_file(const char *path) {
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

int cli_run(int argc, char **argv) {
    if (argc < 2) {
        print_usage();
        return EXIT_ERR_ARGS;
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage();
            return EXIT_OK;
        }
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
            print_version();
            return EXIT_OK;
        }
    }

    CommandMode mode = MODE_UNKNOWN;
    Algorithm algo = ALGO_NONE;
    const char *input  = NULL;
    const char *output = NULL;
    const char *key_arg  = NULL;
    const char *keyfile  = NULL;
    const char *keyenv   = NULL;
    const char *obf_tech = NULL;
    const char *obf_none = NULL;
    const char *anti_analysis = NULL;
    int keygen = 0;
    int keylen = 32;
    int compress_algo = COMPRESS_ID_NONE;
    int compress_level = 6;
    int compress_set = 0;
    int use_vm = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "error: -o requires a filename\n"); return EXIT_ERR_ARGS; }
            output = argv[++i];
        } else if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--algorithm") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "error: -a requires an algorithm name\n"); return EXIT_ERR_ARGS; }
            algo = parse_algorithm(argv[++i]);
            if (algo == ALGO_NONE) { fprintf(stderr, "error: unknown algorithm '%s'\n", argv[i]); return EXIT_ERR_ARGS; }
        } else if (strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--key") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "error: -k requires a key\n"); return EXIT_ERR_ARGS; }
            key_arg = argv[++i];
        } else if (strcmp(argv[i], "--keyfile") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "error: --keyfile requires a filename\n"); return EXIT_ERR_ARGS; }
            keyfile = argv[++i];
        } else if (strcmp(argv[i], "--keyenv") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "error: --keyenv requires a variable name\n"); return EXIT_ERR_ARGS; }
            keyenv = argv[++i];
        } else if (strcmp(argv[i], "--keygen") == 0) {
            keygen = 1;
            if (i + 1 < argc && argv[i+1][0] != '-' && parse_command(argv[i+1]) == MODE_UNKNOWN) {
                int n = atoi(argv[++i]);
                if (n < 1 || n > 1024) { fprintf(stderr, "error: key length must be 1-1024\n"); return EXIT_ERR_ARGS; }
                keylen = n;
            }
        } else if (strcmp(argv[i], "--obf") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "error: --obf requires techniques\n"); return EXIT_ERR_ARGS; }
            if (obf_none) {
                fprintf(stderr, "error: --obf and --obf-none are mutually exclusive\n");
                return EXIT_ERR_ARGS;
            }
            const char *tech = argv[++i];
            if (!is_valid_obf_techniques(tech)) {
                fprintf(stderr, "error: invalid --obf techniques '%s'\n", tech);
                return EXIT_ERR_ARGS;
            }

            obf_tech = tech;
        } else if (strcmp(argv[i], "--obf-none") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "error: --obf-none requires a technique\n"); return EXIT_ERR_ARGS; }
            if (obf_tech) {
                fprintf(stderr, "error: --obf-none and --obf are mutually exclusive\n");
                return EXIT_ERR_ARGS;
            }
            const char *tech = argv[++i];
            if (strchr(tech, ',')) {
                fprintf(stderr, "error: --obf-none accepts only one technique (no commas)\n");
                return EXIT_ERR_ARGS;
            }
            if (!is_valid_obf_techniques(tech)) {
                fprintf(stderr, "error: invalid --obf-none technique '%s'\n", tech);
                return EXIT_ERR_ARGS;
            }
            if (strcmp(tech, "all") == 0) {
                fprintf(stderr, "error: --obf-none all would mean no obfuscation; use --obf none\n");
                return EXIT_ERR_ARGS;
            }
            obf_none = tech;
        } else if (strcmp(argv[i], "--anti-analysis") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "error: --anti-analysis requires debug,hook,scramble,opaque\n"); return EXIT_ERR_ARGS; }
            anti_analysis = argv[++i];
        } else if (strcmp(argv[i], "--compress") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "error: --compress requires an algorithm name\n"); return EXIT_ERR_ARGS; }
            const char *name = argv[++i];
            if (strcmp(name, "zlib") == 0)   compress_algo = COMPRESS_ID_ZLIB;
            else if (strcmp(name, "lzma") == 0)  compress_algo = COMPRESS_ID_LZMA;
            else if (strcmp(name, "bz2") == 0)   compress_algo = COMPRESS_ID_BZ2;
            else if (strcmp(name, "brotli") == 0) compress_algo = COMPRESS_ID_BROTLI;
            else if (strcmp(name, "zstd") == 0)  compress_algo = COMPRESS_ID_ZSTD;
            else if (strcmp(name, "gzip") == 0)  compress_algo = COMPRESS_ID_GZIP;
            else if (strcmp(name, "lz4") == 0)   compress_algo = COMPRESS_ID_LZ4;
            else if (strcmp(name, "snappy") == 0) compress_algo = COMPRESS_ID_SNAPPY;
            else if (strcmp(name, "zopfli") == 0) compress_algo = COMPRESS_ID_ZOPFLI;
            else if (strcmp(name, "blosc") == 0)  compress_algo = COMPRESS_ID_BLOSC;
            else if (strcmp(name, "none") == 0)   compress_algo = COMPRESS_ID_NONE;
            else { fprintf(stderr, "error: unknown compression algorithm '%s'\n", name); return EXIT_ERR_ARGS; }
            compress_set = 1;
        } else if (strcmp(argv[i], "--compress-level") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "error: --compress-level requires a number\n"); return EXIT_ERR_ARGS; }
            int n = atoi(argv[++i]);
            if (n < 1 || n > 9) { fprintf(stderr, "error: --compress-level must be 1-9\n"); return EXIT_ERR_ARGS; }
            compress_level = n;
        } else if (strcmp(argv[i], "--no-compress") == 0) {
            compress_algo = COMPRESS_ID_NONE;
            compress_set = 1;
        } else if (strcmp(argv[i], "--vm") == 0) {
            use_vm = 1;
        } else if (argv[i][0] != '-') {
            CommandMode m = parse_command(argv[i]);
            if (mode == MODE_UNKNOWN && m != MODE_UNKNOWN) {
                mode = m;
            } else if (!input) {
                input = argv[i];
            } else {
                fprintf(stderr, "error: unexpected argument '%s'\n", argv[i]);
                return EXIT_ERR_ARGS;
            }
        } else {
            fprintf(stderr, "error: unknown option '%s'\n", argv[i]);
            return EXIT_ERR_ARGS;
        }
    }

    if (mode == MODE_UNKNOWN && keygen) {
        char *k = generate_key(keylen);
        if (!k) { fprintf(stderr, "error: failed to generate key\n"); return EXIT_ERR_CRYPTO; }
        printf("%s\n", k);
        free(k);
        return EXIT_OK;
    }

    if (mode == MODE_UNKNOWN) {
        fprintf(stderr, "error: missing command\n");
        print_usage();
        return EXIT_ERR_ARGS;
    }

    if (!input) {
        fprintf(stderr, "error: missing input file\n");
        return EXIT_ERR_ARGS;
    }

    if (algo == ALGO_NONE)
        algo = default_algo_for_mode(mode);
    if (algo == ALGO_NONE) {
        fprintf(stderr, "error: could not determine algorithm\n");
        return EXIT_ERR_ARGS;
    }

    // Default compression: zlib for protect, none for encode/encrypt
    if (!compress_set) {
        if (mode == MODE_PROTECT)
            compress_algo = COMPRESS_ID_ZLIB;
    }

    const char *key = NULL;
    int key_needs_free = 0;

    if (keygen) {
        key = generate_key(keylen);
        if (!key) { fprintf(stderr, "error: failed to generate key\n"); return EXIT_ERR_CRYPTO; }
        key_needs_free = 1;
        fprintf(stderr, "key: %s\n", key);
    } else if (key_arg) {
        key = key_arg;
    } else if (keyfile) {
        key = read_key_from_file(keyfile);
        if (!key) return EXIT_ERR_FILE;
        key_needs_free = 1;
    } else if (keyenv) {
        key = getenv(keyenv);
        if (!key || key[0] == '\0') {
            fprintf(stderr, "error: environment variable '%s' is not set or empty\n", keyenv);
            return EXIT_ERR_ARGS;
        }
    } else {
        key = CRYPTO_DEFAULT_KEY;
    }

    {
        int needs_key = (algo == ALGO_XOR || algo == ALGO_ROLLING_XOR ||
                         algo == ALGO_MULTI_PASS_XOR ||
                         algo == ALGO_PRNG_XOR ||
                         algo == ALGO_AES_ECB || algo == ALGO_AES_CBC ||
                         algo == ALGO_AES_CTR || algo == ALGO_AES_GCM ||
                         algo == ALGO_CHACHA20);
        if (needs_key && (!key || key[0] == '\0')) {
            fprintf(stderr, "error: no key available for %s\n", algo_name(algo));
            if (key_needs_free) free((char *)key);
            return EXIT_ERR_ARGS;
        }
    }

    const char *suffix = NULL;
    switch (mode) {
        case MODE_ENCODE:  suffix = ".encoded";  break;
        case MODE_DECODE:  suffix = ".decoded";  break;
        case MODE_ENCRYPT: suffix = ".encrypted"; break;
        case MODE_DECRYPT: suffix = ".decrypted"; break;
        case MODE_PROTECT: suffix = ".protected"; break;
        default: break;
    }

    int out_needs_free = 0;
    if (!output && suffix) {
        output = default_output(input, suffix);
        if (!output) { if (key_needs_free) free((char *)key); fprintf(stderr, "error: out of memory\n"); return EXIT_ERR_CRYPTO; }
        out_needs_free = 1;
    }

    ExitCode ret;
    switch (mode) {
        case MODE_ENCODE:  ret = encode_file(input, output, algo, key, compress_algo, compress_level);  break;
        case MODE_DECODE:  ret = decode_file(input, output, algo, key);  break;
        case MODE_ENCRYPT: ret = encrypt_file(input, output, algo, key, compress_algo, compress_level); break;
        case MODE_DECRYPT: ret = decrypt_file(input, output, algo, key); break;
        case MODE_PROTECT: {
            const char *techs = obf_none ? build_except_techniques(obf_none) : obf_tech;
            ret = protect_file(input, output, algo, key, techs,
                               anti_analysis, compress_algo,
                               compress_level, use_vm);
            break;
        }
        default:           ret = EXIT_ERR_ARGS;                           break;
    }

    if (out_needs_free) free((void *)output);
    if (key_needs_free) free((char *)key);
    return ret;
}
