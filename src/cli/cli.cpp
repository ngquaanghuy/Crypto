#include "cli/cli.h"
#include "cli/cli_help.h"
#include "cli/cli_parse.h"
#include "cli/protect.h"
#include "crypto/common.h"
#include "crypto/compress.h"
#include "encode/encoder.h"
#include "crypto/cipher.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

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
    int use_vram = 0;
    int use_vram_auto = 0;
    int vram_size = 4096;
    int use_vram_garble = 0;
    int vram_garble_min = 80;
    int vram_garble_max = 200;
    int obf_seed = -1;
    float obf_density = 1.0f;

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
            else if (strcmp(name, "gzip") == 0)  compress_algo = COMPRESS_ID_GZIP;
            else if (strcmp(name, "lz4") == 0)   compress_algo = COMPRESS_ID_LZ4;
            else if (strcmp(name, "snappy") == 0) compress_algo = COMPRESS_ID_SNAPPY;
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
        } else if (strcmp(argv[i], "--vram-enable") == 0) {
            use_vram = 1;
        } else if (strcmp(argv[i], "--vram-size") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "error: --vram-size requires a byte count\n"); return EXIT_ERR_ARGS; }
            int n = atoi(argv[++i]);
            if (n < 256 || n > 1048576) { fprintf(stderr, "error: --vram-size must be 256-1048576\n"); return EXIT_ERR_ARGS; }
            vram_size = n;
            use_vram = 1;
        } else if (strcmp(argv[i], "--vram-auto") == 0) {
            use_vram = 1;
            use_vram_auto = 1;
        } else if (strcmp(argv[i], "--vram-garble") == 0) {
            use_vram_garble = 1;
        } else if (strcmp(argv[i], "--vram-garble-interval") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "error: --vram-garble-interval requires <min>-<max>\n"); return EXIT_ERR_ARGS; }
            const char *iv = argv[++i];
            int n = sscanf(iv, "%d-%d", &vram_garble_min, &vram_garble_max);
            if (n != 2 || vram_garble_min < 1 || vram_garble_max < vram_garble_min) {
                fprintf(stderr, "error: --vram-garble-interval must be <min>-<max> (e.g. 80-200)\n");
                return EXIT_ERR_ARGS;
            }
        } else if (strcmp(argv[i], "--seed") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "error: --seed requires an integer\n"); return EXIT_ERR_ARGS; }
            obf_seed = atoi(argv[++i]);
            if (obf_seed < 0) { fprintf(stderr, "error: --seed must be a non-negative integer\n"); return EXIT_ERR_ARGS; }
        } else if (strcmp(argv[i], "--obf-density") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "error: --obf-density requires a number\n"); return EXIT_ERR_ARGS; }
            obf_density = (float)atof(argv[++i]);
            if (obf_density < 0.0f || obf_density > 5.0f) {
                fprintf(stderr, "error: --obf-density must be between 0.0 and 5.0\n");
                return EXIT_ERR_ARGS;
            }
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

    if (!compress_set) {
        if (mode == MODE_PROTECT)
            compress_algo = COMPRESS_ID_LZ4;
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
        if (algo_needs_key(algo) && (!key || key[0] == '\0')) {
            if (mode == MODE_PROTECT) {
                key = generate_key(32);
                if (!key) { fprintf(stderr, "error: failed to generate key\n"); return EXIT_ERR_CRYPTO; }
                key_needs_free = 1;
            } else {
                fprintf(stderr, "error: no key available for %s\n", algo_name(algo));
                if (key_needs_free) free((char *)key);
                return EXIT_ERR_ARGS;
            }
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
                               compress_level, use_vm, obf_seed, obf_density,
                               use_vram, use_vram_garble,
                               vram_garble_min, vram_garble_max,
                               use_vram_auto, vram_size);
            break;
        }
        default:           ret = EXIT_ERR_ARGS;                           break;
    }

    if (out_needs_free) free((void *)output);
    if (key_needs_free) free((char *)key);
    return ret;
}
