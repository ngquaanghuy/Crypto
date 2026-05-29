#include "cli/protect.h"
#include "crypto/file_util.h"
#include "crypto/stub.h"
#include "crypto/pyobf.h"
#include "crypto/aes.h"
#include "crypto/chacha20.h"
#include "encode/base64.h"
#include "encode/base32.h"
#include "encode/base85.h"
#include "encode/ascii85.h"
#include "encode/hexcode.h"
#include "encode/xorcode.h"
#include "vm/vm.h"
#include "vm/vm_interp_py.h"
#include "vm/vm_split.h"
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include "crypto/compress.h"


#define HEADER_SIZE 4
#define SALT_SIZE 16
#define HMAC_SIZE 32

// ... helper to check if a technique is in the list ...
static int has_tech(const char *techs, const char *target) {
    if (!techs) return 0;
    const char *p = techs;
    while (*p) {
        if (strcmp(p, "all") == 0) return 1;
        if (strncmp(p, target, strlen(target)) == 0 && (!p[strlen(target)] || p[strlen(target)] == ',')) {
            return 1;
        }
        p = strchr(p, ',');
        if (!p) break;
        p++;
    }
    return 0;
}

static ExitCode apply_rolling_xor_obfuscation(const char *src, size_t src_len, Buffer *out) {
    if (!src || src_len == 0) return EXIT_ERR_INTERNAL;

    unsigned char key[32];
    if (RAND_bytes(key, 32) != 1) return EXIT_ERR_CRYPTO;

    Buffer encrypted = {0};
    ExitCode ret = rolling_xor_encrypt((const unsigned char *)src, src_len, key, 32, &encrypted);
    if (ret != EXIT_OK) return ret;

    Buffer b64 = {0};
    ret = base64_encode(encrypted.data, encrypted.size, &b64);
    free(encrypted.data);
    if (ret != EXIT_OK) return ret;

    char key_hex[65];
    for (int i = 0; i < 32; i++) sprintf(key_hex + i * 2, "%02x", key[i]);
    key_hex[64] = '\0';

    // Construct the Python wrapper
    // Using a compact form to avoid too much overhead
    const char *fmt = 
        "def _rx(_d, _k):\n"
        "    _s = _k[0]\n"
        "    _r = bytearray()\n"
        "    for i in range(len(_d)):\n"
        "        _v = _d[i] ^ _s\n"
        "        _r.append(_v)\n"
        "        _s = (_d[i] ^ _k[(i+1)%%len(_k)])\n"
        "        _s = (((_s << 3) & 0xFF) | (_s >> 5)) ^ 0x5A\n"
        "    return bytes(_r)\n"
        "import base64 as _b64\n"
        "exec(_rx(_b64.b64decode(\"%s\"), bytes.fromhex(\"%s\")))\n";
    
    // Ensure b64.data is null-terminated for sprintf
    char *b64_str = (char *)malloc(b64.size + 1);
    memcpy(b64_str, b64.data, b64.size);
    b64_str[b64.size] = '\0';

    size_t needed = strlen(fmt) + b64.size + 65 + 10;
    char *res = (char *)malloc(needed);
    if (!res) { 
        free(b64_str); 
        free(b64.data); 
        return EXIT_ERR_CRYPTO; 
    }

    sprintf(res, fmt, b64_str, key_hex);
    free(b64_str);

    
    out->data = (unsigned char *)res;
    out->size = strlen(res);
    free(b64.data);
    return EXIT_OK;
}

static ExitCode apply_xor_bit_rotation_obfuscation(const char *src, size_t src_len, Buffer *out) {
    if (!src || src_len == 0) return EXIT_ERR_INTERNAL;

    unsigned char key[32];
    if (RAND_bytes(key, 32) != 1) return EXIT_ERR_CRYPTO;

    Buffer encrypted = {0};
    ExitCode ret = xor_bit_rotation_encrypt((const unsigned char *)src, src_len, key, 32, &encrypted);
    if (ret != EXIT_OK) return ret;

    Buffer b64 = {0};
    ret = base64_encode(encrypted.data, encrypted.size, &b64);
    free(encrypted.data);
    if (ret != EXIT_OK) return ret;

    char key_hex[65];
    for (int i = 0; i < 32; i++) sprintf(key_hex + i * 2, "%02x", key[i]);
    key_hex[64] = '\0';

    const char *fmt = 
        "def _xbr(_d, _k):\n"
        "    _r = bytearray()\n"
        "    for i in range(len(_d)):\n"
        "        _v = ((_d[i] >> 3) | (_d[i] << 5)) & 0xFF\n"
        "        _v = _v ^ _k[i %% len(_k)]\n"
        "        _r.append(_v)\n"
        "    return bytes(_r)\n"
        "import base64 as _b64\n"
        "exec(_xbr(_b64.b64decode(\"%s\"), bytes.fromhex(\"%s\")))\n";
    
    char *b64_str = (char *)malloc(b64.size + 1);
    memcpy(b64_str, b64.data, b64.size);
    b64_str[b64.size] = '\0';

    size_t needed = strlen(fmt) + b64.size + 65 + 10;
    char *res = (char *)malloc(needed);
    if (!res) { 
        free(b64_str); 
        free(b64.data); 
        return EXIT_ERR_CRYPTO; 
    }

    sprintf(res, fmt, b64_str, key_hex);
    free(b64_str);
    
    out->data = (unsigned char *)res;
    out->size = strlen(res);
    free(b64.data);
    return EXIT_OK;
}

// Return a random int in [lo, hi]
static int rand_range(int lo, int hi) {
    return lo + rand() % (hi - lo + 1);
}

static void rand_name(char *buf, int sz) {
    int len = rand_range(3, 8);
    char *p = buf;
    *p++ = '_';
    for (int i = 1; i < len && i < sz - 1; i++)
        *p++ = (char)('a' + rand() % 26);
    *p = '\0';
}

static void sb_append(char **pos, char *end, const char *s) {
    size_t n = strlen(s);
    if (*pos + n < end) {
        memcpy(*pos, s, n);
        *pos += n;
        **pos = 0;
    }
}

// Safe string printf with null termination
static void sb_printf(char **pos, char *end, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(*pos, (size_t)(end - *pos), fmt, ap);
    va_end(ap);
    if (n > 0) {
        size_t n2 = (size_t)n;
        if (*pos + n2 >= end) n2 = (size_t)(end - *pos - 1);
        *pos += n2;
        **pos = 0;
    }
}

// ── polymorphic stub generator ──────────────────────────────────────────────

#define SB_SZ (65536 * 4)

// Scramble anti-analysis fragments (with __S__ placeholders)
#define ANTI_FRAG_GETTRACE \
    "    if __S__.gettrace() is not None:\n" \
    "        __S__.stderr.write('error: debugger detected\\n'); __S__.exit(1)\n"
#define ANTI_FRAG_BREAKPOINT \
    "    __S__.breakpointhook = None\n" \
    "    for _qm in ('pydevd','pdb','ipdb','pdbpp','pydevconsole'):\n" \
    "        if _qm in __S__.modules:\n" \
    "            __S__.stderr.write('error: debugger detected\\n'); __S__.exit(1)\n"
#define ANTI_FRAG_HOOK \
    "    for _qn in ('__import__','compile','exec'):\n" \
    "        _qf = getattr(__S__.modules.get('builtins'), _qn, None)\n" \
    "        if _qf is not None:\n" \
    "            _qg = getattr(_qf, '__name__', '')\n" \
    "            if _qg != _qn:\n" \
    "                __S__.stderr.write('error: hook detected\\n'); __S__.exit(1)\n"
#define ANTI_FRAG_META \
    "    if len(__S__.meta_path) > 5:\n" \
    "        __S__.stderr.write('error: import hook detected\\n'); __S__.exit(1)\n" \
    "    if getattr(__S__, 'flags', None) and __S__.flags.no_user_site:\n" \
    "        __S__.stderr.write('error: sandbox detected\\n'); __S__.exit(1)\n"

static char* patch_sys_name(const char *code, const char *sys_name) {
    const char needle[] = "__S__";
    size_t needle_len = 5;
    size_t ns_len = strlen(sys_name);
    int cnt = 0;
    const char *pp = code;
    while ((pp = strstr(pp, needle))) { cnt++; pp += needle_len; }
    size_t new_len = strlen(code) + cnt * (ns_len - needle_len);
    char *result = (char *)malloc(new_len + 1);
    if (!result) return NULL;
    pp = code;
    char *wp = result;
    const char *sp;
    while ((sp = strstr(pp, needle))) {
        size_t cp = (size_t)(sp - pp);
        memcpy(wp, pp, cp); wp += cp;
        memcpy(wp, sys_name, ns_len); wp += ns_len;
        pp = sp + needle_len;
    }
    size_t trail = strlen(pp);
    memcpy(wp, pp, trail); wp += trail;
    *wp = 0;
    return result;
}

static ExitCode generate_stub(const char *b64_data, size_t b64_sz,
                                   const char *algo_id,
                                   const char *obf_key, size_t obf_key_len,
                                   const char *anti_code, size_t anti_len,
                                   int xor_byte, int compress_algo,
                                   int use_vm, int use_scramble,
                                   const char *vm_xor_key, int vm_obf_algo,
                                   Buffer *out) {



    char *buf = (char *)malloc(SB_SZ);
    if (!buf) return EXIT_ERR_CRYPTO;
    char *p = buf;
    char *end = buf + SB_SZ - 1;

    // ── random names ──
    char n_h[16], n_m[16], n_b[16], n_s[16], n_z[16];
    char n_P[16], n_A[16], n_k[16], n_r[16], n_fn[16];
    char n_0[16], n_1[16], n_2[16], n_3[16], n_4[16], n_5[16];
    char n_6[16], n_7[16], n_8[16], n_9[16], n_t[16], n_ae[16];
    char n_c[16], n_a[16], n_d[16], n_vx[16];
    char n_85t[16], n_85d[16], n_zd[16], n_zd_arg[16], n_zd_d[16], n_zd_i[16];
    char n_zd_n[16], n_zd_cnt[16], n_zd_nb[16];
    char n_ad[16], n_ad_arg[16], n_ad_d[16], n_ad_i[16];
    char n_ad_n[16], n_ad_cnt[16], n_ad_nb[16];
    rand_name(n_h, sizeof(n_h));
    rand_name(n_m, sizeof(n_m));
    rand_name(n_b, sizeof(n_b));
    rand_name(n_s, sizeof(n_s));
    rand_name(n_z, sizeof(n_z));
    rand_name(n_P, sizeof(n_P));
    rand_name(n_A, sizeof(n_A));
    rand_name(n_k, sizeof(n_k));
    rand_name(n_r, sizeof(n_r));
    rand_name(n_fn, sizeof(n_fn));
    rand_name(n_0, sizeof(n_0));
    rand_name(n_1, sizeof(n_1));
    rand_name(n_2, sizeof(n_2));
    rand_name(n_3, sizeof(n_3));
    rand_name(n_4, sizeof(n_4));
    rand_name(n_5, sizeof(n_5));
    rand_name(n_6, sizeof(n_6));
    rand_name(n_7, sizeof(n_7));
    rand_name(n_8, sizeof(n_8));
    rand_name(n_9, sizeof(n_9));
    rand_name(n_t, sizeof(n_t));
    rand_name(n_ae, sizeof(n_ae));
    rand_name(n_c, sizeof(n_c));
    rand_name(n_a, sizeof(n_a));
    rand_name(n_d, sizeof(n_d));
    rand_name(n_vx, sizeof(n_vx));
    rand_name(n_85t, sizeof(n_85t));
    rand_name(n_85d, sizeof(n_85d));
    rand_name(n_zd, sizeof(n_zd));
    rand_name(n_zd_arg, sizeof(n_zd_arg));
    rand_name(n_zd_d, sizeof(n_zd_d));
    rand_name(n_zd_i, sizeof(n_zd_i));
    rand_name(n_zd_n, sizeof(n_zd_n));
    rand_name(n_zd_cnt, sizeof(n_zd_cnt));
    rand_name(n_zd_nb, sizeof(n_zd_nb));
    rand_name(n_ad, sizeof(n_ad));
    rand_name(n_ad_arg, sizeof(n_ad_arg));
    rand_name(n_ad_d, sizeof(n_ad_d));
    rand_name(n_ad_i, sizeof(n_ad_i));
    rand_name(n_ad_n, sizeof(n_ad_n));
    rand_name(n_ad_cnt, sizeof(n_ad_cnt));
    rand_name(n_ad_nb, sizeof(n_ad_nb));

    // Additional random names for junk
    char j1[16], j2[16], junk_fn[16];
    rand_name(j1, sizeof(j1));
    rand_name(j2, sizeof(j2));
    rand_name(junk_fn, sizeof(junk_fn));

    // Scramble anti-analysis: each fragment gets its own sys name
    char *scramble_frags[4] = {NULL, NULL, NULL, NULL};
    if (use_scramble) {
        // All fragments use the same sys name (n_s) to match the imports
        scramble_frags[0] = patch_sys_name(ANTI_FRAG_GETTRACE, n_s);
        scramble_frags[1] = patch_sys_name(ANTI_FRAG_BREAKPOINT, n_s);
        scramble_frags[2] = patch_sys_name(ANTI_FRAG_HOOK, n_s);
        scramble_frags[3] = patch_sys_name(ANTI_FRAG_META, n_s);
    }

    // anti_code already has __S__ placeholders injected
    // anti_code already has __S__ placeholders injected
    char *patched_anti = NULL;
    if (anti_len > 0) {
        const char *needle = "__S__";
        size_t needle_len = strlen(needle);
        size_t ns_len = strlen(n_s);
        // Count occurrences
        int cnt = 0;
        const char *pp = anti_code;
        while ((pp = strstr(pp, needle))) { cnt++; pp += needle_len; }
        size_t new_len = anti_len + cnt * (ns_len - needle_len);
        patched_anti = (char *)malloc(new_len + 1);
        if (!patched_anti) { free(buf); return EXIT_ERR_CRYPTO; }
        pp = anti_code;
        char *wp = patched_anti;
        const char *sp;
        while ((sp = strstr(pp, needle))) {
            size_t cp = (size_t)(sp - pp);
            memcpy(wp, pp, cp); wp += cp;
            memcpy(wp, n_s, ns_len); wp += ns_len;
            pp = sp + needle_len;
        }
        size_t trail = strlen(pp);
        memcpy(wp, pp, trail); wp += trail;
        *wp = 0;
        anti_code = patched_anti;
        anti_len = new_len;
    }

    // ── junk variable ──
    int junk_val = rand_range(1, 999999);
    int junk_val2 = rand_range(1, 999999);

    // ── build stub ──
    sb_printf(&p, end, "#!/usr/bin/env python3\n");

    // Junk: unused function
    sb_printf(&p, end, "def %s(%s):\n"
              "    return %s %% %d + 1\n\n", junk_fn, j1, j1, rand_range(100, 9999));

    // Imports (with random aliases)
    sb_printf(&p, end, "import hashlib as %s, hmac as %s, base64 as %s, sys as %s, zlib as %s\n",
              n_h, n_m, n_b, n_s, n_z);

    // Junk: dead variable
    sb_printf(&p, end, "%s = %d\n", j1, junk_val);

    // Data declarations
    sb_printf(&p, end, "%s = \"\"\"%s\"\"\"\n", n_P, b64_data);
    sb_printf(&p, end, "%s = %s\n", n_A, algo_id);

    // Junk: dead assignment
    sb_printf(&p, end, "%s = %s(%s)\n", j2, junk_fn, j1);

    // ── VM interpreter (if enabled) ──
    if (use_vm) {
        sb_printf(&p, end, "%s\n", VM_INTERP_SCRIPT);
    }

    // ── main function ──
    sb_printf(&p, end, "def %s():\n", n_fn);

    // Anti-analysis code (indented by 4 spaces)
    if (use_scramble) {
        // Fragment 0: gettrace check (uses same sys name as anti_code)
        sb_append(&p, end, scramble_frags[0]);
    } else if (anti_len > 0) {
        sb_append(&p, end, anti_code);
    }
    free(patched_anti);

    // Key deobfuscation
    sb_printf(&p, end, "    %s = bytes.fromhex(\"%s\")\n", n_k, obf_key);
    if (obf_key_len > 0) {
        sb_printf(&p, end, "    %s = bytes(_ ^ %d for _ in %s).decode()\n",
                  n_k, xor_byte, n_k);
    }
    // Scramble: position B — breakpointhook + modules check
    if (use_scramble && scramble_frags[1]) {
        sb_append(&p, end, scramble_frags[1]);
    }

    sb_printf(&p, end, "    %s = %s.b64decode(%s)\n", n_r, n_b, n_P);

    // Scramble: position C — builtin hook check
    if (use_scramble && scramble_frags[2]) {
        sb_append(&p, end, scramble_frags[2]);
    }

    // ── crypto library import ──
    // Randomize: sometimes import at top-level, sometimes inside branch
    int import_style = rand_range(0, 2);
    int has_early_crypto_import = (import_style < 2);
    if (has_early_crypto_import) {
        sb_printf(&p, end, "    try:\n");
        sb_printf(&p, end, "        from cryptography.hazmat.primitives.ciphers import Cipher as %s, algorithms as %s, modes as %s\n",
                  n_c, n_a, n_d);
        sb_printf(&p, end, "    except ImportError:\n");
        sb_printf(&p, end, "        %s.stderr.write(\"error: cryptography not installed\\n\"); %s.exit(1)\n\n",
                  n_s, n_s);
    }

    // Scramble: position D — meta_path + flags check
    if (use_scramble && scramble_frags[3]) {
        sb_append(&p, end, scramble_frags[3]);
    }

    // ── generate algorithm blocks (dispatch) ──
    // Build a shuffled order for _A values
    // We always include all 14 algorithms, but in random order
    int order[14] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13};
    // Fisher-Yates shuffle
    for (int i = 13; i > 0; i--) {
        int j = rand() % (i + 1);
        int tmp = order[i]; order[i] = order[j]; order[j] = tmp;
    }

    // Track which blocks have been emitted
    int emitted[13] = {0};
    int is_first = 1;

    for (int oi = 0; oi < 14; oi++) {
        int aid = order[oi];
        const char *kw = is_first ? "if" : "elif";
        is_first = 0;

        if (aid == 0) {
            // AES-ECB
            sb_printf(&p, end, "    %s %s == 0:\n", kw, n_A);
            if (!has_early_crypto_import)
                sb_printf(&p, end, "        try:\n"
                          "            from cryptography.hazmat.primitives.ciphers import Cipher as %s, algorithms as %s, modes as %s\n"
                          "        except ImportError:\n"
                          "            %s.stderr.write(\"error: cryptography not installed\\n\"); %s.exit(1)\n",
                          n_c, n_a, n_d, n_s, n_s);
            sb_printf(&p, end, "        %s = %s[:16]; %s = %s[-32:]; %s = %s[16:-32]\n",
                      n_0, n_r, n_2, n_r, n_1, n_r);
            sb_printf(&p, end, "        %s = %s.pbkdf2_hmac('sha256', %s.encode(), %s, 100000, dklen=64)\n",
                      n_3, n_h, n_k, n_0);
            sb_printf(&p, end, "        %s = %s[:32]; %s = %s[32:64]\n",
                      n_4, n_3, n_6, n_3);
            sb_printf(&p, end, "        %s = %s.new(%s, %s, %s.sha256).digest()\n",
                      n_7, n_m, n_6, n_1, n_h);
            sb_printf(&p, end, "        if not %s.compare_digest(%s, %s):\n"
                      "            %s.stderr.write(\"error: integrity check failed\\n\"); %s.exit(1)\n",
                      n_m, n_2, n_7, n_s, n_s);
            sb_printf(&p, end, "        %s = %s(%s.AES(%s), %s.ECB())\n",
                      n_8, n_c, n_a, n_4, n_d);
            sb_printf(&p, end, "        %s = %s.decryptor()\n"
                      "        %s = %s.update(%s) + %s.finalize()\n",
                      n_9, n_8, n_9, n_9, n_1, n_9);
            sb_printf(&p, end, "        %s = %s[-1]\n"
                      "        if %s < 1 or %s > 16 or not all(_ == %s for _ in %s[-%s:]):\n"
                      "            %s.stderr.write(\"error: decryption failed\\n\"); %s.exit(1)\n"
                      "        %s = %s[:-%s]\n",
                      n_t, n_9, n_t, n_t, n_t, n_9, n_t, n_s, n_s, n_9, n_9, n_t);
        } else if (aid == 1) {
            // AES-CBC
            sb_printf(&p, end, "    %s %s == 1:\n", kw, n_A);
            if (!has_early_crypto_import)
                sb_printf(&p, end, "        try:\n"
                          "            from cryptography.hazmat.primitives.ciphers import Cipher as %s, algorithms as %s, modes as %s\n"
                          "        except ImportError:\n"
                          "            %s.stderr.write(\"error: cryptography not installed\\n\"); %s.exit(1)\n",
                          n_c, n_a, n_d, n_s, n_s);
            sb_printf(&p, end, "        %s = %s[:16]; %s = %s[-32:]; %s = %s[16:-32]\n",
                      n_0, n_r, n_2, n_r, n_1, n_r);
            sb_printf(&p, end, "        %s = %s.pbkdf2_hmac('sha256', %s.encode(), %s, 100000, dklen=80)\n",
                      n_3, n_h, n_k, n_0);
            sb_printf(&p, end, "        %s = %s[:32]; %s = %s[32:48]; %s = %s[48:80]\n",
                      n_4, n_3, n_5, n_3, n_6, n_3);
            sb_printf(&p, end, "        %s = %s.new(%s, %s, %s.sha256).digest()\n",
                      n_7, n_m, n_6, n_1, n_h);
            sb_printf(&p, end, "        if not %s.compare_digest(%s, %s):\n"
                      "            %s.stderr.write(\"error: integrity check failed\\n\"); %s.exit(1)\n",
                      n_m, n_2, n_7, n_s, n_s);
            sb_printf(&p, end, "        %s = %s(%s.AES(%s), %s.CBC(%s))\n",
                      n_8, n_c, n_a, n_4, n_d, n_5);
            sb_printf(&p, end, "        %s = %s.decryptor()\n"
                      "        %s = %s.update(%s) + %s.finalize()\n",
                      n_9, n_8, n_9, n_9, n_1, n_9);
            sb_printf(&p, end, "        %s = %s[-1]\n"
                      "        if %s < 1 or %s > 16 or not all(_ == %s for _ in %s[-%s:]):\n"
                      "            %s.stderr.write(\"error: decryption failed\\n\"); %s.exit(1)\n"
                      "        %s = %s[:-%s]\n",
                      n_t, n_9, n_t, n_t, n_t, n_9, n_t, n_s, n_s, n_9, n_9, n_t);
        } else if (aid == 2) {
            // AES-CTR
            sb_printf(&p, end, "    %s %s == 2:\n", kw, n_A);
            if (!has_early_crypto_import)
                sb_printf(&p, end, "        try:\n"
                          "            from cryptography.hazmat.primitives.ciphers import Cipher as %s, algorithms as %s, modes as %s\n"
                          "        except ImportError:\n"
                          "            %s.stderr.write(\"error: cryptography not installed\\n\"); %s.exit(1)\n",
                          n_c, n_a, n_d, n_s, n_s);
            sb_printf(&p, end, "        %s = %s[:16]; %s = %s[-32:]; %s = %s[16:-32]\n",
                      n_0, n_r, n_2, n_r, n_1, n_r);
            sb_printf(&p, end, "        %s = %s.pbkdf2_hmac('sha256', %s.encode(), %s, 100000, dklen=80)\n",
                      n_3, n_h, n_k, n_0);
            sb_printf(&p, end, "        %s = %s[:32]; %s = %s[32:48]; %s = %s[48:80]\n",
                      n_4, n_3, n_5, n_3, n_6, n_3);
            sb_printf(&p, end, "        %s = %s.new(%s, %s, %s.sha256).digest()\n",
                      n_7, n_m, n_6, n_1, n_h);
            sb_printf(&p, end, "        if not %s.compare_digest(%s, %s):\n"
                      "            %s.stderr.write(\"error: integrity check failed\\n\"); %s.exit(1)\n",
                      n_m, n_2, n_7, n_s, n_s);
            sb_printf(&p, end, "        %s = %s(%s.AES(%s), %s.CTR(%s))\n",
                      n_8, n_c, n_a, n_4, n_d, n_5);
            sb_printf(&p, end, "        %s = %s.decryptor().update(%s)\n",
                      n_9, n_8, n_1);
        } else if (aid == 3) {
            // AES-GCM
            sb_printf(&p, end, "    %s %s == 3:\n", kw, n_A);
            if (!has_early_crypto_import)
                sb_printf(&p, end, "        try:\n"
                          "            from cryptography.hazmat.primitives.ciphers.aead import AESGCM as %s\n"
                          "        except ImportError:\n"
                          "            %s.stderr.write(\"error: cryptography not installed\\n\"); %s.exit(1)\n",
                          n_ae, n_s, n_s);
            else
                sb_printf(&p, end, "        from cryptography.hazmat.primitives.ciphers.aead import AESGCM as %s\n",
                          n_ae);
            sb_printf(&p, end, "        %s = %s[:16]; %s = %s[-32:]; %s = %s[16:-32]\n",
                      n_0, n_r, n_2, n_r, n_9, n_r);
            sb_printf(&p, end, "        %s = %s[:-16]; %s = %s[-16:]\n",
                      n_1, n_9, n_t, n_9);
            sb_printf(&p, end, "        %s = %s.pbkdf2_hmac('sha256', %s.encode(), %s, 100000, dklen=76)\n",
                      n_3, n_h, n_k, n_0);
            sb_printf(&p, end, "        %s = %s[:32]; %s = %s[32:44]; %s = %s[44:76]\n",
                      n_4, n_3, n_5, n_3, n_6, n_3);
            sb_printf(&p, end, "        %s = %s.new(%s, %s, %s.sha256).digest()\n",
                      n_7, n_m, n_6, n_9, n_h);
            sb_printf(&p, end, "        if not %s.compare_digest(%s, %s):\n"
                      "            %s.stderr.write(\"error: integrity check failed\\n\"); %s.exit(1)\n",
                      n_m, n_2, n_7, n_s, n_s);
            sb_printf(&p, end, "        %s = %s(%s).decrypt(%s, %s + %s, None)\n",
                      n_9, n_ae, n_4, n_5, n_1, n_t);
        } else if (aid == 4) {
            // ChaCha20
            sb_printf(&p, end, "    %s %s == 4:\n", kw, n_A);
            if (!has_early_crypto_import)
                sb_printf(&p, end, "        try:\n"
                          "            from cryptography.hazmat.primitives.ciphers import Cipher as %s, algorithms as %s, modes as %s\n"
                          "        except ImportError:\n"
                          "            %s.stderr.write(\"error: cryptography not installed\\n\"); %s.exit(1)\n",
                          n_c, n_a, n_d, n_s, n_s);
            sb_printf(&p, end, "        %s = %s[:16]; %s = %s[-32:]; %s = %s[16:-32]\n",
                      n_0, n_r, n_2, n_r, n_1, n_r);
            sb_printf(&p, end, "        %s = %s.pbkdf2_hmac('sha256', %s.encode(), %s, 100000, dklen=80)\n",
                      n_3, n_h, n_k, n_0);
            sb_printf(&p, end, "        %s = %s[:32]; %s = %s[32:48]; %s = %s[48:80]\n",
                      n_4, n_3, n_5, n_3, n_6, n_3);
            sb_printf(&p, end, "        %s = %s.new(%s, %s, %s.sha256).digest()\n",
                      n_7, n_m, n_6, n_1, n_h);
            sb_printf(&p, end, "        if not %s.compare_digest(%s, %s):\n"
                      "            %s.stderr.write(\"error: integrity check failed\\n\"); %s.exit(1)\n",
                      n_m, n_2, n_7, n_s, n_s);
            sb_printf(&p, end, "        %s = %s(%s.ChaCha20(%s, %s), mode=None)\n",
                      n_8, n_c, n_a, n_4, n_5);
            sb_printf(&p, end, "        %s = %s.decryptor().update(%s)\n",
                      n_9, n_8, n_1);
        } else if (aid == 5) {
            // XOR
            sb_printf(&p, end, "    %s %s == 5:\n", kw, n_A);
            sb_printf(&p, end, "        %s = %s[:16]; %s = %s[-32:]; %s = %s[16:-32]\n",
                      n_0, n_r, n_2, n_r, n_1, n_r);
            sb_printf(&p, end, "        %s = %s.pbkdf2_hmac('sha256', %s.encode(), %s, 100000, dklen=64)\n",
                      n_3, n_h, n_k, n_0);
            sb_printf(&p, end, "        %s = %s[:32]; %s = %s[32:64]\n",
                      n_4, n_3, n_6, n_3);
            sb_printf(&p, end, "        %s = %s.new(%s, %s, %s.sha256).digest()\n",
                      n_7, n_m, n_6, n_1, n_h);
            sb_printf(&p, end, "        if not %s.compare_digest(%s, %s):\n"
                      "            %s.stderr.write(\"error: integrity check failed\\n\"); %s.exit(1)\n",
                      n_m, n_2, n_7, n_s, n_s);
            sb_printf(&p, end, "        %s = bytes(%s[i] ^ %s[i %% 32] for i in range(len(%s)))\n",
                      n_9, n_1, n_4, n_1);
        } else if (aid == 6) {
            sb_printf(&p, end, "    %s %s == 6:\n"
                      "        %s = %s.b64decode(%s)\n", kw, n_A, n_9, n_b, n_r);
        } else if (aid == 7) {
            sb_printf(&p, end, "    %s %s == 7:\n"
                      "        %s = %s.b32decode(%s)\n", kw, n_A, n_9, n_b, n_r);
        } else if (aid == 8) {
            // Z85
            sb_printf(&p, end, "    %s %s == 8:\n", kw, n_A);
            sb_printf(&p, end, "        %s = ('0','1','2','3','4','5','6','7','8','9',\n"
                      "                'A','B','C','D','E','F','G','H','I','J','K','L','M',\n"
                      "                'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',\n"
                      "                'a','b','c','d','e','f','g','h','i','j','k','l','m',\n"
                      "                'n','o','p','q','r','s','t','u','v','w','x','y','z',\n"
                      "                '!','#','$','%%','&','(',')','*','+','-',';','<','=',\n"
                      "                '>','?','@','^','_','`','{','|','}','~')\n",
                      n_85t);
            sb_printf(&p, end, "        %s = {c:i for i,c in enumerate(%s)}\n",
                      n_85d, n_85t);
            sb_printf(&p, end, "        def %s(%s):\n"
                      "            %s = bytearray(); %s = 0\n"
                      "            while %s < len(%s):\n"
                      "                %s = 0; %s = 0\n"
                      "                while %s < len(%s) and %s < 5:\n"
                      "                    %s = %s * 85 + %s[chr(%s[%s])]; %s += 1; %s += 1\n"
                      "                %s = %s - 1\n"
                      "                if %s > 0: %s.extend(%s.to_bytes(4, 'big')[4-%s:])\n"
                      "            return bytes(%s)\n",
                      n_zd, n_zd_arg,
                      n_zd_d, n_zd_i,
                      n_zd_i, n_zd_arg,
                      n_zd_n, n_zd_cnt,
                      n_zd_i, n_zd_arg, n_zd_cnt,
                      n_zd_n, n_zd_n, n_85d, n_zd_arg, n_zd_i, n_zd_i, n_zd_cnt,
                      n_zd_nb, n_zd_cnt,
                      n_zd_nb, n_zd_d, n_zd_n, n_zd_nb,
                      n_zd_d);
            sb_printf(&p, end, "        %s = %s(%s)\n", n_9, n_zd, n_r);
        } else if (aid == 9) {
            // Ascii85
            sb_printf(&p, end, "    %s %s == 9:\n", kw, n_A);
            sb_printf(&p, end, "        def %s(%s):\n"
                      "            if %s[:2] == b'<~': %s = %s[2:]\n"
                      "            if %s[-2:] == b'~>': %s = %s[:-2]\n"
                      "            %s = bytearray(); %s = 0\n"
                      "            while %s < len(%s):\n"
                      "                if %s[%s] == 122:\n"
                      "                    %s.extend(b'\\x00\\x00\\x00\\x00'); %s += 1; continue\n"
                      "                %s = 0; %s = 0\n"
                      "                while %s < len(%s) and %s < 5:\n"
                      "                    %s = %s * 85 + (%s[%s] - 33); %s += 1; %s += 1\n"
                      "                %s = %s - 1\n"
                      "                if %s > 0: %s.extend(%s.to_bytes(4, 'big')[4-%s:])\n"
                      "            return bytes(%s)\n",
                      n_ad, n_ad_arg,
                      n_ad_arg, n_ad_arg, n_ad_arg,
                      n_ad_arg, n_ad_arg, n_ad_arg,
                      n_ad_d, n_ad_i,
                      n_ad_i, n_ad_arg,
                      n_ad_arg, n_ad_i,
                      n_ad_d, n_ad_i,
                      n_ad_n, n_ad_cnt,
                      n_ad_i, n_ad_arg, n_ad_cnt,
                      n_ad_n, n_ad_n, n_ad_arg, n_ad_i, n_ad_i, n_ad_cnt,
                      n_ad_nb, n_ad_cnt,
                      n_ad_nb, n_ad_d, n_ad_n, n_ad_nb,
                      n_ad_d);
            sb_printf(&p, end, "        %s = %s(%s)\n", n_9, n_ad, n_r);
        } else if (aid == 10) {
            sb_printf(&p, end, "    %s %s == 10:\n"
                      "        %s = bytes.fromhex(%s.decode('ascii'))\n", kw, n_A, n_9, n_r);
        } else if (aid == 11) {
            // Rolling XOR
            sb_printf(&p, end, "    %s %s == 11:\n", kw, n_A);
            sb_printf(&p, end, "        %s = %s[:16]; %s = %s[-32:]; %s = %s[16:-32]\n", n_0, n_r, n_2, n_r, n_1, n_r);
            sb_printf(&p, end, "        %s = %s.pbkdf2_hmac('sha256', %s.encode(), %s, 100000, dklen=64)\n", n_3, n_h, n_k, n_0);
            sb_printf(&p, end, "        %s = %s[:32]; %s = %s[32:64]\n", n_4, n_3, n_6, n_3);
            sb_printf(&p, end, "        %s = %s.new(%s, %s, %s.sha256).digest()\n", n_7, n_m, n_6, n_1, n_h);
            sb_printf(&p, end, "        if not %s.compare_digest(%s, %s):\n"
                      "            %s.stderr.write(\"error: integrity check failed\\n\"); %s.exit(1)\n",
                      n_m, n_2, n_7, n_s, n_s);
            sb_printf(&p, end, "        %s = %s[0]\n", n_t, n_4);
            sb_printf(&p, end, "        %s = bytearray()\n", n_9);
            sb_printf(&p, end, "        for %s in range(len(%s)):\n", n_vx, n_1);
            sb_printf(&p, end, "            %s = %s[%s] ^ %s\n", n_0, n_1, n_vx, n_t);
            sb_printf(&p, end, "            %s.append(%s)\n", n_9, n_0);
            sb_printf(&p, end, "            %s = %s[%s] ^ %s[ (%s + 1) %% len(%s) ]\n", n_t, n_1, n_vx, n_4, n_vx, n_4);
            sb_printf(&p, end, "            %s = (((%s << 3) & 0xFF) | (%s >> 5)) ^ 0x5A\n", n_t, n_t, n_t);
            sb_printf(&p, end, "        %s = bytes(%s)\n", n_9, n_9);
        } else if (aid == 12) {
            // Multi-pass XOR
            sb_printf(&p, end, "    %s %s == 12:\n", kw, n_A);
            sb_printf(&p, end, "        %s = %s[:16]; %s = %s[-32:]; %s = %s[16:-32]\n",
                      n_0, n_r, n_2, n_r, n_1, n_r);
            sb_printf(&p, end, "        %s = %s.pbkdf2_hmac('sha256', %s.encode(), %s, 100000, dklen=64)\n",
                      n_3, n_h, n_k, n_0);
            sb_printf(&p, end, "        %s = %s[:32]; %s = %s[32:64]\n",
                      n_4, n_3, n_6, n_3);
            sb_printf(&p, end, "        %s = %s.new(%s, %s, %s.sha256).digest()\n",
                      n_7, n_m, n_6, n_1, n_h);
            sb_printf(&p, end, "        if not %s.compare_digest(%s, %s):\n"
                      "            %s.stderr.write(\"error: integrity check failed\\n\"); %s.exit(1)\n",
                      n_m, n_2, n_7, n_s, n_s);
            sb_printf(&p, end, "        %s = 3 + (%s[0] & 7)\n", n_t, n_0);
            sb_printf(&p, end, "        %s = bytearray(%s)\n", n_0, n_1);
            sb_printf(&p, end, "        for %s in range(%s - 1, -1, -1):\n", n_vx, n_t);
            sb_printf(&p, end, "            %s = (3 + %s) & 7\n", junk_fn, n_vx);
            sb_printf(&p, end, "            %s = (%s * 0x1B + 0x5A) & 0xFF\n", j1, n_vx);
            sb_printf(&p, end, "            for %s in range(len(%s)):\n", n_5, n_0);
            sb_printf(&p, end, "                %s = %s[%s]\n", n_t, n_0, n_5);
            sb_printf(&p, end, "                %s ^= %s\n", n_t, j1);
            sb_printf(&p, end, "                %s = ((%s >> %s) | ((%s << (8 - %s)) & 0xFF))\n",
                      n_t, n_t, junk_fn, n_t, junk_fn);
            sb_printf(&p, end, "                %s ^= %s[(%s * len(%s) + %s) %% len(%s)]\n",
                      n_t, n_4, n_vx, n_0, n_5, n_4);
            sb_printf(&p, end, "                %s[%s] = %s\n", n_0, n_5, n_t);
            sb_printf(&p, end, "        %s = bytes(%s)\n", n_9, n_0);
        } else if (aid == 13) {
            // PRNG-XOR (ChaCha20-based)
            sb_printf(&p, end, "    %s %s == 13:\n", kw, n_A);
            sb_printf(&p, end, "        %s = %s[:16]; %s = %s[-32:]; %s = %s[16:-32]\n",
                      n_0, n_r, n_2, n_r, n_1, n_r);
            sb_printf(&p, end, "        %s = %s.pbkdf2_hmac('sha256', %s.encode(), %s, 100000, dklen=80)\n",
                      n_3, n_h, n_k, n_0);
            sb_printf(&p, end, "        %s = %s[:32]; %s = %s[32:48]; %s = %s[48:80]\n",
                      n_4, n_3, n_5, n_3, n_6, n_3);
            sb_printf(&p, end, "        %s = %s.new(%s, %s, %s.sha256).digest()\n",
                      n_7, n_m, n_6, n_1, n_h);
            sb_printf(&p, end, "        if not %s.compare_digest(%s, %s):\n"
                      "            %s.stderr.write(\"error: integrity check failed\\n\"); %s.exit(1)\n",
                      n_m, n_2, n_7, n_s, n_s);
            // Inline pure-Python ChaCha20 decrypt
            sb_printf(&p, end, "        import struct as %s\n", j2);
            sb_printf(&p, end, "        def %s(k,c,n):\n"
                      "            s=[0x61707865,0x3320646e,0x79622d32,0x6b206574]\n"
                      "            for i in range(0,32,4):s.append(%s.unpack('<I',k[i:i+4])[0])\n"
                      "            s.append(c&0xFFFFFFFF)\n"
                      "            for i in range(0,12,4):s.append(%s.unpack('<I',n[i:i+4])[0])\n"
                      "            w=list(s)\n"
                      "            def q(a,b,c,d):\n"
                      "                a=(a+b)&0xFFFFFFFF;d^=a;d=((d<<16)|(d>>16))&0xFFFFFFFF\n"
                      "                c=(c+d)&0xFFFFFFFF;b^=c;b=((b<<12)|(b>>20))&0xFFFFFFFF\n"
                      "                a=(a+b)&0xFFFFFFFF;d^=a;d=((d<<8)|(d>>24))&0xFFFFFFFF\n"
                      "                c=(c+d)&0xFFFFFFFF;b^=c;b=((b<<7)|(b>>25))&0xFFFFFFFF\n"
                      "                return a,b,c,d\n"
                      "            for _ in range(10):\n"
                      "                w[0],w[4],w[8],w[12]=q(w[0],w[4],w[8],w[12])\n"
                      "                w[1],w[5],w[9],w[13]=q(w[1],w[5],w[9],w[13])\n"
                      "                w[2],w[6],w[10],w[14]=q(w[2],w[6],w[10],w[14])\n"
                      "                w[3],w[7],w[11],w[15]=q(w[3],w[7],w[11],w[15])\n"
                      "                w[0],w[5],w[10],w[15]=q(w[0],w[5],w[10],w[15])\n"
                      "                w[1],w[6],w[11],w[12]=q(w[1],w[6],w[11],w[12])\n"
                      "                w[2],w[7],w[8],w[13]=q(w[2],w[7],w[8],w[13])\n"
                      "                w[3],w[4],w[9],w[14]=q(w[3],w[4],w[9],w[14])\n"
                      "            r=bytearray()\n"
                      "            for i in range(16):r.extend(%s.pack('<I',(s[i]+w[i])&0xFFFFFFFF))\n"
                      "            return bytes(r)\n",
                      junk_fn, j2, j2, j2, j2);
            // OpenSSL EVP_chacha20 uses 16-byte IV: counter(4) || nonce(12)
            sb_printf(&p, end, "        %s = %s.unpack('<I',%s[:4])[0]\n", n_vx, j2, n_5);
            sb_printf(&p, end, "        %s = %s[4:]\n", n_5, n_5);
            sb_printf(&p, end, "        %s = bytearray()\n", n_0);
            sb_printf(&p, end, "        while len(%s) < len(%s):\n", n_0, n_1);
            sb_printf(&p, end, "            %s = %s(%s, %s, %s)\n", n_t, junk_fn, n_4, n_vx, n_5);
            sb_printf(&p, end, "            for %s in range(min(64, len(%s) - len(%s))):\n",
                      j1, n_1, n_0);
            sb_printf(&p, end, "                %s.append(%s[len(%s)] ^ %s[%s])\n",
                      n_0, n_1, n_0, n_t, j1);
            sb_printf(&p, end, "            %s += 1\n", n_vx);
            sb_printf(&p, end, "        %s = bytes(%s)\n", n_9, n_0);
        }







        emitted[aid] = 1;
    }

    // else block for unknown algo
    sb_printf(&p, end, "    else:\n"
              "        %s.stderr.write(\"error: unsupported algorithm\\n\"); %s.exit(1)\n",
              n_s, n_s);

    // Decompress and execute
    if (use_vm) {
        // VM mode: deserialize and run through VM interpreter
        if (vm_xor_key) {
            if (vm_obf_algo == 1) {
                sb_printf(&p, end, "    _v_k = bytes.fromhex(\"%s\")\n", vm_xor_key);
                sb_printf(&p, end, "    _v_s = _v_k[0]\n");
                sb_printf(&p, end, "    _v_r = bytearray()\n");
                sb_printf(&p, end, "    for i in range(len(%s[4:])):\n", n_9);
                sb_printf(&p, end, "        _v_v = %s[4+i] ^ _v_s\n", n_9, n_9);
                sb_printf(&p, end, "        _v_r.append(_v_v)\n");
                sb_printf(&p, end, "        _v_s = (%s[4+i] ^ _v_k[(i+1)%%len(_v_k)])\n", n_9);
                sb_printf(&p, end, "        _v_s = (((_v_s << 3) & 0xFF) | (_v_s >> 5)) ^ 0x5A\n");
                sb_printf(&p, end, "    _xd = bytes(_v_r)\n");
            } else if (vm_obf_algo == 2) {
                sb_printf(&p, end, "    _v_k = bytes.fromhex(\"%s\")\n", vm_xor_key);
                sb_printf(&p, end, "    _v_r = bytearray()\n");
                sb_printf(&p, end, "    for i in range(len(%s[4:])):\n", n_9);
                sb_printf(&p, end, "        _v_v = ((%s[4+i] >> 3) | (%s[4+i] << 5)) & 0xFF\n", n_9, n_9);
                sb_printf(&p, end, "        _v_v = _v_v ^ _v_k[i %% len(_v_k)]\n");
                sb_printf(&p, end, "        _v_r.append(_v_v)\n");
                sb_printf(&p, end, "    _xd = bytes(_v_r)\n");
            }

            sb_printf(&p, end, "    %s, _c, _k, _m = _vm_deserialize(_xd)\n", n_9);
        } else {
            sb_printf(&p, end, "    %s, _c, _k, _m = _vm_deserialize(%s[4:])\n", n_9, n_9);
        }
        sb_printf(&p, end, "    exec(compile(%s, '<vm>', 'exec'), globals())\n", n_9);
        sb_printf(&p, end, "    _vm_run(_c, _k, _m, globals(), locals())\n");
    } else {
        if (compress_algo != COMPRESS_ID_NONE) {
            sb_printf(&p, end, "    if %s[1] == %d:\n"
                      "        import zlib as %s\n"
                      "        %s = %s.decompress(%s[4:])\n",
                      n_9, COMPRESS_ID_ZLIB, n_z, n_9, n_z, n_9);
            sb_printf(&p, end, "    elif %s[1] == %d:\n"
                      "        import lzma as %s\n"
                      "        %s = %s.decompress(%s[4:])\n",
                      n_9, COMPRESS_ID_LZMA, n_z, n_9, n_z, n_9);
            sb_printf(&p, end, "    elif %s[1] == %d:\n"
                      "        import bz2 as %s\n"
                      "        %s = %s.decompress(%s[4:])\n",
                      n_9, COMPRESS_ID_BZ2, n_z, n_9, n_z, n_9);
            sb_printf(&p, end, "    elif %s[1] == %d:\n"
                      "        import brotli as %s\n"
                      "        %s = %s.decompress(%s[4:])\n",
                      n_9, COMPRESS_ID_BROTLI, n_z, n_9, n_z, n_9);
            sb_printf(&p, end, "    elif %s[1] == %d:\n"
                      "        import zstandard as %s\n"
                      "        %s = %s.decompress(%s[4:])\n",
                      n_9, COMPRESS_ID_ZSTD, n_z, n_9, n_z, n_9);
            sb_printf(&p, end, "    elif %s[1] == %d:\n"
                      "        import gzip as %s\n"
                      "        %s = %s.decompress(%s[4:])\n",
                      n_9, COMPRESS_ID_GZIP, n_z, n_9, n_z, n_9);
            sb_printf(&p, end, "    elif %s[1] == %d:\n"
                      "        import lz4.frame as %s\n"
                      "        %s = %s.decompress(%s[4:])\n",
                      n_9, COMPRESS_ID_LZ4, n_z, n_9, n_z, n_9);
            sb_printf(&p, end, "    elif %s[1] == %d:\n"
                      "        import snappy as %s\n"
                      "        %s = %s.decompress(%s[4:])\n",
                      n_9, COMPRESS_ID_SNAPPY, n_z, n_9, n_z, n_9);
            sb_printf(&p, end, "    elif %s[1] == %d:\n"
                      "        import gzip as %s\n"
                      "        %s = %s.decompress(%s[4:])\n",
                      n_9, COMPRESS_ID_ZOPFLI, n_z, n_9, n_z, n_9);
            sb_printf(&p, end, "    elif %s[1] == %d:\n"
                      "        import blosc as %s\n"
                      "        %s = %s.decompress(%s[4:])\n",
                      n_9, COMPRESS_ID_BLOSC, n_z, n_9, n_z, n_9);
            sb_printf(&p, end, "    else:\n"
                      "        %s = %s[4:]\n", n_9, n_9);
        } else {
            sb_printf(&p, end, "    %s = %s[4:]\n", n_9, n_9);
        }
        sb_printf(&p, end, "    exec(compile(%s, '<protected>', 'exec'), globals())\n\n",
                  n_9);
    }

    // Guard
    sb_printf(&p, end, "if __name__ == '__main__':\n"
              "    %s()\n", n_fn);

    out->data = (unsigned char *)buf;
    out->size = (size_t)(p - buf);
    for (int i = 0; i < 4; i++) {
        if (scramble_frags[i]) free(scramble_frags[i]);
    }
    return EXIT_OK;
}
#undef SB_SZ

// ── anti-analysis code templates ────────────────────────────────────────────

static const char ANTI_DEBUG_CODE[] =
    "    if __S__.gettrace() is not None:\n"
    "        __S__.stderr.write('error: debugger detected\\n'); __S__.exit(1)\n"
    "    __S__.breakpointhook = None\n"
    "    for __m in ('pydevd','pdb','ipdb','pdbpp','pydevconsole'):\n"
    "        if __m in __S__.modules:\n"
    "            __S__.stderr.write('error: debugger detected\\n'); __S__.exit(1)\n";

static const char ANTI_HOOK_CODE[] =
    "    for _n in ('__import__','compile','exec'):\n"
    "        _f = getattr(__S__.modules.get('builtins'), _n, None)\n"
    "        if _f is not None:\n"
    "            _g = getattr(_f, '__name__', '')\n"
    "            if _g != _n:\n"
    "                __S__.stderr.write('error: hook detected\\n'); __S__.exit(1)\n"
    "    if len(__S__.meta_path) > 5:\n"
    "        __S__.stderr.write('error: import hook detected\\n'); __S__.exit(1)\n"
    "    if getattr(__S__, 'flags', None) and __S__.flags.no_user_site:\n"
    "        __S__.stderr.write('error: sandbox detected\\n'); __S__.exit(1)\n";

static void key_obfuscate(const char *key, size_t key_len, int xor_byte, char *out) {
    for (size_t i = 0; i < key_len; i++)
        sprintf(out + i * 2, "%02x", (unsigned char)(key[i] ^ xor_byte));
    out[key_len * 2] = '\0';
}

static int stub_algo_id(Algorithm algo) {
    switch (algo) {
        case ALGO_AES_ECB:  return 0;
        case ALGO_AES_CBC:  return 1;
        case ALGO_AES_CTR:  return 2;
        case ALGO_AES_GCM:  return 3;
        case ALGO_CHACHA20: return 4;
        case ALGO_XOR:      return 5;
        case ALGO_ROLLING_XOR: return 11;
        case ALGO_MULTI_PASS_XOR: return 12;
        case ALGO_PRNG_XOR: return 13;
        case ALGO_BASE64:   return 6;
        case ALGO_BASE32:   return 7;
        case ALGO_BASE85:   return 8;
        case ALGO_ASCII85:  return 9;
        case ALGO_HEX:      return 10;
        default:            return -1;
    }
}

static const char *algo_name(Algorithm algo) {
    switch (algo) {
        case ALGO_AES_ECB:  return "aes-256-ecb";
        case ALGO_AES_CBC:  return "aes-256-cbc";
        case ALGO_AES_CTR:  return "aes-256-ctr";
        case ALGO_AES_GCM:  return "aes-256-gcm";
        case ALGO_ROLLING_XOR: return "rolling-xor";
        case ALGO_MULTI_PASS_XOR: return "multi-pass-xor";
        case ALGO_PRNG_XOR: return "prng-xor";
        case ALGO_CHACHA20: return "chacha20";
        case ALGO_XOR:      return "xor";
        case ALGO_BASE64:   return "base64";
        case ALGO_BASE32:   return "base32";
        case ALGO_BASE85:   return "base85";
        case ALGO_ASCII85:  return "ascii85";
        case ALGO_HEX:      return "hex";
        default:            return "?";
    }
}

static int needs_key(Algorithm algo) {
    return algo == ALGO_AES_ECB || algo == ALGO_AES_CBC ||
           algo == ALGO_AES_CTR || algo == ALGO_AES_GCM ||
           algo == ALGO_CHACHA20 || algo == ALGO_XOR || algo == ALGO_ROLLING_XOR ||
           algo == ALGO_MULTI_PASS_XOR || algo == ALGO_PRNG_XOR;
}

// Run python3 with arguments, redirecting stdio to the given files.
// argv must contain the argument vector starting after "python3" (i.e.,
// argv[0] = script path, argv[1..] = script args). argv must be NULL-terminated.
// Returns 0 on success, non-zero on failure (program exit code or -1).
static int run_python3(const char **argv,
                        const char *stdin_file,
                        const char *stdout_file,
                        const char *stderr_file) {
    pid_t pid = fork();
    if (pid == -1) return -1;
    if (pid == 0) {
        if (stdin_file) {
            int fd = open(stdin_file, O_RDONLY);
            if (fd >= 0) { dup2(fd, STDIN_FILENO); close(fd); }
        }
        if (stdout_file) {
            int fd = open(stdout_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd >= 0) { dup2(fd, STDOUT_FILENO); close(fd); }
        }
        if (stderr_file) {
            int fd = open(stderr_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd >= 0) { dup2(fd, STDERR_FILENO); close(fd); }
        }
        // Build full argv: python3, script, args..., NULL
        int argc = 0;
        while (argv[argc]) argc++;
        const char *full_argv[16];
        int i = 0;
        full_argv[i++] = "python3";
        for (int j = 0; j < argc && i < 15; j++)
            full_argv[i++] = argv[j];
        full_argv[i] = NULL;
        execvp("python3", (char *const *)full_argv);
        _exit(127);
    }
    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return -1;
}

static ExitCode obfuscate_source(const char *src, size_t src_len,
                                  const char *techniques,
                                  Buffer *out) {
    char obf_tmpl[] = "/tmp/crypto_obf_XXXXXX.py";
    char in_tmpl[]  = "/tmp/crypto_in_XXXXXX.py";
    char out_tmpl[] = "/tmp/crypto_out_XXXXXX.py";

    int obf_fd = mkstemps(obf_tmpl, 3);
    int in_fd  = mkstemps(in_tmpl, 3);
    int out_fd = mkstemps(out_tmpl, 3);
    int have_fds = (obf_fd >= 0 && in_fd >= 0 && out_fd >= 0) ? 1 : 0;

    if (!have_fds) {
        if (obf_fd >= 0) { close(obf_fd); unlink(obf_tmpl); }
        if (in_fd >= 0)  { close(in_fd);  unlink(in_tmpl); }
        if (out_fd >= 0) { close(out_fd); unlink(out_tmpl); }
        return EXIT_ERR_CRYPTO;
    }

    size_t slen = strlen(PYOBF_SCRIPT);
    if (write(obf_fd, PYOBF_SCRIPT, slen) != (ssize_t)slen ||
        write(in_fd, src, src_len) != (ssize_t)src_len) {
        close(obf_fd); close(in_fd); close(out_fd);
        unlink(obf_tmpl); unlink(in_tmpl); unlink(out_tmpl);
        return EXIT_ERR_FILE;
    }
    close(obf_fd); close(in_fd);

    const char *argv[] = {obf_tmpl, techniques, NULL};
    if (run_python3(argv, in_tmpl, out_tmpl, NULL) != 0) {
        close(out_fd); unlink(obf_tmpl); unlink(in_tmpl); unlink(out_tmpl);
        return EXIT_ERR_CRYPTO;
    }

    off_t fsz = lseek(out_fd, 0, SEEK_END);
    if (fsz <= 0) { close(out_fd); unlink(obf_tmpl); unlink(in_tmpl); unlink(out_tmpl); return EXIT_ERR_CRYPTO; }
    lseek(out_fd, 0, SEEK_SET);

    out->data = (unsigned char *)malloc((size_t)fsz + 1);
    if (!out->data) { close(out_fd); unlink(obf_tmpl); unlink(in_tmpl); unlink(out_tmpl); return EXIT_ERR_CRYPTO; }

    ssize_t nr = read(out_fd, out->data, (size_t)fsz);
    if (nr != fsz) { free(out->data); out->data = NULL; close(out_fd); unlink(obf_tmpl); unlink(in_tmpl); unlink(out_tmpl); return EXIT_ERR_FILE; }
    out->data[nr] = '\0';
    out->size = (size_t)nr;

    close(out_fd);
    unlink(obf_tmpl); unlink(in_tmpl); unlink(out_tmpl);
    return EXIT_OK;
}

static ExitCode vm_split_source(const char *src, size_t src_len,
                                const char *obf_tmpl_path,
                                const char *techniques,
                                Buffer *exec_out, Buffer *vm_out) {
    // Writes VM_SPLIT_SCRIPT to temp file and runs it to
    // split obfuscated source into:
    //   exec_out = function/class defs with FULL obfuscation
    //   vm_out   = clean module-level code with renamed names
    char split_tmpl[] = "/tmp/crypto_split_XXXXXX.py";
    char in_tmpl[]    = "/tmp/crypto_split_in_XXXXXX.py";
    char out_tmpl[]   = "/tmp/crypto_split_out_XXXXXX";

    int fd_s = mkstemps(split_tmpl, 3);
    int fd_i = mkstemps(in_tmpl, 3);
    int fd_o = mkstemps(out_tmpl, 0);

    if (fd_s < 0 || fd_i < 0 || fd_o < 0) {
        if (fd_s >= 0) { close(fd_s); unlink(split_tmpl); }
        if (fd_i >= 0) { close(fd_i); unlink(in_tmpl); }
        if (fd_o >= 0) { close(fd_o); unlink(out_tmpl); }
        return EXIT_ERR_CRYPTO;
    }

    size_t slen = strlen(VM_SPLIT_SCRIPT);
    if (write(fd_s, VM_SPLIT_SCRIPT, slen) != (ssize_t)slen ||
        write(fd_i, src, src_len) != (ssize_t)src_len) {
        close(fd_s); close(fd_i); close(fd_o);
        unlink(split_tmpl); unlink(in_tmpl); unlink(out_tmpl);
        return EXIT_ERR_FILE;
    }
    close(fd_s); close(fd_i);

    const char *tech = techniques ? techniques : "rename";
    char err_tmpl[sizeof(out_tmpl) + 8];
    snprintf(err_tmpl, sizeof(err_tmpl), "%s.err", out_tmpl);
    const char *argv[] = {split_tmpl, obf_tmpl_path, tech, NULL};
    if (run_python3(argv, in_tmpl, out_tmpl, err_tmpl) != 0) {
        close(fd_o); unlink(split_tmpl); unlink(in_tmpl); unlink(out_tmpl);
        return EXIT_ERR_CRYPTO;
    }

    off_t fsz = lseek(fd_o, 0, SEEK_END);
    if (fsz <= 0) { close(fd_o); unlink(split_tmpl); unlink(in_tmpl); unlink(out_tmpl); return EXIT_ERR_CRYPTO; }
    lseek(fd_o, 0, SEEK_SET);

    unsigned char *data = (unsigned char *)malloc((size_t)fsz + 1);
    if (!data) { close(fd_o); unlink(split_tmpl); unlink(in_tmpl); unlink(out_tmpl); return EXIT_ERR_CRYPTO; }

    ssize_t nr = read(fd_o, data, (size_t)fsz);
    close(fd_o);
    unlink(split_tmpl); unlink(in_tmpl); unlink(out_tmpl);
    if (nr != fsz) { free(data); return EXIT_ERR_FILE; }
    data[nr] = '\0';

    // Parse markers: #===EXEC_SOURCE=== ... #===VM_SOURCE=== ...
    const char *exec_marker = "#===EXEC_SOURCE===\n";
    const char *vm_marker   = "#===VM_SOURCE===\n";

    char *exec_start = strstr((char *)data, exec_marker);
    char *vm_start   = strstr((char *)data, vm_marker);

    if (!exec_start || !vm_start) {
        free(data);
        return EXIT_ERR_CRYPTO;
    }

    exec_start += strlen(exec_marker);
    // exec_source: from exec_start to vm_marker - 1 (strip trailing newline)
    size_t exec_len = (size_t)(vm_start - exec_start);
    if (exec_len > 0 && exec_start[exec_len - 1] == '\n')
        exec_len--;

    vm_start += strlen(vm_marker);
    size_t vm_len = (size_t)(nr - (vm_start - (char *)data));
    if (vm_len > 0 && vm_start[vm_len - 1] == '\n')
        vm_len--;

    exec_out->data = (unsigned char *)malloc(exec_len + 1);
    vm_out->data   = (unsigned char *)malloc(vm_len + 1);
    if (!exec_out->data || !vm_out->data) {
        free(exec_out->data); free(vm_out->data); free(data);
        return EXIT_ERR_CRYPTO;
    }

    memcpy(exec_out->data, exec_start, exec_len);
    exec_out->data[exec_len] = '\0';
    exec_out->size = exec_len;

    memcpy(vm_out->data, vm_start, vm_len);
    vm_out->data[vm_len] = '\0';
    vm_out->size = vm_len;

    free(data);
    return EXIT_OK;
}

// Clean split (no obfuscation): split source into function/class defs (exec)
// and module-level code (VM). Uses a pass-through "obfuscation" script.
static ExitCode vm_split_source_clean(const char *src, size_t src_len,
                                       Buffer *exec_out, Buffer *vm_out) {
    char obf_tmpl[] = "/tmp/crypto_nop_XXXXXX.py";
    int obf_fd = mkstemps(obf_tmpl, 3);
    if (obf_fd < 0) return EXIT_ERR_CRYPTO;

    const char *nop_script = "#!/usr/bin/env python3\nimport sys\nsys.stdout.write(sys.stdin.read())\n";
    size_t slen = strlen(nop_script);
    if (write(obf_fd, nop_script, slen) != (ssize_t)slen) {
        close(obf_fd); unlink(obf_tmpl);
        return EXIT_ERR_FILE;
    }
    close(obf_fd);

    ExitCode ret = vm_split_source(src, src_len, obf_tmpl, "rename", exec_out, vm_out);
    unlink(obf_tmpl);
    return ret;
}

// ── VM bytecode obfuscation ─────────────────────────────────────────────
// Insert NOP instructions at random positions and fix up jump targets.
static void vm_obfuscate_program(VmProgram *prog) {
    int n = prog->count;
    if (n <= 3) return;

    int extra = n / 4 + 1;
    if (extra > 20) extra = 20;
    int new_count = n + extra;

    VmInstr *new_instrs = (VmInstr *)calloc((size_t)new_count, sizeof(VmInstr));
    if (!new_instrs) return;

    // Choose random NOP positions
    char *is_nop = (char *)calloc((size_t)new_count, 1);
    if (!is_nop) { free(new_instrs); return; }
    int inserted = 0;
    while (inserted < extra) {
        int pos = rand() % new_count;
        if (!is_nop[pos]) {
            is_nop[pos] = 1;
            inserted++;
        }
    }

    // Build old→new index mapping and fill new array
    int *old_to_new = (int *)malloc((size_t)n * sizeof(int));
    if (!old_to_new) { free(new_instrs); free(is_nop); return; }
    int src_i = 0;
    for (int dst_i = 0; dst_i < new_count; dst_i++) {
        if (is_nop[dst_i]) {
            new_instrs[dst_i].op  = 0; // NOP
            new_instrs[dst_i].rd  = (uint8_t)(rand() % 64);
            new_instrs[dst_i].rs1 = (uint8_t)(rand() % 64);
            new_instrs[dst_i].rs2 = (uint8_t)(rand() % 64);
            new_instrs[dst_i].imm = rand();
        } else {
            new_instrs[dst_i] = prog->instrs[src_i];
            old_to_new[src_i] = dst_i;
            src_i++;
        }
    }

    // Fix jump targets (opcodes 30=JMP, 31=JMP_IF_TRUE, 32=JMP_IF_FALSE)
    for (int i = 0; i < new_count; i++) {
        if (new_instrs[i].op == 30 ||
            new_instrs[i].op == 31 ||
            new_instrs[i].op == 32) {
            int old_target = new_instrs[i].imm;
            if (old_target >= 0 && old_target < n) {
                new_instrs[i].imm = old_to_new[old_target];
            }
        }
    }

    free(prog->instrs);
    free(is_nop);
    free(old_to_new);
    prog->instrs = new_instrs;
    prog->count = new_count;
}

ExitCode protect_file(const char *input, const char *output,
                      Algorithm algo, const char *key,
                      const char *obf_techniques,
                      const char *anti_analysis,
                      int compress_algo, int compress_level,
                      int use_vm) {
    int sa_id = stub_algo_id(algo);
    if (sa_id < 0) {
        fprintf(stderr, "error: unsupported algorithm for protect\n");
        return EXIT_ERR_ARGS;
    }
    if (needs_key(algo) && (!key || strlen(key) == 0)) {
        fprintf(stderr, "error: protect requires a non-empty key for this algorithm\n");
        return EXIT_ERR_ARGS;
    }

    srand((unsigned)(time(NULL) ^ (uintptr_t)sa_id ^ (uintptr_t)input ^ (uintptr_t)output));
    int xor_byte = rand_range(1, 254);

    // ── anti-analysis assembly (with __S__ placeholder) ──
    int use_debug = 0, use_hook = 0, use_scramble = 0, use_opaque = 0;
    if (anti_analysis && anti_analysis[0]) {
        const char *p = anti_analysis;
        while (*p) {
            while (*p == ' ' || *p == ',') p++;
            if      (strncmp(p, "debug", 5) == 0) { use_debug = 1; p += 5; }
            else if (strncmp(p, "hook",  4) == 0) { use_hook  = 1; p += 4; }
            else if (strncmp(p, "scramble", 8) == 0) { use_scramble = 1; p += 8; }
            else if (strncmp(p, "opaque", 6) == 0) { use_opaque = 1; p += 6; }
            else if (strncmp(p, "all", 3) == 0) { use_debug = use_hook = use_scramble = use_opaque = 1; p += 3; }
            else    { while (*p && *p != ',') p++; }
        }
    }

    FileBuffer buf;
    ExitCode ret = file_read(input, &buf);
    if (ret != EXIT_OK) return ret;

    Buffer obf_buf = {0};
    Buffer exec_buf = {0};
    Buffer vm_buf_src = {0};
    unsigned char *src_data = buf.data;
    size_t src_size = buf.size;

    int vm_obf_enabled = 0;

    if (use_vm) {
        if (obf_techniques && obf_techniques[0]) {
            // VM + obf: split + obfuscate in one pipeline pass.
            // Pipeline handles rename-only pass for name mapping, then
            // applies remaining techniques to func defs only.
            char obf_tmpl[] = "/tmp/crypto_vmobf_XXXXXX.py";
            int obf_fd = mkstemps(obf_tmpl, 3);
            if (obf_fd < 0) { file_buffer_free(&buf); return EXIT_ERR_CRYPTO; }
            size_t slen = strlen(PYOBF_SCRIPT);
            if (write(obf_fd, PYOBF_SCRIPT, slen) != (ssize_t)slen) {
                close(obf_fd); unlink(obf_tmpl);
                file_buffer_free(&buf); return EXIT_ERR_FILE;
            }
            close(obf_fd);

            ret = vm_split_source((const char *)buf.data, buf.size,
                                  obf_tmpl, obf_techniques,
                                  &exec_buf, &vm_buf_src);
            unlink(obf_tmpl);
            if (ret != EXIT_OK) {
                fprintf(stderr, "[vm] error: split+obf failed\n");
                file_buffer_free(&buf);
                return ret;
            }
            printf("[vm] split+obf: %s (%zu bytes exec + %zu bytes VM source)\n",
                   obf_techniques, exec_buf.size, vm_buf_src.size);
            vm_obf_enabled = 1;
        } else {
            // VM only (no obfuscation): clean split
            ret = vm_split_source_clean((const char *)buf.data, buf.size,
                                        &exec_buf, &vm_buf_src);
            if (ret != EXIT_OK) {
                fprintf(stderr, "[vm] error: clean split failed\n");
                file_buffer_free(&buf);
                return ret;
            }
            printf("[vm] split: %zu bytes exec + %zu bytes VM source\n",
                   exec_buf.size, vm_buf_src.size);
        }
    } else if (obf_techniques && obf_techniques[0]) {
        // Normal obfuscation (non-VM mode)
        ret = obfuscate_source((const char *)buf.data, buf.size,
                                 obf_techniques, &obf_buf);
        if (ret == EXIT_OK) {
            printf("[obf] obfuscated with: %s (%zu -> %zu bytes)\n",
                   obf_techniques, buf.size, obf_buf.size);
            src_data = obf_buf.data;
            src_size = obf_buf.size;

            if (has_tech(obf_techniques, "rolling-xor")) {
                Buffer rx_buf = {0};
                if (apply_rolling_xor_obfuscation((const char *)src_data, src_size, &rx_buf) == EXIT_OK) {
                    printf("[obf] applied rolling-xor wrapper (%zu -> %zu bytes)\n", src_size, rx_buf.size);
                    free(obf_buf.data);
                    obf_buf = rx_buf;
                    src_data = obf_buf.data;
                    src_size = obf_buf.size;
                }
            }
            if (has_tech(obf_techniques, "xor-bit-rotation")) {
                Buffer xbr_buf = {0};
                if (apply_xor_bit_rotation_obfuscation((const char *)src_data, src_size, &xbr_buf) == EXIT_OK) {
                    printf("[obf] applied xor-bit-rotation wrapper (%zu -> %zu bytes)\n", src_size, xbr_buf.size);
                    free(obf_buf.data);
                    obf_buf = xbr_buf;
                    src_data = obf_buf.data;
                    src_size = obf_buf.size;
                }
            }
        } else {
            fprintf(stderr, "[obf] warning: obfuscation failed, using original\n");
        }
    }


    char *vm_xor_key_hex = NULL;
    int vm_obf_algo = 0;
    size_t key_len = key ? strlen(key) : 0;

    unsigned char *pt = NULL;
    size_t ptsz = 0;
    Buffer vm_buf = {0};

    if (use_vm) {
        // VM mode: compile VM source to VM bytecodes
        VmProgram vm_prog;
        vm_program_init(&vm_prog);

        const char *vm_src = (const char *)(vm_buf_src.data ? vm_buf_src.data : src_data);
        size_t vm_src_len = vm_buf_src.data ? vm_buf_src.size : src_size;

        // Compile CLEAN VM source (always clean — no obfuscation in VM source)
        ret = vm_compile_source(vm_src, vm_src_len, &vm_prog, use_opaque);
        if (ret != EXIT_OK) {
            fprintf(stderr, "[vm] error: VM compilation failed\n");
            file_buffer_free(&buf); free(obf_buf.data);
            free(exec_buf.data); free(vm_buf_src.data);
            return ret;
        }

        // Obfuscate VM bytecode (if obfuscation enabled)
        if (vm_obf_enabled) {
            vm_obfuscate_program(&vm_prog);
        }
        
        if (obf_techniques && has_tech(obf_techniques, "rolling-xor")) {
            Buffer rx_exec = {0};
            if (apply_rolling_xor_obfuscation((const char *)exec_buf.data, exec_buf.size, &rx_exec) == EXIT_OK) {
                printf("[vm] applied rolling-xor wrapper to exec source\n");
                free(exec_buf.data);
                exec_buf = rx_exec;
            }
        }
        if (obf_techniques && has_tech(obf_techniques, "xor-bit-rotation")) {
            Buffer xbr_exec = {0};
            if (apply_xor_bit_rotation_obfuscation((const char *)exec_buf.data, exec_buf.size, &xbr_exec) == EXIT_OK) {
                printf("[vm] applied xor-bit-rotation wrapper to exec source\n");
                free(exec_buf.data);
                exec_buf = xbr_exec;
            }
        }

        // Always replace hot source with exec_source.

        // When exec_source is empty (no function defs), exec() does nothing
        // and only _vm_run executes module-level code (no duplicate).
        free(vm_prog.hot_src);
        vm_prog.hot_src = strdup(exec_buf.data ? (const char *)exec_buf.data : "");
        if (!vm_prog.hot_src) {
            vm_program_free(&vm_prog);
            file_buffer_free(&buf); free(obf_buf.data);
            free(exec_buf.data); free(vm_buf_src.data);
            return EXIT_ERR_CRYPTO;
        }

        // Serialize VM program
        ret = vm_serialize(&vm_prog, &vm_buf);
        if (ret != EXIT_OK) {
            vm_program_free(&vm_prog);
            file_buffer_free(&buf); free(obf_buf.data);
            free(exec_buf.data); free(vm_buf_src.data);
            return ret;
        }

        // XOR-encrypt the serialized VM data (if obfuscation enabled)
        if (vm_obf_enabled) {
            if (obf_techniques && has_tech(obf_techniques, "rolling-xor")) {
                vm_obf_algo = 1;
                unsigned char vkey[32];
                if (RAND_bytes(vkey, 32) != 1) { file_buffer_free(&buf); return EXIT_ERR_CRYPTO; }
                
                Buffer encrypted_vm = {0};
                if (rolling_xor_encrypt(vm_buf.data, vm_buf.size, vkey, 32, &encrypted_vm) == EXIT_OK) {
                    free(vm_buf.data);
                    vm_buf = encrypted_vm;
                    
                    vm_xor_key_hex = (char *)malloc(65);
                    for (int i = 0; i < 32; i++) sprintf(vm_xor_key_hex + i * 2, "%02x", vkey[i]);
                    vm_xor_key_hex[64] = '\0';
                    printf("[vm] Rolling-XOR-encrypted VM data\n");
                } else {
                    file_buffer_free(&buf); return EXIT_ERR_CRYPTO;
                }
            } else if (obf_techniques && has_tech(obf_techniques, "xor-bit-rotation")) {
                vm_obf_algo = 2;
                unsigned char vkey[32];
                if (RAND_bytes(vkey, 32) != 1) { file_buffer_free(&buf); return EXIT_ERR_CRYPTO; }
                
                Buffer encrypted_vm = {0};
                if (xor_bit_rotation_encrypt(vm_buf.data, vm_buf.size, vkey, 32, &encrypted_vm) == EXIT_OK) {
                    free(vm_buf.data);
                    vm_buf = encrypted_vm;
                    
                    vm_xor_key_hex = (char *)malloc(65);
                    for (int i = 0; i < 32; i++) sprintf(vm_xor_key_hex + i * 2, "%02x", vkey[i]);
                    vm_xor_key_hex[64] = '\0';
                    printf("[vm] XOR-Bit-Rotation-encrypted VM data\n");
                } else {
                    file_buffer_free(&buf); return EXIT_ERR_CRYPTO;
                }
            } else {
                vm_obf_algo = 0;
                int v_key = rand_range(1, 255);
                for (size_t i = 0; i < vm_buf.size; i++) {
                    vm_buf.data[i] ^= (unsigned char)v_key;
                }
                vm_xor_key_hex = (char *)malloc(12);
                sprintf(vm_xor_key_hex, "%d", v_key);
                printf("[vm] XOR-encrypted VM data with key %d\n", v_key);
            }
        }

        printf("[vm] compiled %zu bytes -> %zu bytes VM (%d instrs, %d consts, %d names)\n",
               vm_src_len, vm_buf.size, vm_prog.count, vm_prog.const_count, vm_prog.name_count);

        // Build header: version=2 for VM mode
        unsigned char hdr[HEADER_SIZE] = {2, (unsigned char)compress_algo, (unsigned char)sa_id, 0};
        ptsz = HEADER_SIZE + vm_buf.size;
        pt = (unsigned char *)malloc(ptsz);
        if (!pt) {
            free(vm_buf.data); vm_program_free(&vm_prog);
            file_buffer_free(&buf); free(obf_buf.data);
            free(exec_buf.data); free(vm_buf_src.data);
            return EXIT_ERR_CRYPTO;
        }
        memcpy(pt, hdr, HEADER_SIZE);
        memcpy(pt + HEADER_SIZE, vm_buf.data, vm_buf.size);
        vm_program_free(&vm_prog);
    } else {
        // Normal mode: compress source
        Buffer comp = {0};
        ret = compress_data(src_data, src_size, compress_algo, compress_level, &comp);
        if (ret != EXIT_OK) {
            file_buffer_free(&buf); free(obf_buf.data);
            return ret;
        }

        unsigned char hdr[HEADER_SIZE] = {1, (unsigned char)compress_algo, (unsigned char)sa_id, 0};
        ptsz = HEADER_SIZE + comp.size;
        pt = (unsigned char *)malloc(ptsz);
        if (!pt) { free(comp.data); file_buffer_free(&buf); free(obf_buf.data); return EXIT_ERR_CRYPTO; }
        memcpy(pt, hdr, HEADER_SIZE);
        memcpy(pt + HEADER_SIZE, comp.data, comp.size);
        free(comp.data);
    }

    Buffer enc = {0};
    switch (algo) {
        case ALGO_AES_ECB:
            ret = aes_encrypt(pt, ptsz, (const unsigned char *)key, key_len, AES_ECB, &enc);
            break;
        case ALGO_AES_CBC:
            ret = aes_encrypt(pt, ptsz, (const unsigned char *)key, key_len, AES_CBC, &enc);
            break;
        case ALGO_AES_CTR:
            ret = aes_encrypt(pt, ptsz, (const unsigned char *)key, key_len, AES_CTR, &enc);
            break;
        case ALGO_AES_GCM:
            ret = aes_encrypt(pt, ptsz, (const unsigned char *)key, key_len, AES_GCM, &enc);
            break;
        case ALGO_CHACHA20:
            ret = chacha20_encrypt(pt, ptsz, (const unsigned char *)key, key_len, &enc);
            break;
        case ALGO_XOR:
            ret = xor_encrypt_protect(pt, ptsz, (const unsigned char *)key, key_len, &enc);
            break;
        case ALGO_ROLLING_XOR:
            ret = rolling_xor_encrypt_protect(pt, ptsz, (const unsigned char *)key, key_len, &enc);
            break;
        case ALGO_MULTI_PASS_XOR:
            ret = multi_pass_xor_encrypt_protect(pt, ptsz, (const unsigned char *)key, key_len, &enc);
            break;
        case ALGO_PRNG_XOR:
            ret = prng_xor_encrypt_protect(pt, ptsz, (const unsigned char *)key, key_len, &enc);
            break;
        case ALGO_BASE64:
            ret = base64_encode(pt, ptsz, &enc);
            break;
        case ALGO_BASE32:
            ret = base32_encode(pt, ptsz, &enc);
            break;
        case ALGO_BASE85:
            ret = base85_encode(pt, ptsz, &enc);
            break;
        case ALGO_ASCII85:
            ret = ascii85_encode(pt, ptsz, &enc);
            break;
        case ALGO_HEX:
            ret = hex_encode(pt, ptsz, &enc);
            break;
        default:
            ret = EXIT_ERR_INTERNAL;
            break;
    }
    free(pt);
    if (ret != EXIT_OK) { file_buffer_free(&buf); free(obf_buf.data); free(exec_buf.data); free(vm_buf_src.data); return ret; }

    Buffer b64 = {0};
    ret = base64_encode(enc.data, enc.size, &b64);
    free(enc.data);
    if (ret != EXIT_OK) { file_buffer_free(&buf); free(obf_buf.data); free(exec_buf.data); free(vm_buf_src.data); return ret; }

    char algo_id[12];
    snprintf(algo_id, sizeof(algo_id), "%d", sa_id);

    char *obf_key = NULL;
    size_t obf_len = 0;
    if (needs_key(algo)) {
        obf_len = key_len * 2;
        obf_key = (char *)malloc(obf_len + 1);
        if (!obf_key) { free(b64.data); file_buffer_free(&buf); free(obf_buf.data); free(exec_buf.data); free(vm_buf_src.data); return EXIT_ERR_CRYPTO; }
        key_obfuscate(key, key_len, xor_byte, obf_key);
    } else {
        obf_key = (char *)malloc(1);
        if (!obf_key) { free(b64.data); file_buffer_free(&buf); free(obf_buf.data); free(exec_buf.data); free(vm_buf_src.data); return EXIT_ERR_CRYPTO; }
        obf_key[0] = '\0';
        obf_len = 0;
    }

    char anti_buf[4096];
    // ── build anti-analysis buffer ──
    size_t anti_pos = 0;
    if (use_debug) {
        size_t sl = strlen(ANTI_DEBUG_CODE);
        if (anti_pos + sl < sizeof(anti_buf)) {
            memcpy(anti_buf + anti_pos, ANTI_DEBUG_CODE, sl);
            anti_pos += sl;
        }
    }
    if (use_hook) {
        size_t sl = strlen(ANTI_HOOK_CODE);
        if (anti_pos + sl < sizeof(anti_buf)) {
            memcpy(anti_buf + anti_pos, ANTI_HOOK_CODE, sl);
            anti_pos += sl;
        }
    }
    anti_buf[anti_pos] = '\0';
    const char *anti_code = anti_buf;
    size_t anti_len = anti_pos;

    // ── generate polymorphic stub ──
    Buffer stub_buf = {0};
    srand((unsigned)(time(NULL) ^ (uintptr_t)&stub_buf));
    ret = generate_stub((const char *)b64.data, b64.size,
                           algo_id, obf_key, obf_len,
                           anti_code, anti_len, xor_byte, compress_algo,
                           use_vm, use_scramble,
                           vm_xor_key_hex, vm_obf_algo,
                           &stub_buf);
    free(b64.data); free(obf_key); free(vm_xor_key_hex);

    if (ret != EXIT_OK) {
        file_buffer_free(&buf); free(obf_buf.data); free(exec_buf.data); free(vm_buf_src.data);
        return ret;
    }

    printf("[protect] %s (%s) %zu bytes -> %s (%zu bytes)\n",
           input, algo_name(algo), buf.size, output, stub_buf.size);

    FILE *f = fopen(output, "w");
    if (!f) {
        fprintf(stderr, "error: cannot write '%s'\n", output);
        free(stub_buf.data); file_buffer_free(&buf); free(obf_buf.data); free(exec_buf.data); free(vm_buf_src.data);
        return EXIT_ERR_FILE;
    }
    size_t written = fwrite(stub_buf.data, 1, stub_buf.size, f);
    fclose(f);

    free(stub_buf.data); file_buffer_free(&buf); free(obf_buf.data); free(exec_buf.data); free(vm_buf_src.data);

    if (written != stub_buf.size) {
        fprintf(stderr, "error: failed to write '%s'\n", output);
        return EXIT_ERR_FILE;
    }
    return EXIT_OK;
}
