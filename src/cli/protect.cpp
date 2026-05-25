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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>

#define HEADER_SIZE 4
#define SALT_SIZE 16
#define HMAC_SIZE 32

// ── helpers ─────────────────────────────────────────────────────────────────

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

static ExitCode generate_stub(const char *b64_data, size_t b64_sz,
                               const char *algo_id,
                               const char *obf_key, size_t obf_key_len,
                               const char *anti_code, size_t anti_len,
                               int xor_byte,
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
    char n_c[16], n_a[16], n_d[16];
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

    // ── main function ──
    sb_printf(&p, end, "def %s():\n", n_fn);

    // Anti-analysis code (indented by 4 spaces)
    if (anti_len > 0) {
        sb_append(&p, end, anti_code);
    }
    free(patched_anti);

    // Key deobfuscation
    sb_printf(&p, end, "    %s = bytes.fromhex(\"%s\")\n", n_k, obf_key);
    if (obf_key_len > 0) {
        sb_printf(&p, end, "    %s = bytes(_ ^ %d for _ in %s).decode()\n",
                  n_k, xor_byte, n_k);
    }

    sb_printf(&p, end, "    %s = %s.b64decode(%s)\n", n_r, n_b, n_P);

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

    // ── generate algorithm blocks (dispatch) ──
    // Build a shuffled order for _A values
    // We always include all 11 algorithms, but in random order
    int order[11] = {0,1,2,3,4,5,6,7,8,9,10};
    // Fisher-Yates shuffle
    for (int i = 10; i > 0; i--) {
        int j = rand() % (i + 1);
        int tmp = order[i]; order[i] = order[j]; order[j] = tmp;
    }

    // Track which blocks have been emitted
    int emitted[11] = {0};
    int is_first = 1;

    for (int oi = 0; oi < 11; oi++) {
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
            sb_printf(&p, end, "        %s = %s.decryptor().update(%s) + %s.finalize()\n",
                      n_9, n_8, n_1, n_8);
            sb_printf(&p, end, "        %s = %s[-1]\n"
                      "        if %s < 1 or %s > 16 or not all(_ == %s for _ in %s[-%s:]):\n"
                      "            %s.stderr.write(\"error: decryption failed\\n\"); %s.exit(1)\n"
                      "        %s = %s[:-%s]\n",
                      n_9, n_9, n_9, n_9, n_9, n_9, n_9, n_s, n_s, n_9, n_9, n_9);
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
            sb_printf(&p, end, "        %s = %s.decryptor().update(%s) + %s.finalize()\n",
                      n_9, n_8, n_1, n_8);
            sb_printf(&p, end, "        %s = %s[-1]\n"
                      "        if %s < 1 or %s > 16 or not all(_ == %s for _ in %s[-%s:]):\n"
                      "            %s.stderr.write(\"error: decryption failed\\n\"); %s.exit(1)\n"
                      "        %s = %s[:-%s]\n",
                      n_9, n_9, n_9, n_9, n_9, n_9, n_9, n_s, n_s, n_9, n_9, n_9);
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
        }
        emitted[aid] = 1;
    }

    // else block for unknown algo
    sb_printf(&p, end, "    else:\n"
              "        %s.stderr.write(\"error: unsupported algorithm\\n\"); %s.exit(1)\n",
              n_s, n_s);

    // Decompress and execute
    sb_printf(&p, end, "    if %s[1] & 1:\n"
              "        %s = %s.decompress(%s[4:])\n"
              "    else:\n"
              "        %s = %s[4:]\n"
              "    exec(compile(%s, '<protected>', 'exec'), globals())\n\n",
              n_9, n_9, n_z, n_9, n_9, n_9, n_9);

    // Guard
    sb_printf(&p, end, "if __name__ == '__main__':\n"
              "    %s()\n", n_fn);

    out->data = (unsigned char *)buf;
    out->size = (size_t)(p - buf);
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
           algo == ALGO_CHACHA20 || algo == ALGO_XOR;
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

    char cmd[8192];
    int n = snprintf(cmd, sizeof(cmd), "python3 %s %s < %s > %s",
                     obf_tmpl, techniques, in_tmpl, out_tmpl);
    if (n < 0 || (size_t)n >= sizeof(cmd)) {
        close(out_fd); unlink(obf_tmpl); unlink(in_tmpl); unlink(out_tmpl);
        return EXIT_ERR_INTERNAL;
    }

    if (system(cmd) != 0) {
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

ExitCode protect_file(const char *input, const char *output,
                      Algorithm algo, const char *key,
                      const char *obf_techniques,
                      const char *anti_analysis) {
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

    FileBuffer buf;
    ExitCode ret = file_read(input, &buf);
    if (ret != EXIT_OK) return ret;

    Buffer obf_buf = {0};
    unsigned char *src_data = buf.data;
    size_t src_size = buf.size;

    if (obf_techniques && obf_techniques[0]) {
        ret = obfuscate_source((const char *)buf.data, buf.size,
                                obf_techniques, &obf_buf);
        if (ret == EXIT_OK) {
            printf("[obf] obfuscated with: %s (%zu -> %zu bytes)\n",
                   obf_techniques, buf.size, obf_buf.size);
            src_data = obf_buf.data;
            src_size = obf_buf.size;
        } else {
            fprintf(stderr, "[obf] warning: obfuscation failed, using original\n");
        }
    }

    size_t key_len = key ? strlen(key) : 0;

    unsigned char hdr[HEADER_SIZE] = {1, 1, 0, 0};
    hdr[2] = (unsigned char)sa_id;

    uLongf cmax = compressBound(src_size);
    Bytef *comp = (Bytef *)malloc(cmax);
    if (!comp) { file_buffer_free(&buf); free(obf_buf.data); return EXIT_ERR_CRYPTO; }
    uLongf csz = cmax;
    if (compress(comp, &csz, src_data, src_size) != Z_OK) {
        free(comp); file_buffer_free(&buf); free(obf_buf.data);
        fprintf(stderr, "error: compression failed\n");
        return EXIT_ERR_CRYPTO;
    }

    size_t ptsz = HEADER_SIZE + csz;
    unsigned char *pt = (unsigned char *)malloc(ptsz);
    if (!pt) { free(comp); file_buffer_free(&buf); free(obf_buf.data); return EXIT_ERR_CRYPTO; }
    memcpy(pt, hdr, HEADER_SIZE);
    memcpy(pt + HEADER_SIZE, comp, csz);
    free(comp);

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
    if (ret != EXIT_OK) { file_buffer_free(&buf); free(obf_buf.data); return ret; }

    Buffer b64 = {0};
    ret = base64_encode(enc.data, enc.size, &b64);
    free(enc.data);
    if (ret != EXIT_OK) { file_buffer_free(&buf); free(obf_buf.data); return ret; }

    char algo_id[12];
    snprintf(algo_id, sizeof(algo_id), "%d", sa_id);

    char *obf_key = NULL;
    size_t obf_len = 0;
    if (needs_key(algo)) {
        obf_len = key_len * 2;
        obf_key = (char *)malloc(obf_len + 1);
        if (!obf_key) { free(b64.data); file_buffer_free(&buf); free(obf_buf.data); return EXIT_ERR_CRYPTO; }
        key_obfuscate(key, key_len, xor_byte, obf_key);
    } else {
        obf_key = (char *)malloc(1);
        if (!obf_key) { free(b64.data); file_buffer_free(&buf); free(obf_buf.data); return EXIT_ERR_CRYPTO; }
        obf_key[0] = '\0';
        obf_len = 0;
    }

    // ── anti-analysis assembly (with __S__ placeholder) ──
    int use_debug = 0, use_hook = 0;
    if (anti_analysis && anti_analysis[0]) {
        const char *p = anti_analysis;
        while (*p) {
            while (*p == ' ' || *p == ',') p++;
            if      (strncmp(p, "debug", 5) == 0) { use_debug = 1; p += 5; }
            else if (strncmp(p, "hook",  4) == 0) { use_hook  = 1; p += 4; }
            else    { while (*p && *p != ',') p++; }
        }
    }

    char anti_buf[4096];
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
                         anti_code, anti_len, xor_byte, &stub_buf);
    free(b64.data); free(obf_key);
    if (ret != EXIT_OK) {
        file_buffer_free(&buf); free(obf_buf.data);
        return ret;
    }

    printf("[protect] %s (%s) %zu bytes -> %s (%zu bytes)\n",
           input, algo_name(algo), buf.size, output, stub_buf.size);

    FILE *f = fopen(output, "w");
    if (!f) {
        fprintf(stderr, "error: cannot write '%s'\n", output);
        free(stub_buf.data); file_buffer_free(&buf); free(obf_buf.data);
        return EXIT_ERR_FILE;
    }
    size_t written = fwrite(stub_buf.data, 1, stub_buf.size, f);
    fclose(f);

    free(stub_buf.data); file_buffer_free(&buf); free(obf_buf.data);

    if (written != stub_buf.size) {
        fprintf(stderr, "error: failed to write '%s'\n", output);
        return EXIT_ERR_FILE;
    }
    return EXIT_OK;
}
