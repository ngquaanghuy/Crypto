#include "cli/protect_internal.h"
#ifndef CRYPTO_OBFUSCATE_VM_RUNTIME
#define VM_INTERP_MARSHAL_DUMMY 1
#endif

#include "vm/vm.h"
#include "vm/vm_interp_py.h"
#include "vm/vm_split.h"
#include "crypto/compress.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <format>
#include <string>
#include <vector>
#include <string_view>

namespace protect {

ExitCode generate_stub(const char *b64_data, size_t b64_sz,
                                    const char *algo_id,
                                    const char *obf_key, size_t obf_key_len,
                                    const char *anti_code, size_t anti_len,
                                    int xor_byte, int compress_algo,
                                    int use_vm, int use_scramble,
                                    const char *vm_xor_key, int vm_obf_algo,
                                    const char *vm_nonce_hex,
                                    const char *exec_src,
                                    Buffer *out,
                                    float density,
                                    const MultiLayerKey *ml_key,
                                    int use_antidump) {
    std::string buf;
    buf.reserve(SB_SZ);

    // ── random names ──
    std::string n_h = rand_name(), n_m = rand_name(), n_b = rand_name(), n_s = rand_name(), n_z = rand_name();
    std::string n_P = rand_name(), n_A = rand_name(), n_k = rand_name(), n_r = rand_name(), n_fn = rand_name();
    std::string n_0 = rand_name(), n_1 = rand_name(), n_2 = rand_name(), n_3 = rand_name(), n_4 = rand_name();
    std::string n_5 = rand_name(), n_6 = rand_name(), n_7 = rand_name(), n_8 = rand_name(), n_9 = rand_name();
    std::string n_t = rand_name(), n_ae = rand_name(), n_c = rand_name(), n_a = rand_name(), n_d = rand_name();
    std::string n_vx = rand_name(), n_85t = rand_name(), n_85d = rand_name();
    std::string n_zd = rand_name(), n_zd_arg = rand_name(), n_zd_d = rand_name(), n_zd_i = rand_name();
    std::string n_zd_n = rand_name(), n_zd_cnt = rand_name(), n_zd_nb = rand_name();
    std::string n_ad = rand_name(), n_ad_arg = rand_name(), n_ad_d = rand_name(), n_ad_i = rand_name();
    std::string n_ad_n = rand_name(), n_ad_cnt = rand_name(), n_ad_nb = rand_name();
    std::string j1 = rand_name(), j2 = rand_name(), junk_fn = rand_name();

    // Scramble anti-analysis fragments
    std::vector<std::string> scramble_frags;
    if (use_scramble) {
        scramble_frags.push_back(patch_sys_name(ANTI_FRAG_GETTRACE, n_s));
        scramble_frags.push_back(patch_sys_name(ANTI_FRAG_BREAKPOINT, n_s));
        scramble_frags.push_back(patch_sys_name(ANTI_FRAG_HOOK, n_s));
        scramble_frags.push_back(patch_sys_name(ANTI_FRAG_FRIDA, n_s));
        scramble_frags.push_back(patch_sys_name(ANTI_FRAG_META, n_s));
    }

    // Patch anti_code __S__ placeholders with n_s
    std::string patched_anti;
    if (anti_len > 0) {
        patched_anti = patch_sys_name(std::string_view(anti_code, anti_len), n_s);
        anti_code = patched_anti.c_str();
        anti_len = patched_anti.size();
    }

    int junk_val = rand_range(1, 999999);

    int stub_junk_fns = (int)(density + 0.5f);
    if (stub_junk_fns < 1) stub_junk_fns = 1;
    int stub_junk_vars = (int)(density * 5.0f);
    if (stub_junk_vars < 1) stub_junk_vars = 1;
    int stub_dummy_blocks = density >= 2.0f ? (int)(density * 2.0f) : 0;

    // ── build stub ──
    sb_printf(buf, "#!/usr/bin/env python3\n");

    // Junk: unused functions (extra ones from density, then the canonical one)
    for (int ji = 1; ji < stub_junk_fns; ji++) {
        std::string jfn = rand_name(), jarg = rand_name();
        sb_printf(buf, "def {}({}):\n    return {} % {} + 1\n\n", jfn, jarg, jarg, rand_range(100, 9999));
    }
    sb_printf(buf, "def {}({}):\n    return {} % {} + 1\n\n", junk_fn, j1, j1, rand_range(100, 9999));

    // Junk: dummy variable declarations
    for (int vi = 0; vi < stub_junk_vars; vi++) {
        std::string jv = rand_name();
        sb_printf(buf, "{} = {}\n", jv, rand_range(1, 999999));
    }

    // Junk: dummy if/else blocks (density >= 2)
    for (int di = 0; di < stub_dummy_blocks; di++) {
        std::string jc = rand_name(), jt = rand_name(), jf = rand_name();
        sb_printf(buf, "if {} % 2 == 0:\n    {} = {}\nelse:\n    {} = {}\n\n",
                  junk_val + di, jt, rand_range(1000, 9999), jf, rand_range(1000, 9999));
    }

    // Imports
    sb_printf(buf, "import hashlib as {}, hmac as {}, base64 as {}, sys as {}, zlib as {}\n",
              n_h, n_m, n_b, n_s, n_z);

    // Junk + data
    sb_printf(buf, "{} = {}\n", j1, junk_val);
    sb_printf(buf, "{} = \"\"\"{}\"\"\"\n", n_P, b64_data);
    sb_printf(buf, "{} = {}\n", n_A, algo_id);
    sb_printf(buf, "{} = {}({})\n", j2, junk_fn, j1);

    // VM runtime (marshalled bytecode bootstrap)
    if (use_vm) {
#ifdef CRYPTO_OBFUSCATE_VM_RUNTIME
        // exec the bytecode using __import__ to avoid any name shadowing
        // __import__ is always available and doesn't conflict with VM's obfuscated names
        sb_printf(buf, "exec(__import__('marshal').loads(__import__('base64').b64decode(\"{}\")))\n", VM_INTERP_MARSHAL);
#else
        // Legacy: embed runtime as plain Python source (debugging/fallback)
        sb_printf(buf, "{}\n", VM_INTERP_SCRIPT);
#endif
    }

    // Main function
    sb_printf(buf, "def {}():\n", n_fn);

    // Anti-analysis
    if (use_scramble && scramble_frags.size() > 0) {
        sb_append(buf, scramble_frags[0]);
    } else if (anti_len > 0) {
        sb_append(buf, anti_code);
    }

    // Key deobfuscation — multi-layer if ML key provided, else simple XOR
    if (ml_key) {
        // Multi-layer key reconstruction with string pool + env split
        // ── Layer 3 (outer): String pool — reconstruct hex from scattered fragments ──
        sb_printf(buf, "    _pool = [{}]\n", ml_key->pool_csv);
        sb_printf(buf, "    _pix = [{}]\n", ml_key->pool_indices);
        sb_printf(buf, "    _real_hex = ''.join(_pool[i] for i in _pix)\n");
        // ── Layer 2 (outer): Env-derived hash byte ──
        sb_printf(buf, "    _ek = 0x{}\n", ml_key->env_payload);
        // ── Layer 1 (inner): Crypto decrypt (reverse rolling + rotate + perm) ──
        sb_printf(buf, "    _salt = bytes.fromhex(\"{}\")\n", ml_key->salt_hex);
        sb_printf(buf, "    _lk1 = bytes.fromhex(\"{}\")\n", ml_key->layer1_hex);
        sb_printf(buf, "    _ed = bytes.fromhex(_real_hex)\n");
        // Reverse layer 1a: rolling XOR (state-based)
        sb_printf(buf, "    _st = _lk1[0]\n");
        sb_printf(buf, "    _t1 = bytearray()\n");
        sb_printf(buf, "    for _i in range(len(_ed)):\n");
        sb_printf(buf, "        _b = _ed[_i] ^ _st\n");
        sb_printf(buf, "        _t1.append(_b)\n");
        sb_printf(buf, "        _st = ((_ed[_i] ^ _lk1[(_i+1)%len(_lk1)]) ^ 0x5A)\n");
        sb_printf(buf, "        _st = (((_st << 3) & 0xFF) | (_st >> 5))\n");
        sb_printf(buf, "    _t1 = bytes(_t1)\n");
        // Reverse layer 1b: bit rotation + XOR
        sb_printf(buf, "    _t2 = bytearray()\n");
        sb_printf(buf, "    for _i in range(len(_t1)):\n");
        sb_printf(buf, "        _b = _t1[_i] ^ _lk1[_i % 16]\n");
        sb_printf(buf, "        _sh = _lk1[8 + (_i % 8)] & 7\n");
        sb_printf(buf, "        _b = ((_b >> _sh) | ((_b << (8 - _sh)) & 0xFF))\n");
        sb_printf(buf, "        _t2.append(_b)\n");
        sb_printf(buf, "    _t2 = bytes(_t2)\n");
        // Note: No permutation layer — uses deterministic cross-mix from layer2
        // Remaining layers: rolling XOR + bit rotate + string pool + env hash = 4 layers
        sb_printf(buf, "    {} = bytes(_t2).decode()\n", n_k);
    } else {
        // Simple XOR fallback
        sb_printf(buf, "    {} = bytes.fromhex(\"{}\")\n", n_k, obf_key);
        if (obf_key_len > 0) {
            sb_printf(buf, "    {} = bytes(_ ^ {} for _ in {}).decode()\n", n_k, xor_byte, n_k);
        }
    }
    if (use_scramble && scramble_frags.size() > 1) {
        sb_append(buf, scramble_frags[1]);
    }

    sb_printf(buf, "    {} = {}.b64decode({})\n", n_r, n_b, n_P);

    if (use_scramble && scramble_frags.size() > 2) {
        sb_append(buf, scramble_frags[2]);
    }

    // Crypto import style
    int import_style = rand_range(0, 2);
    int has_early_crypto_import = (import_style < 2);
    if (has_early_crypto_import) {
        sb_printf(buf, "    try:\n");
        sb_printf(buf, "        from cryptography.hazmat.primitives.ciphers import Cipher as {}, algorithms as {}, modes as {}\n",
                  n_c, n_a, n_d);
        sb_printf(buf, "    except ImportError:\n");
        sb_printf(buf, "        {}.stderr.write(\"error: cryptography not installed\\n\"); {}.exit(1)\n\n",
                  n_s, n_s);
    }

    if (use_scramble && scramble_frags.size() > 3) {
        sb_append(buf, scramble_frags[3]);
    }

    // Algorithm dispatch (16 algorithms in random order)
    int order[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    for (int i = 15; i > 0; i--) {
        int j = rand() % (i + 1);
        std::swap(order[i], order[j]);
    }

    int emitted[16] = {0};
    int is_first = 1;

    for (int oi = 0; oi < 16; oi++) {
        int aid = order[oi];
        const char *kw = is_first ? "if" : "elif";
        is_first = 0;

        if (aid == 0) {
            // AES-ECB C++ format: [salt(16)] [ciphertext(N)] — no nonce, no tag, no HMAC
            sb_printf(buf, "    {} {} == 0:\n", kw, n_A);
            if (!has_early_crypto_import)
                sb_printf(buf, "        try:\n"
                     "            from cryptography.hazmat.primitives.ciphers import Cipher as {}, algorithms as {}, modes as {}\n"
                     "        except ImportError:\n"
                     "            {}.stderr.write(\"error: cryptography not installed\\n\"); {}.exit(1)\n",
                     n_c, n_a, n_d, n_s, n_s);
            sb_printf(buf, "        {} = {}[:16]; {} = {}[16:]\n", n_0, n_r, n_1, n_r);
            sb_printf(buf, "        {} = {}.pbkdf2_hmac('sha256', {}.encode(), {}, 100000, dklen=32)\n", n_4, n_h, n_k, n_0);
            sb_printf(buf, "        {} = {}({}.AES({}), {}.ECB())\n", n_8, n_c, n_a, n_4, n_d);
            sb_printf(buf, "        {} = {}.decryptor()\n"
                 "        {} = {}.update({}) + {}.finalize()\n", n_9, n_8, n_9, n_9, n_1, n_9);
            sb_printf(buf, "        {} = {}[-1]\n"
                 "        if {} < 1 or {} > 16 or not all(_ == {} for _ in {}[-{}:]):\n"
                 "            {}.stderr.write(\"error: decryption failed\\n\"); {}.exit(1)\n"
                 "        {} = {}[:-{}]\n",
                 n_t, n_9, n_t, n_t, n_t, n_9, n_t, n_s, n_s, n_9, n_9, n_t);
        } else if (aid == 1) {
            // AES-CBC C++ format: [salt(16)] [nonce(16)] [ciphertext(N)] — no HMAC
            sb_printf(buf, "    {} {} == 1:\n", kw, n_A);
            if (!has_early_crypto_import)
                sb_printf(buf, "        try:\n"
                     "            from cryptography.hazmat.primitives.ciphers import Cipher as {}, algorithms as {}, modes as {}\n"
                     "        except ImportError:\n"
                     "            {}.stderr.write(\"error: cryptography not installed\\n\"); {}.exit(1)\n",
                     n_c, n_a, n_d, n_s, n_s);
            sb_printf(buf, "        {} = {}[:16]; {} = {}[16:32]; {} = {}[32:]\n", n_0, n_r, n_5, n_r, n_1, n_r);
            sb_printf(buf, "        {} = {}.pbkdf2_hmac('sha256', {}.encode(), {}, 100000, dklen=32)\n", n_4, n_h, n_k, n_0);
            sb_printf(buf, "        {} = {}({}.AES({}), {}.CBC({}))\n", n_8, n_c, n_a, n_4, n_d, n_5);
            sb_printf(buf, "        {} = {}.decryptor()\n"
                 "        {} = {}.update({}) + {}.finalize()\n", n_9, n_8, n_9, n_9, n_1, n_9);
            sb_printf(buf, "        {} = {}[-1]\n"
                 "        if {} < 1 or {} > 16 or not all(_ == {} for _ in {}[-{}:]):\n"
                 "            {}.stderr.write(\"error: decryption failed\\n\"); {}.exit(1)\n"
                 "        {} = {}[:-{}]\n",
                 n_t, n_9, n_t, n_t, n_t, n_9, n_t, n_s, n_s, n_9, n_9, n_t);
        } else if (aid == 2) {
            // AES-CTR C++ format: [salt(16)] [nonce(16)] [ciphertext(N)] — no HMAC
            sb_printf(buf, "    {} {} == 2:\n", kw, n_A);
            if (!has_early_crypto_import)
                sb_printf(buf, "        try:\n"
                     "            from cryptography.hazmat.primitives.ciphers import Cipher as {}, algorithms as {}, modes as {}\n"
                     "        except ImportError:\n"
                     "            {}.stderr.write(\"error: cryptography not installed\\n\"); {}.exit(1)\n",
                     n_c, n_a, n_d, n_s, n_s);
            sb_printf(buf, "        {} = {}[:16]; {} = {}[16:32]; {} = {}[32:]\n", n_0, n_r, n_5, n_r, n_1, n_r);
            sb_printf(buf, "        {} = {}.pbkdf2_hmac('sha256', {}.encode(), {}, 100000, dklen=32)\n", n_4, n_h, n_k, n_0);
            sb_printf(buf, "        {} = {}({}.AES({}), {}.CTR({}))\n", n_8, n_c, n_a, n_4, n_d, n_5);
            sb_printf(buf, "        {} = {}.decryptor().update({})\n", n_9, n_8, n_1);
        } else if (aid == 3) {
            // AES-GCM C++ format: [salt(16)] [nonce(12)] [ciphertext(N)] [tag(16)] — no separate HMAC
            // GCM tag provides built-in authentication — no extra HMAC needed
            sb_printf(buf, "    {} {} == 3:\n", kw, n_A);
            if (!has_early_crypto_import)
                sb_printf(buf, "        try:\n"
                     "            from cryptography.hazmat.primitives.ciphers.aead import AESGCM as {}\n"
                     "        except ImportError:\n"
                     "            {}.stderr.write(\"error: cryptography not installed\\n\"); {}.exit(1)\n",
                     n_ae, n_s, n_s);
            else
                sb_printf(buf, "        from cryptography.hazmat.primitives.ciphers.aead import AESGCM as {}\n", n_ae);
            // Extract salt, nonce, ciphertext, tag from correct positions
            sb_printf(buf, "        {} = {}[:16]; {} = {}[16:28]; {} = {}[28:-16]; {} = {}[-16:]\n", n_0, n_r, n_5, n_r, n_1, n_r, n_t, n_r);
            // Derive only AES key (32 bytes) — nonce is read from payload, not PBKDF2
            sb_printf(buf, "        {} = {}.pbkdf2_hmac('sha256', {}.encode(), {}, 100000, dklen=32)\n", n_4, n_h, n_k, n_0);
            // AES-GCM AEAD decrypt: decrypt(nonce, ciphertext + tag, aad)
            sb_printf(buf, "        {} = {}({}).decrypt({}, {} + {}, None)\n", n_9, n_ae, n_4, n_5, n_1, n_t);
        } else if (aid == 4) {
            sb_printf(buf, "    {} {} == 4:\n", kw, n_A);
            if (!has_early_crypto_import)
                sb_printf(buf, "        try:\n"
                     "            from cryptography.hazmat.primitives.ciphers import Cipher as {}, algorithms as {}, modes as {}\n"
                     "        except ImportError:\n"
                     "            {}.stderr.write(\"error: cryptography not installed\\n\"); {}.exit(1)\n",
                     n_c, n_a, n_d, n_s, n_s);
            // ChaCha20 C++ output: [salt(16)] [nonce(16)] [ciphertext] [HMAC(32)]
            // HMAC = HMAC-SHA256(chacha_key, salt + nonce + ciphertext)
            // chacha_key = PBKDF2(user_key, salt, 100000, 32)
            // nonce = random 16 bytes stored in payload (NOT derived from PBKDF2!)
            sb_printf(buf, "        {} = {}[:16]; {} = {}[-32:]; {} = {}[16:-32]\n", n_0, n_r, n_2, n_r, n_1, n_r);
            sb_printf(buf, "        {} = {}[:16]; {} = {}[16:]\n", n_5, n_1, n_t, n_1);  // nonce, ciphertext
            // Derive only chacha_key (32 bytes) — matches C++ PBKDF2(dklen=32)
            sb_printf(buf, "        {} = {}.pbkdf2_hmac('sha256', {}.encode(), {}, 100000, dklen=32)\n", n_4, n_h, n_k, n_0);
            // HMAC over salt + nonce + ciphertext using chacha_key — matches C++
            sb_printf(buf, "        {} = {}.new({}, {}[:-32], digestmod='sha256').digest()\n", n_7, n_m, n_4, n_r);
            sb_printf(buf, "        if not {}.compare_digest({}, {}):\n"
                 "            {}.stderr.write(\"error: integrity check failed\\n\"); {}.exit(1)\n",
                 n_m, n_2, n_7, n_s, n_s);
            sb_printf(buf, "        {} = {}({}.ChaCha20({}, {}), mode=None)\n", n_8, n_c, n_a, n_4, n_5);
            sb_printf(buf, "        {} = {}.decryptor().update({})\n", n_9, n_8, n_t);
        } else if (aid == 5) {
            sb_printf(buf, "    {} {} == 5:\n", kw, n_A);
            sb_printf(buf, "        {} = {}[:16]; {} = {}[-32:]; {} = {}[16:-32]\n", n_0, n_r, n_2, n_r, n_1, n_r);
            sb_printf(buf, "        {} = {}.pbkdf2_hmac('sha256', {}.encode(), {}, 100000, dklen=64)\n", n_3, n_h, n_k, n_0);
            sb_printf(buf, "        {} = {}[:32]; {} = {}[32:64]\n", n_4, n_3, n_6, n_3);
            sb_printf(buf, "        {} = {}.new({}, {}, digestmod='sha256').digest()\n", n_7, n_m, n_6, n_1);
            sb_printf(buf, "        if not {}.compare_digest({}, {}):\n"
                 "            {}.stderr.write(\"error: integrity check failed\\n\"); {}.exit(1)\n",
                 n_m, n_2, n_7, n_s, n_s);
            sb_printf(buf, "        {} = bytes({}[i] ^ {}[i % 32] for i in range(len({})))\n", n_9, n_1, n_4, n_1);
        } else if (aid == 6) {
            sb_printf(buf, "    {} {} == 6:\n"
                 "        {} = {}.b64decode({})\n", kw, n_A, n_9, n_b, n_r);
        } else if (aid == 7) {
            sb_printf(buf, "    {} {} == 7:\n"
                 "        {} = {}.b32decode({})\n", kw, n_A, n_9, n_b, n_r);
        } else if (aid == 8) {
            sb_printf(buf, "    {} {} == 8:\n", kw, n_A);
            sb_printf(buf, "        {} = ('0','1','2','3','4','5','6','7','8','9',\n"
                 "                'A','B','C','D','E','F','G','H','I','J','K','L','M',\n"
                 "                'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',\n"
                 "                'a','b','c','d','e','f','g','h','i','j','k','l','m',\n"
                 "                'n','o','p','q','r','s','t','u','v','w','x','y','z',\n"
                 "                '!','#','$','%','&','(',')','*','+','-',';','<','=',\n"
                 "                '>','?','@','^','_','`','{{','|','}}','~')\n", n_85t);
            sb_printf(buf, "        {} = {{c:i for i,c in enumerate({})}}\n", n_85d, n_85t);
            sb_printf(buf, "        def {}({}):\n"
                 "            {} = bytearray(); {} = 0\n"
                 "            while {} < len({}):\n"
                 "                {} = 0; {} = 0\n"
                 "                while {} < len({}) and {} < 5:\n"
                 "                    {} = {} * 85 + {}[chr({}[{}])]; {} += 1; {} += 1\n"
                 "                {} = {} - 1\n"
                 "                if {} > 0: {}.extend({}.to_bytes(4, 'big')[4-{}:])\n"
                 "            return bytes({})\n",
                 n_zd, n_zd_arg,
                 n_zd_d, n_zd_i, n_zd_i, n_zd_arg,
                 n_zd_n, n_zd_cnt, n_zd_i, n_zd_arg, n_zd_cnt,
                 n_zd_n, n_zd_n, n_85d, n_zd_arg, n_zd_i, n_zd_i, n_zd_cnt,
                 n_zd_nb, n_zd_cnt, n_zd_nb, n_zd_d, n_zd_n, n_zd_nb, n_zd_d);
            sb_printf(buf, "        {} = {}({})\n", n_9, n_zd, n_r);
        } else if (aid == 9) {
            sb_printf(buf, "    {} {} == 9:\n", kw, n_A);
            sb_printf(buf, "        def {}({}):\n"
                 "            if {}[:2] == b'<~': {} = {}[2:]\n"
                 "            if {}[-2:] == b'~>': {} = {}[:-2]\n"
                 "            {} = bytearray(); {} = 0\n"
                 "            while {} < len({}):\n"
                 "                if {}[{}] == 122:\n"
                 "                    {}.extend(b'\\x00\\x00\\x00\\x00'); {} += 1; continue\n"
                 "                {} = 0; {} = 0\n"
                 "                while {} < len({}) and {} < 5:\n"
                 "                    {} = {} * 85 + ({}[{}] - 33); {} += 1; {} += 1\n"
                 "                {} = {} - 1\n"
                 "                if {} > 0: {}.extend({}.to_bytes(4, 'big')[4-{}:])\n"
                 "            return bytes({})\n",
                 n_ad, n_ad_arg,
                 n_ad_arg, n_ad_arg, n_ad_arg, n_ad_arg, n_ad_arg, n_ad_arg,
                 n_ad_d, n_ad_i, n_ad_i, n_ad_arg,
                 n_ad_arg, n_ad_i, n_ad_d, n_ad_i,
                 n_ad_n, n_ad_cnt, n_ad_i, n_ad_arg, n_ad_cnt,
                 n_ad_n, n_ad_n, n_ad_arg, n_ad_i, n_ad_i, n_ad_cnt,
                 n_ad_nb, n_ad_cnt, n_ad_nb, n_ad_d, n_ad_n, n_ad_nb, n_ad_d);
            sb_printf(buf, "        {} = {}({})\n", n_9, n_ad, n_r);
        } else if (aid == 10) {
            sb_printf(buf, "    {} {} == 10:\n"
                 "        {} = bytes.fromhex({}.decode('ascii'))\n", kw, n_A, n_9, n_r);
        } else if (aid == 11) {
            sb_printf(buf, "    {} {} == 11:\n", kw, n_A);
            sb_printf(buf, "        {} = {}[:16]; {} = {}[-32:]; {} = {}[16:-32]\n", n_0, n_r, n_2, n_r, n_1, n_r);
            sb_printf(buf, "        {} = {}.pbkdf2_hmac('sha256', {}.encode(), {}, 100000, dklen=64)\n", n_3, n_h, n_k, n_0);
            sb_printf(buf, "        {} = {}[:32]; {} = {}[32:64]\n", n_4, n_3, n_6, n_3);
            sb_printf(buf, "        {} = {}.new({}, {}, digestmod='sha256').digest()\n", n_7, n_m, n_6, n_1);
            sb_printf(buf, "        if not {}.compare_digest({}, {}):\n"
                 "            {}.stderr.write(\"error: integrity check failed\\n\"); {}.exit(1)\n",
                 n_m, n_2, n_7, n_s, n_s);
            sb_printf(buf, "        {} = {}[0]\n", n_t, n_4);
            sb_printf(buf, "        {} = bytearray()\n", n_9);
            sb_printf(buf, "        for {} in range(len({})):\n", n_vx, n_1);
            sb_printf(buf, "            {} = {}[{}] ^ {}\n", n_0, n_1, n_vx, n_t);
            sb_printf(buf, "            {}.append({})\n", n_9, n_0);
            sb_printf(buf, "            {} = {}[{}] ^ {}[ ({} + 1) % len({}) ]\n", n_t, n_1, n_vx, n_4, n_vx, n_4);
            sb_printf(buf, "            {} = ((({} << 3) & 0xFF) | ({} >> 5)) ^ 0x5A\n", n_t, n_t, n_t);
            sb_printf(buf, "        {} = bytes({})\n", n_9, n_9);
        } else if (aid == 12) {
            sb_printf(buf, "    {} {} == 12:\n", kw, n_A);
            sb_printf(buf, "        {} = {}[:16]; {} = {}[-32:]; {} = {}[16:-32]\n", n_0, n_r, n_2, n_r, n_1, n_r);
            sb_printf(buf, "        {} = {}.pbkdf2_hmac('sha256', {}.encode(), {}, 100000, dklen=64)\n", n_3, n_h, n_k, n_0);
            sb_printf(buf, "        {} = {}[:32]; {} = {}[32:64]\n", n_4, n_3, n_6, n_3);
            sb_printf(buf, "        {} = {}.new({}, {}, digestmod='sha256').digest()\n", n_7, n_m, n_6, n_1);
            sb_printf(buf, "        if not {}.compare_digest({}, {}):\n"
                 "            {}.stderr.write(\"error: integrity check failed\\n\"); {}.exit(1)\n",
                 n_m, n_2, n_7, n_s, n_s);
            sb_printf(buf, "        {} = 3 + ({}[0] & 7)\n", n_t, n_0);
            sb_printf(buf, "        {} = bytearray({})\n", n_0, n_1);
            sb_printf(buf, "        for {} in range({} - 1, -1, -1):\n", n_vx, n_t);
            sb_printf(buf, "            {} = (3 + {}) & 7\n", junk_fn, n_vx);
            sb_printf(buf, "            {} = ({} * 0x1B + 0x5A) & 0xFF\n", j1, n_vx);
            sb_printf(buf, "            for {} in range(len({})):\n", n_5, n_0);
            sb_printf(buf, "                {} = {}[{}]\n", n_t, n_0, n_5);
            sb_printf(buf, "                {} ^= {}\n", n_t, j1);
            sb_printf(buf, "                {} = (({} >> {}) | (({} << (8 - {})) & 0xFF))\n", n_t, n_t, junk_fn, n_t, junk_fn);
            sb_printf(buf, "                {} ^= {}[({} * len({}) + {}) % len({})]\n", n_t, n_4, n_vx, n_0, n_5, n_4);
            sb_printf(buf, "                {}[{}] = {}\n", n_0, n_5, n_t);
            sb_printf(buf, "        {} = bytes({})\n", n_9, n_0);
        } else if (aid == 14) {
            sb_printf(buf, "    {} {} == 14:\n", kw, n_A);
            if (!has_early_crypto_import)
                sb_printf(buf, "        try:\n"
                     "            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305 as {}\n"
                     "        except ImportError:\n"
                     "            {}.stderr.write(\"error: cryptography not installed\\n\"); {}.exit(1)\n",
                     n_ae, n_s, n_s);
            else
                sb_printf(buf, "        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305 as {}\n", n_ae);
            sb_printf(buf, "        {} = {}[:16]; {} = {}[-32:]; {} = {}[16:-32]\n", n_0, n_r, n_2, n_r, n_9, n_r);
            sb_printf(buf, "        {} = {}[:-16]; {} = {}[-16:]\n", n_1, n_9, n_t, n_9);
            sb_printf(buf, "        {} = {}.pbkdf2_hmac('sha256', {}.encode(), {}, 100000, dklen=76)\n", n_3, n_h, n_k, n_0);
            sb_printf(buf, "        {} = {}[:32]; {} = {}[32:44]; {} = {}[44:76]\n", n_4, n_3, n_5, n_3, n_6, n_3);
            sb_printf(buf, "        {} = {}.new({}, {}, digestmod='sha256').digest()\n", n_7, n_m, n_6, n_9);
            sb_printf(buf, "        if not {}.compare_digest({}, {}):\n"
                 "            {}.stderr.write(\"error: integrity check failed\\n\"); {}.exit(1)\n",
                 n_m, n_2, n_7, n_s, n_s);
            sb_printf(buf, "        {} = {}({}).decrypt({}, {} + {}, None)\n", n_9, n_ae, n_4, n_5, n_1, n_t);
        } else if (aid == 15) {
            sb_printf(buf, "    {} {} == 15:\n", kw, n_A);
            sb_printf(buf, "        {} = {}[:16]\n", n_0, n_r);
            sb_printf(buf, "        {} = {}[16:40]\n", n_5, n_r);
            sb_printf(buf, "        {} = {}[-32:]\n", n_2, n_r);
            sb_printf(buf, "        {} = {}[40:-32]\n", n_9, n_r);
            sb_printf(buf, "        {} = {}[:-16]; {} = {}[-16:]\n", n_1, n_9, n_t, n_9);
            sb_printf(buf, "        {} = {}.pbkdf2_hmac('sha256', {}.encode(), {}, 100000, dklen=64)\n", n_3, n_h, n_k, n_0);
            sb_printf(buf, "        {} = {}[:32]; {} = {}[32:64]\n", n_4, n_3, n_6, n_3);
            sb_printf(buf, "        {} = {}.new({}, {}, digestmod='sha256').digest()\n", n_7, n_m, n_6, n_9);
            sb_printf(buf, "        if not {}.compare_digest({}, {}):\n"
                 "            {}.stderr.write(\"error: integrity check failed\\n\"); {}.exit(1)\n",
                 n_m, n_2, n_7, n_s, n_s);
            sb_printf(buf, "        def {}(_k, _n):\n", j2);
            sb_printf(buf, "            _s=[0x61707865,0x3320646e,0x79622d32,0x6b206574]\n");
            sb_printf(buf, "            for _i in range(0,32,4):_s.append(int.from_bytes(_k[_i:_i+4],'little'))\n");
            sb_printf(buf, "            for _i in range(0,16,4):_s.append(int.from_bytes(_n[_i:_i+4],'little'))\n");
            sb_printf(buf, "            _w=list(_s)\n");
            sb_printf(buf, "            def _q(_a,_b,_c,_d):\n");
            sb_printf(buf, "                _a=(_a+_b)&0xFFFFFFFF;_d^=_a;_d=((_d<<16)|(_d>>16))&0xFFFFFFFF\n");
            sb_printf(buf, "                _c=(_c+_d)&0xFFFFFFFF;_b^=_c;_b=((_b<<12)|(_b>>20))&0xFFFFFFFF\n");
            sb_printf(buf, "                _a=(_a+_b)&0xFFFFFFFF;_d^=_a;_d=((_d<<8)|(_d>>24))&0xFFFFFFFF\n");
            sb_printf(buf, "                _c=(_c+_d)&0xFFFFFFFF;_b^=_c;_b=((_b<<7)|(_b>>25))&0xFFFFFFFF\n");
            sb_printf(buf, "                return _a,_b,_c,_d\n");
            sb_printf(buf, "            for _ in range(10):\n");
            sb_printf(buf, "                _w[0],_w[4],_w[8],_w[12]=_q(_w[0],_w[4],_w[8],_w[12])\n");
            sb_printf(buf, "                _w[1],_w[5],_w[9],_w[13]=_q(_w[1],_w[5],_w[9],_w[13])\n");
            sb_printf(buf, "                _w[2],_w[6],_w[10],_w[14]=_q(_w[2],_w[6],_w[10],_w[14])\n");
            sb_printf(buf, "                _w[3],_w[7],_w[11],_w[15]=_q(_w[3],_w[7],_w[11],_w[15])\n");
            sb_printf(buf, "                _w[0],_w[5],_w[10],_w[15]=_q(_w[0],_w[5],_w[10],_w[15])\n");
            sb_printf(buf, "                _w[1],_w[6],_w[11],_w[12]=_q(_w[1],_w[6],_w[11],_w[12])\n");
            sb_printf(buf, "                _w[2],_w[7],_w[8],_w[13]=_q(_w[2],_w[7],_w[8],_w[13])\n");
            sb_printf(buf, "                _w[3],_w[4],_w[9],_w[14]=_q(_w[3],_w[4],_w[9],_w[14])\n");
            sb_printf(buf, "            return b''.join(_w[i].to_bytes(4,'little') for i in (0,1,2,3,12,13,14,15))\n");
            sb_printf(buf, "        {} = {}({}, {}[:16])\n", n_4, j2, n_4, n_5);
            sb_printf(buf, "        {} = b'\\x00\\x00\\x00\\x00' + {}[16:]\n", n_0, n_5);
            if (!has_early_crypto_import)
                sb_printf(buf, "        try:\n"
                     "            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305 as {}\n"
                     "        except ImportError:\n"
                     "            {}.stderr.write(\"error: cryptography not installed\\n\"); {}.exit(1)\n",
                     n_ae, n_s, n_s);
            else
                sb_printf(buf, "        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305 as {}\n", n_ae);
            sb_printf(buf, "        {} = {}({}).decrypt({}, {} + {}, None)\n", n_9, n_ae, n_4, n_0, n_1, n_t);
        } else if (aid == 13) {
            sb_printf(buf, "    {} {} == 13:\n", kw, n_A);
            sb_printf(buf, "        {} = {}[:16]; {} = {}[-32:]; {} = {}[16:-32]\n", n_0, n_r, n_2, n_r, n_1, n_r);
            sb_printf(buf, "        {} = {}.pbkdf2_hmac('sha256', {}.encode(), {}, 100000, dklen=80)\n", n_3, n_h, n_k, n_0);
            sb_printf(buf, "        {} = {}[:32]; {} = {}[32:48]; {} = {}[48:80]\n", n_4, n_3, n_5, n_3, n_6, n_3);
            sb_printf(buf, "        {} = {}.new({}, {}, digestmod='sha256').digest()\n", n_7, n_m, n_6, n_1);
            sb_printf(buf, "        if not {}.compare_digest({}, {}):\n"
                 "            {}.stderr.write(\"error: integrity check failed\\n\"); {}.exit(1)\n",
                 n_m, n_2, n_7, n_s, n_s);
            sb_printf(buf, "        import struct as {}\n", j2);
            sb_printf(buf, "        def {}(k,c,n):\n"
                 "            s=[0x61707865,0x3320646e,0x79622d32,0x6b206574]\n"
                 "            for i in range(0,32,4):s.append({}.unpack('<I',k[i:i+4])[0])\n"
                 "            s.append(c&0xFFFFFFFF)\n"
                 "            for i in range(0,12,4):s.append({}.unpack('<I',n[i:i+4])[0])\n"
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
                 "            for i in range(16):r.extend({}.pack('<I',(s[i]+w[i])&0xFFFFFFFF))\n"
                 "            return bytes(r)\n",
                 junk_fn, j2, j2, j2, j2);
            sb_printf(buf, "        {} = {}.unpack('<I',{}[:4])[0]\n", n_vx, j2, n_5);
            sb_printf(buf, "        {} = {}[4:]\n", n_5, n_5);
            sb_printf(buf, "        {} = bytearray()\n", n_0);
            sb_printf(buf, "        while len({}) < len({}):\n", n_0, n_1);
            sb_printf(buf, "            {} = {}({}, {}, {})\n", n_t, junk_fn, n_4, n_vx, n_5);
            sb_printf(buf, "            for {} in range(min(64, len({}) - len({}))):\n", j1, n_1, n_0);
            sb_printf(buf, "                {}.append({}[len({})] ^ {}[{}])\n", n_0, n_1, n_0, n_t, j1);
            sb_printf(buf, "            {} += 1\n", n_vx);
            sb_printf(buf, "        {} = bytes({})\n", n_9, n_0);
        }
        emitted[aid] = 1;
    }

    // else fallback
    sb_printf(buf, "    else:\n"
              "        {}.stderr.write(\"error: unsupported algorithm\\n\"); {}.exit(1)\n",
              n_s, n_s);

    if (use_vm) {
        // VM decryption: XChaCha20-Poly1305 format
        // VM blob: [salt(16)] [nonce(24)] [ciphertext+tag] [HMAC(32)]
        // n_9 = outer decrypted payload
        sb_printf(buf, "    _vsalt_vm = {}[4+0:4+16]  # VM salt from encrypted blob\n", n_9);
        sb_printf(buf, "    _vn_full = {}[4+16:4+40]  # VM 24-byte nonce\n", n_9);
        sb_printf(buf, "    # hchacha20: derive 32-byte subkey from PBKDF2 key + first 16 bytes of nonce\n");
        sb_printf(buf, "    def hchacha20_h(_k, _n):\n");
        sb_printf(buf, "        _C=[0x61707865,0x3320646e,0x79622d32,0x6b206574]\n");
        sb_printf(buf, "        _s=[_C[0],_C[1],_C[2],_C[3]]\n");
        sb_printf(buf, "        for _i in range(8):_s.append(int.from_bytes(_k[_i*4:(_i+1)*4],'little'))\n");
        sb_printf(buf, "        for _i in range(4):_s.append(int.from_bytes(_n[_i*4:(_i+1)*4],'little'))\n");
        sb_printf(buf, "        def _qr(_x,_a,_b,_c,_d):\n");
        sb_printf(buf, "            _x[_a]=(_x[_a]+_x[_b])&0xFFFFFFFF;_x[_d]=_x[_d]^_x[_a];_x[_d]=((_x[_d]<<16)|(_x[_d]>>16))&0xFFFFFFFF\n");
        sb_printf(buf, "            _x[_c]=(_x[_c]+_x[_d])&0xFFFFFFFF;_x[_b]=_x[_b]^_x[_c];_x[_b]=((_x[_b]<<12)|(_x[_b]>>20))&0xFFFFFFFF\n");
        sb_printf(buf, "            _x[_a]=(_x[_a]+_x[_b])&0xFFFFFFFF;_x[_d]=_x[_d]^_x[_a];_x[_d]=((_x[_d]<<8)|(_x[_d]>>24))&0xFFFFFFFF\n");
        sb_printf(buf, "            _x[_c]=(_x[_c]+_x[_d])&0xFFFFFFFF;_x[_b]=_x[_b]^_x[_c];_x[_b]=((_x[_b]<<7)|(_x[_b]>>25))&0xFFFFFFFF\n");
        sb_printf(buf, "        for _ in range(10):\n");
        sb_printf(buf, "            _qr(_s,0,4,8,12);_qr(_s,1,5,9,13);_qr(_s,2,6,10,14);_qr(_s,3,7,11,15)\n");
        sb_printf(buf, "            _qr(_s,0,5,10,15);_qr(_s,1,6,11,12);_qr(_s,2,7,8,13);_qr(_s,3,4,9,14)\n");
        sb_printf(buf, "        return b''.join(_s[_i].to_bytes(4,'little') for _i in [0,1,2,3,12,13,14,15])\n");
        sb_printf(buf, "    _vk_pbk = {}.pbkdf2_hmac('sha256', {}.encode(), _vsalt_vm, 100000, dklen=32)\n", n_h, n_k);
        sb_printf(buf, "    _vk = hchacha20_h(_vk_pbk, _vn_full[:16])[:32]  # hchacha20 to derive ChaCha20 key\n");
        sb_printf(buf, "    _vn = b'\\x00\\x00\\x00\\x00' + _vn_full[16:24]  # 12-byte ChaCha20 nonce\n");
        sb_printf(buf, "    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305 as {}\n", n_ae);
        sb_printf(buf, "    _ct = {}[4+40:]  # ciphertext+tag from VM blob (no HMAC in this format)\n", n_9);
        sb_printf(buf, "    _pd = {}(_vk).decrypt(_vn, _ct, b'')\n", n_ae);
        if (compress_algo != COMPRESS_ID_NONE) {
            // VM mode decompression with error handling
            sb_printf(buf, "    _dc_algo = {}[1]\n", n_9);
            sb_printf(buf, "    if _dc_algo == {}:\n", COMPRESS_ID_ZLIB);
            sb_printf(buf, "        try:\n"
                      "            import zlib as {}\n"
                      "            _pd = {}.decompress(_pd)\n"
                      "        except ImportError:\n"
                      "            {}.stderr.write('error: zlib not installed\\n'); {}.exit(1)\n"
                      "        except Exception:\n"
                      "            {}.stderr.write('error: zlib decompression failed\\n'); {}.exit(1)\n",
                      n_z, n_z, n_s, n_s, n_s, n_s);
            sb_printf(buf, "    elif _dc_algo == {}:\n", COMPRESS_ID_LZMA);
            sb_printf(buf, "        try:\n"
                      "            import lzma as {}\n"
                      "            _pd = {}.decompress(_pd)\n"
                      "        except ImportError:\n"
                      "            {}.stderr.write('error: lzma not installed\\n'); {}.exit(1)\n"
                      "        except Exception:\n"
                      "            {}.stderr.write('error: lzma decompression failed\\n'); {}.exit(1)\n",
                      n_z, n_z, n_s, n_s, n_s, n_s);
            sb_printf(buf, "    elif _dc_algo == {}:\n", COMPRESS_ID_BZ2);
            sb_printf(buf, "        try:\n"
                      "            import bz2 as {}\n"
                      "            _pd = {}.decompress(_pd)\n"
                      "        except ImportError:\n"
                      "            {}.stderr.write('error: bz2 not installed\\n'); {}.exit(1)\n"
                      "        except Exception:\n"
                      "            {}.stderr.write('error: bz2 decompression failed\\n'); {}.exit(1)\n",
                      n_z, n_z, n_s, n_s, n_s, n_s);
            sb_printf(buf, "    elif _dc_algo == {}:\n", COMPRESS_ID_BROTLI);
            sb_printf(buf, "        try:\n"
                      "            import brotli as {}\n"
                      "            _pd = {}.decompress(_pd)\n"
                      "        except ImportError:\n"
                      "            {}.stderr.write('error: brotli not installed\\n'); {}.exit(1)\n"
                      "        except Exception:\n"
                      "            {}.stderr.write('error: brotli decompression failed\\n'); {}.exit(1)\n",
                      n_z, n_z, n_s, n_s, n_s, n_s);
            sb_printf(buf, "    elif _dc_algo == {}:\n", COMPRESS_ID_GZIP);
            sb_printf(buf, "        try:\n"
                      "            import gzip as {}\n"
                      "            _pd = {}.decompress(_pd)\n"
                      "        except ImportError:\n"
                      "            {}.stderr.write('error: gzip not installed\\n'); {}.exit(1)\n"
                      "        except Exception:\n"
                      "            {}.stderr.write('error: gzip decompression failed\\n'); {}.exit(1)\n",
                      n_z, n_z, n_s, n_s, n_s, n_s);
            sb_printf(buf, "    elif _dc_algo == {}:\n", COMPRESS_ID_LZ4);
            sb_printf(buf, "        try:\n"
                      "            import lz4.frame as {}\n"
                      "            _pd = {}.decompress(_pd)\n"
                      "        except ImportError:\n"
                      "            {}.stderr.write('error: lz4 not installed\\n'); {}.exit(1)\n"
                      "        except Exception:\n"
                      "            {}.stderr.write('error: lz4 decompression failed\\n'); {}.exit(1)\n",
                      n_z, n_z, n_s, n_s, n_s, n_s);
            sb_printf(buf, "    elif _dc_algo == {}:\n", COMPRESS_ID_SNAPPY);
            sb_printf(buf, "        try:\n"
                      "            import snappy as {}\n"
                      "            _pd = {}.decompress(_pd)\n"
                      "        except ImportError:\n"
                      "            {}.stderr.write('error: snappy not installed\\n'); {}.exit(1)\n"
                      "        except Exception:\n"
                      "            {}.stderr.write('error: snappy decompression failed\\n'); {}.exit(1)\n",
                      n_z, n_z, n_s, n_s, n_s, n_s);
            sb_printf(buf, "    elif _dc_algo == {}:\n", COMPRESS_ID_BLOSC);
            sb_printf(buf, "        try:\n"
                      "            import blosc as {}\n"
                      "            _pd = {}.decompress(_pd)\n"
                      "        except ImportError:\n"
                      "            {}.stderr.write('error: blosc not installed\\n'); {}.exit(1)\n"
                      "        except Exception:\n"
                      "            {}.stderr.write('error: blosc decompression failed\\n'); {}.exit(1)\n",
                      n_z, n_z, n_s, n_s, n_s, n_s);
        }
        sb_printf(buf, "    _c, _k, _m, _map, _ok, _ht, _pf, _vf, _vs = _vm_deserialize(_pd)\n");
        if (exec_src && exec_src[0]) {
            sb_printf(buf, "    exec(compile({}.b64decode(\"{}\"), '<exec>', 'exec'), globals())\n", n_b, exec_src);
        }
        sb_printf(buf, "    _vm_run(_c, _k, _m, globals(), locals(), _map, _ok, _ht, _pf, _vf, _vs)\n");
    } else {
        // Non-VM mode decompression with error handling
        if (compress_algo != COMPRESS_ID_NONE) {
            sb_printf(buf, "    _dc_algo = {}[1]\n", n_9);
            sb_printf(buf, "    if _dc_algo == {}:\n", COMPRESS_ID_ZLIB);
            sb_printf(buf, "        try:\n"
                      "            import zlib as {0}\n"
                      "            {1} = {0}.decompress({2}[4:])\n"
                      "        except ImportError:\n"
                      "            {3}.stderr.write('error: zlib not installed\\n'); {3}.exit(1)\n"
                      "        except Exception:\n"
                      "            {3}.stderr.write('error: zlib decompression failed\\n'); {3}.exit(1)\n",
                      n_z, n_9, n_9, n_s);
            sb_printf(buf, "    elif _dc_algo == {}:\n", COMPRESS_ID_LZMA);
            sb_printf(buf, "        try:\n"
                      "            import lzma as {0}\n"
                      "            {1} = {0}.decompress({2}[4:])\n"
                      "        except ImportError:\n"
                      "            {3}.stderr.write('error: lzma not installed\\n'); {3}.exit(1)\n"
                      "        except Exception:\n"
                      "            {3}.stderr.write('error: lzma decompression failed\\n'); {3}.exit(1)\n",
                      n_z, n_9, n_9, n_s);
            sb_printf(buf, "    elif _dc_algo == {}:\n", COMPRESS_ID_BZ2);
            sb_printf(buf, "        try:\n"
                      "            import bz2 as {0}\n"
                      "            {1} = {0}.decompress({2}[4:])\n"
                      "        except ImportError:\n"
                      "            {3}.stderr.write('error: bz2 not installed\\n'); {3}.exit(1)\n"
                      "        except Exception:\n"
                      "            {3}.stderr.write('error: bz2 decompression failed\\n'); {3}.exit(1)\n",
                      n_z, n_9, n_9, n_s);
            sb_printf(buf, "    elif _dc_algo == {}:\n", COMPRESS_ID_BROTLI);
            sb_printf(buf, "        try:\n"
                      "            import brotli as {0}\n"
                      "            {1} = {0}.decompress({2}[4:])\n"
                      "        except ImportError:\n"
                      "            {3}.stderr.write('error: brotli not installed\\n'); {3}.exit(1)\n"
                      "        except Exception:\n"
                      "            {3}.stderr.write('error: brotli decompression failed\\n'); {3}.exit(1)\n",
                      n_z, n_9, n_9, n_s);
            sb_printf(buf, "    elif _dc_algo == {}:\n", COMPRESS_ID_GZIP);
            sb_printf(buf, "        try:\n"
                      "            import gzip as {0}\n"
                      "            {1} = {0}.decompress({2}[4:])\n"
                      "        except ImportError:\n"
                      "            {3}.stderr.write('error: gzip not installed\\n'); {3}.exit(1)\n"
                      "        except Exception:\n"
                      "            {3}.stderr.write('error: gzip decompression failed\\n'); {3}.exit(1)\n",
                      n_z, n_9, n_9, n_s);
            sb_printf(buf, "    elif _dc_algo == {}:\n", COMPRESS_ID_LZ4);
            sb_printf(buf, "        try:\n"
                      "            import lz4.frame as {0}\n"
                      "            {1} = {0}.decompress({2}[4:])\n"
                      "        except ImportError:\n"
                      "            {3}.stderr.write('error: lz4 not installed\\n'); {3}.exit(1)\n"
                      "        except Exception:\n"
                      "            {3}.stderr.write('error: lz4 decompression failed\\n'); {3}.exit(1)\n",
                      n_z, n_9, n_9, n_s);
            sb_printf(buf, "    elif _dc_algo == {}:\n", COMPRESS_ID_SNAPPY);
            sb_printf(buf, "        try:\n"
                      "            import snappy as {0}\n"
                      "            {1} = {0}.decompress({2}[4:])\n"
                      "        except ImportError:\n"
                      "            {3}.stderr.write('error: snappy not installed\\n'); {3}.exit(1)\n"
                      "        except Exception:\n"
                      "            {3}.stderr.write('error: snappy decompression failed\\n'); {3}.exit(1)\n",
                      n_z, n_9, n_9, n_s);
            sb_printf(buf, "    elif _dc_algo == {}:\n", COMPRESS_ID_BLOSC);
            sb_printf(buf, "        try:\n"
                      "            import blosc as {0}\n"
                      "            {1} = {0}.decompress({2}[4:])\n"
                      "        except ImportError:\n"
                      "            {3}.stderr.write('error: blosc not installed\\n'); {3}.exit(1)\n"
                      "        except Exception:\n"
                      "            {3}.stderr.write('error: blosc decompression failed\\n'); {3}.exit(1)\n",
                      n_z, n_9, n_9, n_s);
            sb_printf(buf, "    else:\n"
                      "        {} = {}[4:]\n", n_9, n_9);
        } else {
            sb_printf(buf, "    {} = {}[4:]\n", n_9, n_9);
        }
        sb_printf(buf, "    exec(compile({}, '<protected>', 'exec'), globals())\n\n", n_9);
    }

    sb_printf(buf, "if __name__ == '__main__':\n"
              "    {}()\n", n_fn);

    out->data = static_cast<unsigned char*>(malloc(buf.size()));
    memcpy(out->data, buf.data(), buf.size());
    out->size = buf.size();
    return EXIT_OK;
}

} /* namespace protect */
