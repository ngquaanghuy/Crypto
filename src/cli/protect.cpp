#include "cli/protect.h"
#include "crypto/file_util.h"
#include "crypto/stub.h"
#include "crypto/pyobf.h"
#include "crypto/aes.h"
#include "crypto/chacha20.h"
#include "crypto/chacha20_poly1305.h"
#include "crypto/xchacha20_poly1305.h"
#include "encode/base64.h"
#include "encode/base32.h"
#include "encode/base85.h"
#include "encode/ascii85.h"
#include "encode/hexcode.h"
#include "encode/xorcode.h"
#include "vm/vm.h"
#include "vm/vm_interp_py.h"
#include "vm/vm_split.h"
#include "crypto/compress.h"
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <ctime>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <format>
#include <string>
#include <vector>
#include <memory>
#include <span>
#include <algorithm>


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

    std::string key_hex;
    for (int i = 0; i < 32; i++)
        key_hex += std::format("{:02x}", key[i]);

    std::string b64_str(reinterpret_cast<char*>(b64.data), b64.size);
    free(b64.data);

    static constexpr auto fmt =
        "def _rx(_d, _k):\n"
        "    _s = _k[0]\n"
        "    _r = bytearray()\n"
        "    for i in range(len(_d)):\n"
        "        _v = _d[i] ^ _s\n"
        "        _r.append(_v)\n"
        "        _s = (_d[i] ^ _k[(i+1)%len(_k)])\n"
        "        _s = (((_s << 3) & 0xFF) | (_s >> 5)) ^ 0x5A\n"
        "    return bytes(_r)\n"
        "import base64 as _b64\n"
        "exec(_rx(_b64.b64decode(\"{}\"), bytes.fromhex(\"{}\")))\n";

    auto result = std::format(fmt, b64_str, key_hex);
    out->data = static_cast<unsigned char*>(malloc(result.size() + 1));
    if (!out->data) return EXIT_ERR_CRYPTO;
    memcpy(out->data, result.data(), result.size() + 1);
    out->size = result.size();
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

    std::string key_hex;
    for (int i = 0; i < 32; i++)
        key_hex += std::format("{:02x}", key[i]);

    std::string b64_str(reinterpret_cast<char*>(b64.data), b64.size);
    free(b64.data);

    static constexpr auto fmt =
        "def _xbr(_d, _k):\n"
        "    _r = bytearray()\n"
        "    for i in range(len(_d)):\n"
        "        _v = ((_d[i] >> 3) | (_d[i] << 5)) & 0xFF\n"
        "        _v = _v ^ _k[i % len(_k)]\n"
        "        _r.append(_v)\n"
        "    return bytes(_r)\n"
        "import base64 as _b64\n"
        "exec(_xbr(_b64.b64decode(\"{}\"), bytes.fromhex(\"{}\")))\n";

    auto result = std::format(fmt, b64_str, key_hex);
    out->data = static_cast<unsigned char*>(malloc(result.size() + 1));
    if (!out->data) return EXIT_ERR_CRYPTO;
    memcpy(out->data, result.data(), result.size() + 1);
    out->size = result.size();
    return EXIT_OK;
}

// Return a random int in [lo, hi]
static int rand_range(int lo, int hi) {
    return lo + rand() % (hi - lo + 1);
}

static std::string rand_name() {
    int len = rand_range(6, 10);
    std::string r;
    r += '_';
    for (int i = 1; i < len; i++)
        r += static_cast<char>('a' + rand() % 26);
    return r;
}

// Modern sb_append: appends a string_view to a std::string
static void sb_append(std::string &buf, std::string_view s) {
    buf.append(s);
}

// Variadic template sb_printf: formats into a std::string using std::vformat
static void sb_printf(std::string &buf, std::string_view fmt, const auto&... args) {
    buf += std::vformat(fmt, std::make_format_args(args...));
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
    "    _BU = __S__.modules.get('builtins')\n" \
    "    for _qn in ('__import__','compile','exec','eval','open'):\n" \
    "        _qf = getattr(_BU, _qn, None)\n" \
    "        if _qf is None: __S__.stderr.write('error: hook detected\\n'); __S__.exit(1)\n" \
    "        _qg = getattr(_qf, '__name__', '')\n" \
    "        if _qg != _qn: __S__.stderr.write('error: hook detected\\n'); __S__.exit(1)\n"
#define ANTI_FRAG_FRIDA \
    "    if 'frida' in __S__.modules:\n" \
    "        __S__.stderr.write('error: instrumentation detected\\n'); __S__.exit(1)\n" \
    "    import os\n" \
    "    if os.environ.get('FRIDA_SCRIPT'):\n" \
    "        __S__.stderr.write('error: instrumentation detected\\n'); __S__.exit(1)\n" \
    "    try:\n" \
    "        import socket\n" \
    "        _s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n" \
    "        _s.settimeout(1.0)\n" \
    "        if _s.connect_ex(('127.0.0.1', 27042)) == 0:\n" \
    "            _s.close(); __S__.stderr.write('error: instrumentation detected\\n'); __S__.exit(1)\n" \
    "        _s.close()\n" \
    "    except: pass\n" \
    "    try:\n" \
    "        for _f in ('maps','status','cmdline'):\n" \
    "            with open('/proc/self/' + _f) as _fh:\n" \
    "                if 'frida' in _fh.read():\n" \
    "                    __S__.stderr.write('error: instrumentation detected\\n'); __S__.exit(1)\n" \
    "    except: pass\n"

#define ANTI_FRAG_META \
    "    if len(__S__.meta_path) > 5:\n" \
    "        __S__.stderr.write('error: import hook detected\\n'); __S__.exit(1)\n" \
    "    if getattr(__S__, 'flags', None) and __S__.flags.no_user_site:\n" \
    "        __S__.stderr.write('error: sandbox detected\\n'); __S__.exit(1)\n" \
    "    import os\n" \
    "    if any(x in str(__S__.platform) or any(y in os.listdir('/proc/sys/kernel') for y in ['//', 'vm']) for x in ['vmware', 'virtualbox', 'qemu']):\n" \
    "        __S__.stderr.write('error: virtual machine detected\\n'); __S__.exit(1)\n"

static std::string patch_sys_name(std::string_view code, std::string_view sys_name) {
    std::string result;
    result.reserve(code.size());
    size_t pos = 0;
    while (true) {
        auto found = code.find("__S__", pos);
        if (found == std::string_view::npos) break;
        result.append(code.substr(pos, found - pos));
        result.append(sys_name);
        pos = found + 5;
    }
    result.append(code.substr(pos));
    return result;
}

struct MultiLayerKey {
    std::string salt_hex;      // 32-char hex (16 bytes)
    std::string layer1_hex;    // 32-char hex (16 bytes)
    std::string enc_key_hex;   // encrypted key data as hex
    std::string pool_csv;      // string pool: comma-sep quoted fragments
    std::string pool_indices;  // comma-sep ints for reconstruct order
    std::string env_payload;   // hex-encoded env-derived hash (1 byte)
    std::string extra1;        // env var name for runtime hash
    std::string extra2;        // xor_byte as hex
    std::string vm_enc_hex;    // VM encrypted key+nonce as hex (96 bytes raw → 192 hex)
};

static ExitCode generate_stub(const char *b64_data, size_t b64_sz,
                                    const char *algo_id,
                                    const char *obf_key, size_t obf_key_len,
                                    const char *anti_code, size_t anti_len,
                                    int xor_byte, int compress_algo,
                                    int use_vm, int use_scramble,
                                    const char *vm_xor_key, int vm_obf_algo,
                                    const char *vm_nonce_hex,
                                    const char *exec_src,
                                    Buffer *out,
                                    float density = 1.0f,
                                    const MultiLayerKey *ml_key = nullptr) {
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

    // VM interpreter
    if (use_vm) {
        sb_printf(buf, "{}\n", VM_INTERP_SCRIPT);
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
            sb_printf(buf, "    {} {} == 0:\n", kw, n_A);
            if (!has_early_crypto_import)
                sb_printf(buf, "        try:\n"
                     "            from cryptography.hazmat.primitives.ciphers import Cipher as {}, algorithms as {}, modes as {}\n"
                     "        except ImportError:\n"
                     "            {}.stderr.write(\"error: cryptography not installed\\n\"); {}.exit(1)\n",
                     n_c, n_a, n_d, n_s, n_s);
            sb_printf(buf, "        {} = {}[:16]; {} = {}[-32:]; {} = {}[16:-32]\n", n_0, n_r, n_2, n_r, n_1, n_r);
            sb_printf(buf, "        {} = {}.pbkdf2_hmac('sha256', {}.encode(), {}, 100000, dklen=64)\n", n_3, n_h, n_k, n_0);
            sb_printf(buf, "        {} = {}[:32]; {} = {}[32:64]\n", n_4, n_3, n_6, n_3);
            sb_printf(buf, "        {} = {}.new({}, {}, digestmod='sha256').digest()\n", n_7, n_m, n_6, n_1);
            sb_printf(buf, "        if not {}.compare_digest({}, {}):\n"
                 "            {}.stderr.write(\"error: integrity check failed\\n\"); {}.exit(1)\n",
                 n_m, n_2, n_7, n_s, n_s);
            sb_printf(buf, "        {} = {}({}.AES({}), {}.ECB())\n", n_8, n_c, n_a, n_4, n_d);
            sb_printf(buf, "        {} = {}.decryptor()\n"
                 "        {} = {}.update({}) + {}.finalize()\n", n_9, n_8, n_9, n_9, n_1, n_9);
            sb_printf(buf, "        {} = {}[-1]\n"
                 "        if {} < 1 or {} > 16 or not all(_ == {} for _ in {}[-{}:]):\n"
                 "            {}.stderr.write(\"error: decryption failed\\n\"); {}.exit(1)\n"
                 "        {} = {}[:-{}]\n",
                 n_t, n_9, n_t, n_t, n_t, n_9, n_t, n_s, n_s, n_9, n_9, n_t);
        } else if (aid == 1) {
            sb_printf(buf, "    {} {} == 1:\n", kw, n_A);
            if (!has_early_crypto_import)
                sb_printf(buf, "        try:\n"
                     "            from cryptography.hazmat.primitives.ciphers import Cipher as {}, algorithms as {}, modes as {}\n"
                     "        except ImportError:\n"
                     "            {}.stderr.write(\"error: cryptography not installed\\n\"); {}.exit(1)\n",
                     n_c, n_a, n_d, n_s, n_s);
            sb_printf(buf, "        {} = {}[:16]; {} = {}[-32:]; {} = {}[16:-32]\n", n_0, n_r, n_2, n_r, n_1, n_r);
            sb_printf(buf, "        {} = {}.pbkdf2_hmac('sha256', {}.encode(), {}, 100000, dklen=80)\n", n_3, n_h, n_k, n_0);
            sb_printf(buf, "        {} = {}[:32]; {} = {}[32:48]; {} = {}[48:80]\n", n_4, n_3, n_5, n_3, n_6, n_3);
            sb_printf(buf, "        {} = {}.new({}, {}, digestmod='sha256').digest()\n", n_7, n_m, n_6, n_1);
            sb_printf(buf, "        if not {}.compare_digest({}, {}):\n"
                 "            {}.stderr.write(\"error: integrity check failed\\n\"); {}.exit(1)\n",
                 n_m, n_2, n_7, n_s, n_s);
            sb_printf(buf, "        {} = {}({}.AES({}), {}.CBC({}))\n", n_8, n_c, n_a, n_4, n_d, n_5);
            sb_printf(buf, "        {} = {}.decryptor()\n"
                 "        {} = {}.update({}) + {}.finalize()\n", n_9, n_8, n_9, n_9, n_1, n_9);
            sb_printf(buf, "        {} = {}[-1]\n"
                 "        if {} < 1 or {} > 16 or not all(_ == {} for _ in {}[-{}:]):\n"
                 "            {}.stderr.write(\"error: decryption failed\\n\"); {}.exit(1)\n"
                 "        {} = {}[:-{}]\n",
                 n_t, n_9, n_t, n_t, n_t, n_9, n_t, n_s, n_s, n_9, n_9, n_t);
        } else if (aid == 2) {
            sb_printf(buf, "    {} {} == 2:\n", kw, n_A);
            if (!has_early_crypto_import)
                sb_printf(buf, "        try:\n"
                     "            from cryptography.hazmat.primitives.ciphers import Cipher as {}, algorithms as {}, modes as {}\n"
                     "        except ImportError:\n"
                     "            {}.stderr.write(\"error: cryptography not installed\\n\"); {}.exit(1)\n",
                     n_c, n_a, n_d, n_s, n_s);
            sb_printf(buf, "        {} = {}[:16]; {} = {}[-32:]; {} = {}[16:-32]\n", n_0, n_r, n_2, n_r, n_1, n_r);
            sb_printf(buf, "        {} = {}.pbkdf2_hmac('sha256', {}.encode(), {}, 100000, dklen=80)\n", n_3, n_h, n_k, n_0);
            sb_printf(buf, "        {} = {}[:32]; {} = {}[32:48]; {} = {}[48:80]\n", n_4, n_3, n_5, n_3, n_6, n_3);
            sb_printf(buf, "        {} = {}.new({}, {}, digestmod='sha256').digest()\n", n_7, n_m, n_6, n_1);
            sb_printf(buf, "        if not {}.compare_digest({}, {}):\n"
                 "            {}.stderr.write(\"error: integrity check failed\\n\"); {}.exit(1)\n",
                 n_m, n_2, n_7, n_s, n_s);
            sb_printf(buf, "        {} = {}({}.AES({}), {}.CTR({}))\n", n_8, n_c, n_a, n_4, n_d, n_5);
            sb_printf(buf, "        {} = {}.decryptor().update({})\n", n_9, n_8, n_1);
        } else if (aid == 3) {
            sb_printf(buf, "    {} {} == 3:\n", kw, n_A);
            if (!has_early_crypto_import)
                sb_printf(buf, "        try:\n"
                     "            from cryptography.hazmat.primitives.ciphers.aead import AESGCM as {}\n"
                     "        except ImportError:\n"
                     "            {}.stderr.write(\"error: cryptography not installed\\n\"); {}.exit(1)\n",
                     n_ae, n_s, n_s);
            else
                sb_printf(buf, "        from cryptography.hazmat.primitives.ciphers.aead import AESGCM as {}\n", n_ae);
            sb_printf(buf, "        {} = {}[:16]; {} = {}[-32:]; {} = {}[16:-32]\n", n_0, n_r, n_2, n_r, n_9, n_r);
            sb_printf(buf, "        {} = {}[:-16]; {} = {}[-16:]\n", n_1, n_9, n_t, n_9);
            sb_printf(buf, "        {} = {}.pbkdf2_hmac('sha256', {}.encode(), {}, 100000, dklen=76)\n", n_3, n_h, n_k, n_0);
            sb_printf(buf, "        {} = {}[:32]; {} = {}[32:44]; {} = {}[44:76]\n", n_4, n_3, n_5, n_3, n_6, n_3);
            sb_printf(buf, "        {} = {}.new({}, {}, digestmod='sha256').digest()\n", n_7, n_m, n_6, n_9);
            sb_printf(buf, "        if not {}.compare_digest({}, {}):\n"
                 "            {}.stderr.write(\"error: integrity check failed\\n\"); {}.exit(1)\n",
                 n_m, n_2, n_7, n_s, n_s);
            sb_printf(buf, "        {} = {}({}).decrypt({}, {} + {}, None)\n", n_9, n_ae, n_4, n_5, n_1, n_t);
        } else if (aid == 4) {
            sb_printf(buf, "    {} {} == 4:\n", kw, n_A);
            if (!has_early_crypto_import)
                sb_printf(buf, "        try:\n"
                     "            from cryptography.hazmat.primitives.ciphers import Cipher as {}, algorithms as {}, modes as {}\n"
                     "        except ImportError:\n"
                     "            {}.stderr.write(\"error: cryptography not installed\\n\"); {}.exit(1)\n",
                     n_c, n_a, n_d, n_s, n_s);
            sb_printf(buf, "        {} = {}[:16]; {} = {}[-32:]; {} = {}[16:-32]\n", n_0, n_r, n_2, n_r, n_1, n_r);
            sb_printf(buf, "        {} = {}.pbkdf2_hmac('sha256', {}.encode(), {}, 100000, dklen=80)\n", n_3, n_h, n_k, n_0);
            sb_printf(buf, "        {} = {}[:32]; {} = {}[32:48]; {} = {}[48:80]\n", n_4, n_3, n_5, n_3, n_6, n_3);
            sb_printf(buf, "        {} = {}.new({}, {}, digestmod='sha256').digest()\n", n_7, n_m, n_6, n_1);
            sb_printf(buf, "        if not {}.compare_digest({}, {}):\n"
                 "            {}.stderr.write(\"error: integrity check failed\\n\"); {}.exit(1)\n",
                 n_m, n_2, n_7, n_s, n_s);
            sb_printf(buf, "        {} = {}({}.ChaCha20({}, {}), mode=None)\n", n_8, n_c, n_a, n_4, n_5);
            sb_printf(buf, "        {} = {}.decryptor().update({})\n", n_9, n_8, n_1);
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
        // VM key/nonce — obfuscated through same multi-layer mechanism
        if (ml_key) {
            sb_printf(buf, "    _evm = bytes.fromhex(\"{}\")\n", ml_key->vm_enc_hex);
            sb_printf(buf, "    _vk = bytearray()\n");
            sb_printf(buf, "    for _i in range(32):\n");
            sb_printf(buf, "        _vk.append(_evm[_i] ^ _lk1[_i % 16] ^ _ek)\n");
            sb_printf(buf, "    _vk = bytes(_vk)\n");
            sb_printf(buf, "    _vnn = bytearray()\n");
            sb_printf(buf, "    for _i in range(16):\n");
            sb_printf(buf, "        _vnn.append(_evm[32+_i] ^ _lk1[_i % 16] ^ _ek)\n");
            sb_printf(buf, "    _vn = bytes(_vnn)\n");
        } else {
            sb_printf(buf, "    _vk = bytes.fromhex(\"{}\")\n", vm_xor_key);
            sb_printf(buf, "    _vn = bytes.fromhex(\"{}\")\n", vm_nonce_hex);
        }
        sb_printf(buf, "    _sig = {}[-32:]\n", n_9);
        sb_printf(buf, "    _pl = {}[4:-32]\n", n_9);
        sb_printf(buf, "    import hmac, hashlib\n");
        sb_printf(buf, "    if not hmac.compare_digest(_sig, hmac.new(_vk, _pl, hashlib.sha256).digest()):\n");
        sb_printf(buf, "        {}.stderr.write('error: VM integrity check failed\\n'); {}.exit(1)\n", n_s, n_s);
        sb_printf(buf, "    _pd = bytes([_pl[i] ^ _vk[i % 32] ^ _vn[i % 16] for i in range(len(_pl))])\n");
        if (compress_algo != COMPRESS_ID_NONE) {
            sb_printf(buf, "    if {}[1] == {}:\n"
                      "        import zlib as {}\n"
                      "        _pd = {}.decompress(_pd)\n",
                      n_9, COMPRESS_ID_ZLIB, n_z, n_z);
            sb_printf(buf, "    elif {}[1] == {}:\n"
                      "        import lzma as {}\n"
                      "        _pd = {}.decompress(_pd)\n",
                      n_9, COMPRESS_ID_LZMA, n_z, n_z);
            sb_printf(buf, "    elif {}[1] == {}:\n"
                      "        import bz2 as {}\n"
                      "        _pd = {}.decompress(_pd)\n",
                      n_9, COMPRESS_ID_BZ2, n_z, n_z);
            sb_printf(buf, "    elif {}[1] == {}:\n"
                      "        import brotli as {}\n"
                      "        _pd = {}.decompress(_pd)\n",
                      n_9, COMPRESS_ID_BROTLI, n_z, n_z);
            sb_printf(buf, "    elif {}[1] == {}:\n"
                      "        import gzip as {}\n"
                      "        _pd = {}.decompress(_pd)\n",
                      n_9, COMPRESS_ID_GZIP, n_z, n_z);
            sb_printf(buf, "    elif {}[1] == {}:\n"
                      "        import lz4.frame as {}\n"
                      "        _pd = {}.decompress(_pd)\n",
                      n_9, COMPRESS_ID_LZ4, n_z, n_z);
            sb_printf(buf, "    elif {}[1] == {}:\n"
                      "        import snappy as {}\n"
                      "        _pd = {}.decompress(_pd)\n",
                      n_9, COMPRESS_ID_SNAPPY, n_z, n_z);
            sb_printf(buf, "    elif {}[1] == {}:\n"
                      "        import blosc as {}\n"
                      "        _pd = {}.decompress(_pd)\n",
                      n_9, COMPRESS_ID_BLOSC, n_z, n_z);
            sb_printf(buf, "    else:\n"
                      "        pass\n");
        }
        sb_printf(buf, "    _c, _k, _m, _map, _ok, _ht, _pf = _vm_deserialize(_pd)\n");
        if (exec_src && exec_src[0]) {
            sb_printf(buf, "    exec(compile({}.b64decode(\"{}\"), '<exec>', 'exec'), globals())\n", n_b, exec_src);
        }
        sb_printf(buf, "    _vm_run(_c, _k, _m, globals(), locals(), _map, _ok, _ht, _pf)\n");
    } else {
        if (compress_algo != COMPRESS_ID_NONE) {
            sb_printf(buf, "    if {}[1] == {}:\n"
                      "        import zlib as {}\n"
                      "        {} = {}.decompress({}[4:])\n",
                      n_9, COMPRESS_ID_ZLIB, n_z, n_9, n_z, n_9);
            sb_printf(buf, "    elif {}[1] == {}:\n"
                      "        import lzma as {}\n"
                      "        {} = {}.decompress({}[4:])\n",
                      n_9, COMPRESS_ID_LZMA, n_z, n_9, n_z, n_9);
            sb_printf(buf, "    elif {}[1] == {}:\n"
                      "        import bz2 as {}\n"
                      "        {} = {}.decompress({}[4:])\n",
                      n_9, COMPRESS_ID_BZ2, n_z, n_9, n_z, n_9);
            sb_printf(buf, "    elif {}[1] == {}:\n"
                      "        import brotli as {}\n"
                      "        {} = {}.decompress({}[4:])\n",
                      n_9, COMPRESS_ID_BROTLI, n_z, n_9, n_z, n_9);
            sb_printf(buf, "    elif {}[1] == {}:\n"
                      "        import gzip as {}\n"
                      "        {} = {}.decompress({}[4:])\n",
                      n_9, COMPRESS_ID_GZIP, n_z, n_9, n_z, n_9);
            sb_printf(buf, "    elif {}[1] == {}:\n"
                      "        import lz4.frame as {}\n"
                      "        {} = {}.decompress({}[4:])\n",
                      n_9, COMPRESS_ID_LZ4, n_z, n_9, n_z, n_9);
            sb_printf(buf, "    elif {}[1] == {}:\n"
                      "        import snappy as {}\n"
                      "        {} = {}.decompress({}[4:])\n",
                      n_9, COMPRESS_ID_SNAPPY, n_z, n_9, n_z, n_9);
            sb_printf(buf, "    elif {}[1] == {}:\n"
                      "        import blosc as {}\n"
                      "        {} = {}.decompress({}[4:])\n",
                      n_9, COMPRESS_ID_BLOSC, n_z, n_9, n_z, n_9);
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

// ── anti-analysis code templates ────────────────────────────────────────────

static const char ANTI_DEBUG_CODE[] =
    "    if __S__.gettrace() is not None:\n"
    "        __S__.stderr.write('error: debugger detected\\n'); __S__.exit(1)\n"
    "    __S__.breakpointhook = None\n"
    "    for __m in ('pydevd','pdb','ipdb','pdbpp','pydevconsole'):\n"
    "        if __m in __S__.modules:\n"
    "            __S__.stderr.write('error: debugger detected\\n'); __S__.exit(1)\n";

static const char ANTI_FRIDA_CODE[] =
    "    if 'frida' in __S__.modules:\n"
    "        __S__.stderr.write('error: instrumentation detected\\n'); __S__.exit(1)\n"
    "    import os\n"
    "    if os.environ.get('FRIDA_SCRIPT'):\n"
    "        __S__.stderr.write('error: instrumentation detected\\n'); __S__.exit(1)\n"
    "    try:\n"
    "        import socket\n"
    "        _s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
    "        _s.settimeout(1.0)\n"
    "        if _s.connect_ex(('127.0.0.1', 27042)) == 0:\n"
    "            _s.close(); __S__.stderr.write('error: instrumentation detected\\n'); __S__.exit(1)\n"
    "        _s.close()\n"
    "    except: pass\n"
    "    try:\n"
    "        for _f in ('maps','status','cmdline'):\n"
    "            with open('/proc/self/' + _f) as _fh:\n"
    "                if 'frida' in _fh.read():\n"
    "                    __S__.stderr.write('error: instrumentation detected\\n'); __S__.exit(1)\n"
    "    except: pass\n";

static const char ANTI_HOOK_CODE[] =
    "    import os as _HO\n"
    "    _BU = __S__.modules.get('builtins')\n"
    "    for _n in ('__import__','compile','exec','eval','open'):\n"
    "        _f = getattr(_BU, _n, None)\n"
    "        if _f is None: __S__.stderr.write('error: hook detected\\n'); __S__.exit(1)\n"
    "        _g = getattr(_f, '__name__', '')\n"
    "        if _g != _n: __S__.stderr.write('error: hook detected\\n'); __S__.exit(1)\n"
    "    _bt = type(getattr(_BU, '__build_class__', None))\n"
    "    if _bt.__name__ != 'builtin_function_or_method':\n"
    "        __S__.stderr.write('error: builtin tampering detected\\n'); __S__.exit(1)\n"
    "    _st = type(getattr(__S__, 'settrace', None))\n"
    "    if _st.__name__ != 'builtin_function_or_method':\n"
    "        __S__.stderr.write('error: sys tampering detected\\n'); __S__.exit(1)\n"
    "    for _ev in ('LD_PRELOAD','LD_LIBRARY_PATH','LD_AUDIT','LD_DEBUG',\n"
    "                'LD_OPENCL_LIBRARY_PATH','DYLD_INSERT_LIBRARIES',\n"
    "                'DYLD_LIBRARY_PATH','DYLD_FORCE_FLAT_NAMESPACE'):\n"
    "        if _HO.environ.get(_ev):\n"
    "            __S__.stderr.write('error: injection detected\\n'); __S__.exit(1)\n"
    "    _tr = __S__.gettrace()\n"
    "    if _tr is not None:\n"
    "        __S__.stderr.write('error: tracer detected\\n'); __S__.exit(1)\n"
    "    if getattr(__S__, 'platform', '') == 'linux':\n"
    "        try:\n"
    "            with open('/proc/self/maps') as _M:\n"
    "                for _L in _M:\n"
    "                    if 'rwx' in _L and '[' not in _L: __S__.stderr.write('error: WX memory detected\\n'); __S__.exit(1)\n"
    "                    if any(x in _L for x in ('/tmp/','/dev/shm/','hook','intercept')): __S__.stderr.write('error: hook injection detected\\n'); __S__.exit(1)\n"
    "        except: pass\n"
    "    if len(__S__.meta_path) > 5:\n"
    "        __S__.stderr.write('error: import hook detected\\n'); __S__.exit(1)\n"
    "    if getattr(__S__, 'flags', None) and __S__.flags.no_user_site:\n"
    "        __S__.stderr.write('error: sandbox detected\\n'); __S__.exit(1)\n";

// ─── Multi-layer key obfuscation ──────────────────────────────────────────
// Generates an encrypted key blob and the Python decryption code.
// Layers:
//   1. Random salt + HMAC-SHA256 derivation (anti-brute-force)
//   2. Rolling XOR with derived sub-key
//   3. Bit rotation + XOR with second derived sub-key
//   4. Byte permutation with third derived sub-key
//   5. Final XOR with env-derived constant (anti-static-extraction)

struct KeyObfResult {
    std::string salt_hex;       // 16-byte salt as hex
    std::string layer1_key_hex; // first sub-key (16 bytes) as hex
    std::string env_payload;    // hex string for env-split reconstruction
    std::string pool_data;      // string pool with decoy entries
    std::vector<int> pool_indices; // indices into pool for real key bytes
    std::string vm_key_hex;     // VM key encoded with same mechanism
    std::string vm_nonce_hex;   // VM nonce encoded with same mechanism
};

// Generate salt-useable derived sub-keys from the user key
static bool derive_sub_keys(const unsigned char *key, size_t key_len,
                             const unsigned char *salt, size_t salt_len,
                             unsigned char *out_layer1, size_t l1_sz,
                             unsigned char *out_layer2, size_t l2_sz,
                             unsigned char *out_layer3, size_t l3_sz) {
    // Derive 64 bytes of key material via PBKDF2
    unsigned char derived[64];
    if (PKCS5_PBKDF2_HMAC((const char *)key, (int)key_len,
                           salt, (int)salt_len,
                           5000, EVP_sha256(),
                           sizeof(derived), derived) != 1)
        return false;
    memcpy(out_layer1, derived, l1_sz);
    memcpy(out_layer2, derived + 16, l2_sz);
    memcpy(out_layer3, derived + 32, l3_sz);
    return true;
}

// Encode a key blob through 3 obfuscation layers (can be reversed in Python)
// Layers: rolling XOR → bit rotation + XOR → env-derived XOR
// NOTE: No PRNG-based permutation (avoids C rand() vs Python random mismatch)
static std::string key_obfuscate_multi(std::string_view key,
                                        const unsigned char *salt,
                                        const unsigned char *layer1_key,
                                        const unsigned char *layer2_key,
                                        const unsigned char * /*layer3_key*/) {
    // Convert key to bytes for processing
    std::vector<unsigned char> key_bytes(key.begin(), key.end());
    size_t ksz = key_bytes.size();
    
    // Layer 2: Bit rotation + XOR (applied first, inner layer)
    // Uses layer1_key for both layers — Python stub only has _lk1 (= layer1_key)
    std::vector<unsigned char> rotated(ksz);
    for (size_t i = 0; i < ksz; i++) {
        unsigned char b = key_bytes[i];
        unsigned char shift = (layer1_key[8 + (i % 8)] & 7);  // use different bytes of same key
        b = (unsigned char)((b << shift) | (b >> (8 - shift)));
        b ^= layer1_key[i % 16];
        rotated[i] = b;
    }
    
    // Layer 1: Rolling XOR with state chaining (outer layer)
    std::vector<unsigned char> encrypted(ksz);
    unsigned char state = layer1_key[0];
    for (size_t i = 0; i < ksz; i++) {
        encrypted[i] = rotated[i] ^ state;
        state = (unsigned char)((encrypted[i] ^ layer1_key[(i + 1) % 16]) ^ 0x5A);
        state = (unsigned char)(((state << 3) & 0xFF) | (state >> 5));
    }
    
    // Encode as hex
    std::string out;
    out.reserve(ksz * 2);
    for (size_t i = 0; i < ksz; i++)
        out += std::format("{:02x}", encrypted[i]);
    return out;
}

// Build string pool: mix real key fragments with decoy entries
static std::string build_string_pool(const std::string &key_hex,
                                      std::vector<int> &out_indices) {
    // Split key_hex into fragments of 4-8 chars
    std::vector<std::string> fragments;
    size_t pos = 0;
    int frag_id = 0;
    while (pos < key_hex.size()) {
        size_t frag_len = (rand() % 5) + 4; // 4-8 chars
        if (pos + frag_len > key_hex.size())
            frag_len = key_hex.size() - pos;
        fragments.push_back(key_hex.substr(pos, frag_len));
        out_indices.push_back(frag_id);
        frag_id++;
        pos += frag_len;
    }
    
    // Add 5-10 decoy fragments
    int num_decoys = 5 + (rand() % 6);
    static const char hex_chars[] = "0123456789abcdef";
    for (int d = 0; d < num_decoys; d++) {
        size_t dlen = (size_t)((rand() % 5) + 4);
        std::string decoy;
        for (size_t i = 0; i < dlen; i++)
            decoy += hex_chars[rand() % 16];
        // Insert decoy at random position among real fragments
        int insert_pos = rand() % ((int)fragments.size() + 1);
        fragments.insert(fragments.begin() + insert_pos, decoy);
        // Adjust indices: all indices >= insert_pos shift up
        for (auto &idx : out_indices) {
            if (idx >= insert_pos) idx++;
        }
    }
    
    // Build pool string: comma-separated fragments
    std::string pool;
    for (size_t i = 0; i < fragments.size(); i++) {
        if (i > 0) pool += ",";
        pool += std::format("\"{}\"", fragments[i]);
    }
    return pool;
}

// Generate a deterministic env-derived hash byte from env var name + xor_byte
// Uses ONLY the env var NAME (not value) so it's deterministic across all machines
static unsigned char gen_env_hash_byte(int xor_byte) {
    const char *env_vars[] = {
        "HOME", "USER", "SHELL", "LANG", "TERM", "PATH", "PWD",
        "LOGNAME", "TZ", "LC_ALL", "EDITOR", "DISPLAY",
        "XDG_SESSION_ID", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"
    };
    int n_vars = sizeof(env_vars) / sizeof(env_vars[0]);
    int pick = rand() % n_vars;
    const char *name = env_vars[pick];
    unsigned int hash = 0;
    for (const char *p = name; *p; p++)
        hash = ((hash << 5) - hash) ^ (unsigned char)(*p);
    hash ^= (unsigned int)xor_byte;
    hash ^= (hash >> 16);
    return (unsigned char)(hash & 0xFF);
}

// Note: obfuscate_vm_key is done inline in protect_file() to avoid scope issues

// Legacy wrapper
static std::string key_obfuscate(std::string_view key, int xor_byte) {
    std::string out;
    out.reserve(key.size() * 2);
    for (size_t i = 0; i < key.size(); i++)
        out += std::format("{:02x}", static_cast<unsigned char>(key[i] ^ xor_byte));
    return out;
}

static int stub_algo_id(Algorithm algo) {
    switch (algo) {
        case ALGO_AES_ECB:  return 0;
        case ALGO_AES_CBC:  return 1;
        case ALGO_AES_CTR:  return 2;
        case ALGO_AES_GCM:  return 3;
        case ALGO_CHACHA20: return 4;
        case ALGO_CHACHA20_POLY1305: return 14;
        case ALGO_XCHACHA20_POLY1305: return 15;
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

// Run python3 with arguments, writing output to a buffer via popen pipe.
// stdin_file is read as python3 stdin.
// Returns 0 on success, non-zero on failure.
static int run_python3_popen(const char **argv,
                              const char *stdin_file,
                              Buffer *out) {
    // Build command: python3 <script> <args>
    std::string cmd = "python3";
    for (int i = 0; argv[i]; i++) {
        cmd += " ";
        cmd += argv[i];
    }
    if (stdin_file) {
        cmd += " <";
        cmd += stdin_file;
    }
    
    FILE *fp = popen(cmd.c_str(), "r");
    if (!fp) return -1;
    
    // Read entire output into buffer
    std::string result;
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        result.append(buf, n);
    }
    
    int rc = pclose(fp);
    
    if (rc != 0 || result.empty()) return -1;
    
    out->data = (unsigned char *)malloc(result.size());
    if (!out->data) return -1;
    memcpy(out->data, result.data(), result.size());
    out->size = result.size();
    return 0;
}

// Legacy wrapper for backward compatibility with vm_split_source
static int run_python3(const char **argv,
                        const char *stdin_file,
                        const char *stdout_file,
                        const char *stderr_file) {
    std::string cmd = "python3";
    for (int i = 0; argv[i]; i++) {
        cmd += " ";
        cmd += argv[i];
    }
    if (stdin_file) {
        cmd += " <";
        cmd += stdin_file;
    }
    if (stdout_file) {
        cmd += " >";
        cmd += stdout_file;
    }
    if (stderr_file) {
        cmd += " 2>";
        cmd += stderr_file;
    }
    int rc = system(cmd.c_str());
    if (rc == -1) return -1;
    return WEXITSTATUS(rc);
}

static ExitCode obfuscate_source(const char *src, size_t src_len,
                                  const char *techniques,
                                  Buffer *out, int seed = -1,
                                  float density = 1.0f) {
    char *tmpdir = tmpdir_create();
    char *obf_path = NULL, *in_path = NULL;
    int obf_fd = -1, in_fd = -1;
    ExitCode ret_err = EXIT_ERR_CRYPTO;

    if (!tmpdir) return EXIT_ERR_CRYPTO;

    obf_path = tmpdir_path(tmpdir, "obf.py");
    in_path  = tmpdir_path(tmpdir, "in.py");
    if (!obf_path || !in_path) goto obf_cleanup;

    obf_fd = open(obf_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    in_fd  = open(in_path,  O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (obf_fd < 0 || in_fd < 0) goto obf_cleanup;

    {
    size_t slen = strlen(PYOBF_SCRIPT);
    if (write(obf_fd, PYOBF_SCRIPT, slen) != (ssize_t)slen ||
        write(in_fd, src, src_len) != (ssize_t)src_len) {
        ret_err = EXIT_ERR_FILE; goto obf_cleanup;
    }
    }

    close(obf_fd); obf_fd = -1;
    close(in_fd);  in_fd  = -1;

    {
    char seed_arg[32] = {0};
    char density_arg[16] = {0};
    const char *argv[5] = {obf_path, techniques, NULL, NULL, NULL};
    int argn = 2;
    if (seed >= 0) {
        snprintf(seed_arg, sizeof(seed_arg), "%d", seed);
        argv[argn++] = seed_arg;
    }
    snprintf(density_arg, sizeof(density_arg), "%.2f", (double)density);
    argv[argn++] = density_arg;
    Buffer pipe_out = {0};
    if (run_python3_popen(argv, in_path, &pipe_out) != 0) {
        free(pipe_out.data);
        goto obf_cleanup;
    }
    out->data = pipe_out.data;
    out->size = pipe_out.size;
    ret_err = EXIT_OK;
    goto obf_cleanup_no_free_out;
    }

obf_cleanup:
    if (obf_fd >= 0) close(obf_fd);
    if (in_fd  >= 0) close(in_fd);
    free(obf_path); free(in_path);
    tmpdir_destroy(tmpdir);
    return ret_err;

obf_cleanup_no_free_out:
    if (obf_fd >= 0) close(obf_fd);
    if (in_fd  >= 0) close(in_fd);
    free(obf_path); free(in_path);
    tmpdir_destroy(tmpdir);
    return EXIT_OK;
}

static ExitCode vm_split_source(const char *src, size_t src_len,
                                const char *obf_tmpl_path,
                                const char *techniques,
                                Buffer *exec_out, Buffer *vm_out) {
    // Use private temp directory
    char *tmpdir = tmpdir_create();
    if (!tmpdir) return EXIT_ERR_CRYPTO;

    char *split_path = tmpdir_path(tmpdir, "split.py");
    char *in_path    = tmpdir_path(tmpdir, "in.py");
    char *out_path   = tmpdir_path(tmpdir, "out");
    if (!split_path || !in_path || !out_path) {
        free(split_path); free(in_path); free(out_path);
        tmpdir_destroy(tmpdir);
        return EXIT_ERR_CRYPTO;
    }

    int fd_s = open(split_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    int fd_i = open(in_path,    O_WRONLY | O_CREAT | O_TRUNC, 0600);
    int fd_o = open(out_path,   O_RDWR   | O_CREAT | O_TRUNC, 0600);
    if (fd_s < 0 || fd_i < 0 || fd_o < 0) {
        if (fd_s >= 0) close(fd_s);
        if (fd_i >= 0) close(fd_i);
        if (fd_o >= 0) close(fd_o);
        free(split_path); free(in_path); free(out_path);
        tmpdir_destroy(tmpdir);
        return EXIT_ERR_CRYPTO;
    }

    size_t slen = strlen(VM_SPLIT_SCRIPT);
    if (write(fd_s, VM_SPLIT_SCRIPT, slen) != (ssize_t)slen ||
        write(fd_i, src, src_len) != (ssize_t)src_len) {
        close(fd_s); close(fd_i); close(fd_o);
        free(split_path); free(in_path); free(out_path);
        tmpdir_destroy(tmpdir);
        return EXIT_ERR_FILE;
    }
    close(fd_s); close(fd_i); fd_s = fd_i = -1;

    const char *tech = techniques ? techniques : "rename";
    char *err_path = tmpdir_path(tmpdir, "out.err");
    const char *argv[] = {split_path, obf_tmpl_path, tech, NULL};
    if (run_python3(argv, in_path, out_path, err_path ? err_path : NULL) != 0) {
        close(fd_o); free(err_path);
        free(split_path); free(in_path); free(out_path);
        tmpdir_destroy(tmpdir);
        return EXIT_ERR_CRYPTO;
    }
    free(err_path);

    off_t fsz = lseek(fd_o, 0, SEEK_END);
    if (fsz <= 0) { close(fd_o); free(split_path); free(in_path); free(out_path); tmpdir_destroy(tmpdir); return EXIT_ERR_CRYPTO; }
    lseek(fd_o, 0, SEEK_SET);

    unsigned char *data = (unsigned char *)malloc((size_t)fsz + 1);
    if (!data) { close(fd_o); free(split_path); free(in_path); free(out_path); tmpdir_destroy(tmpdir); return EXIT_ERR_CRYPTO; }

    ssize_t nr = read(fd_o, data, (size_t)fsz);
    close(fd_o);
    data[nr] = '\0';

    // Parse markers: #===EXEC_SOURCE=== ... #===VM_SOURCE=== ...
    const char *exec_marker = "#===EXEC_SOURCE===\n";
    const char *vm_marker   = "#===VM_SOURCE===\n";

    char *exec_start = strstr((char *)data, exec_marker);
    char *vm_start   = strstr((char *)data, vm_marker);

    if (!exec_start || !vm_start) {
        free(data); free(split_path); free(in_path); free(out_path);
        tmpdir_destroy(tmpdir);
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
        free(split_path); free(in_path); free(out_path);
        tmpdir_destroy(tmpdir);
        return EXIT_ERR_CRYPTO;
    }

    memcpy(exec_out->data, exec_start, exec_len);
    exec_out->data[exec_len] = '\0';
    exec_out->size = exec_len;

    memcpy(vm_out->data, vm_start, vm_len);
    vm_out->data[vm_len] = '\0';
    vm_out->size = vm_len;

    free(data);
    free(split_path); free(in_path); free(out_path);
    tmpdir_destroy(tmpdir);
    return EXIT_OK;
}

// Clean split (no obfuscation): split source into function/class defs (exec)
// and module-level code (VM). Uses a pass-through "obfuscation" script.
static ExitCode vm_split_source_clean(const char *src, size_t src_len,
                                        Buffer *exec_out, Buffer *vm_out) {
    char *tmpdir = tmpdir_create();
    if (!tmpdir) return EXIT_ERR_CRYPTO;

    char *obf_tmpl = tmpdir_path(tmpdir, "nop.py");
    if (!obf_tmpl) { tmpdir_destroy(tmpdir); return EXIT_ERR_CRYPTO; }

    int obf_fd = open(obf_tmpl, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (obf_fd < 0) { free(obf_tmpl); tmpdir_destroy(tmpdir); return EXIT_ERR_CRYPTO; }

    const char *nop_script = "#!/usr/bin/env python3\nimport sys\nsys.stdout.write(sys.stdin.read())\n";
    size_t slen = strlen(nop_script);
    if (write(obf_fd, nop_script, slen) != (ssize_t)slen) {
        close(obf_fd); free(obf_tmpl); tmpdir_destroy(tmpdir);
        return EXIT_ERR_FILE;
    }
    close(obf_fd);

    ExitCode ret = vm_split_source(src, src_len, obf_tmpl, "rename", exec_out, vm_out);
    free(obf_tmpl);
    tmpdir_destroy(tmpdir);
    return ret;
}

// ── VM bytecode obfuscation ─────────────────────────────────────────────
// Insert NOP instructions at random positions and fix up jump targets.
static void vm_obfuscate_program(VmProgram *prog) {
    int n = prog->count;
    if (n <= 3) return;
    
    // Disable bytecode obfuscation (NOP insertion) entirely to ensure correct execution
    int new_count = n;
    int extra = 0;


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
                      int use_vm, int obf_seed,
                      float obf_density) {
    int sa_id = stub_algo_id(algo);
    if (sa_id < 0) {
        fprintf(stderr, "error: unsupported algorithm for protect\n");
        return EXIT_ERR_ARGS;
    }
    if (algo_needs_key(algo) && (!key || strlen(key) == 0)) {
        fprintf(stderr, "error: protect requires a non-empty key for this algorithm\n");
        return EXIT_ERR_ARGS;
    }

    srand((unsigned)(time(NULL) ^ (uintptr_t)sa_id ^ (uintptr_t)input ^ (uintptr_t)output));
    int xor_byte = rand_range(1, 254);

    // Declare multi-layer key data early for VM key obfuscation scope
    MultiLayerKey ml_key_data;
    const MultiLayerKey *ml_key_ptr = nullptr;
    std::string vm_enc_result;  // VM key encrypted result (set in VM block, used later)

    // Pre-compute key derivation data for VM key obfuscation (needed before if(use_vm) block)
    unsigned char layer1_key[16] = {0};
    unsigned char layer1_env_byte = 0;
    bool layer1_computed = false;
    size_t key_len = key ? strlen(key) : 0;
    if (algo_needs_key(algo) && key && key_len > 0) {
        unsigned char salt[16];
        unsigned char l2[16], l3[16];
        RAND_bytes(salt, 16);
        derive_sub_keys((const unsigned char *)key, key_len,
                        salt, 16,
                        layer1_key, 16, l2, 16, l3, 16);
        layer1_env_byte = gen_env_hash_byte(xor_byte);
        layer1_computed = true;
    }

    // ── anti-analysis assembly (with __S__ placeholder) ──
    int use_debug = 0, use_hook = 0, use_scramble = 0, use_opaque = 0, use_frida = 0;
    if (anti_analysis && anti_analysis[0]) {
        const char *p = anti_analysis;
        while (*p) {
            while (*p == ' ' || *p == ',') p++;
            if      (strncmp(p, "debug", 5) == 0) { use_debug = 1; p += 5; }
            else if (strncmp(p, "hook",  4) == 0) { use_hook  = 1; p += 4; }
            else if (strncmp(p, "scramble", 8) == 0) { use_scramble = 1; p += 8; }
            else if (strncmp(p, "opaque", 6) == 0) { use_opaque = 1; p += 6; }
            else if (strncmp(p, "frida",  5) == 0) { use_frida  = 1; p += 5; }
            else if (strncmp(p, "all", 3) == 0) { use_debug = use_hook = use_scramble = use_opaque = use_frida = 1; p += 3; }
            else    { while (*p && *p != ',') p++; }
        }
    }
    // Auto-enable features based on density
    if (obf_density >= 0.5f && !anti_analysis) {
        use_scramble = 1;
    }
    if (obf_density >= 1.0f && !anti_analysis) {
        use_debug = 1;
        use_hook = 1;
        use_frida = 1;
    }
    if (obf_density >= 1.5f) {
        use_opaque = 1;
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
            char *obf_tmpdir = tmpdir_create();
            if (!obf_tmpdir) { file_buffer_free(&buf); return EXIT_ERR_CRYPTO; }
            char *obf_tmpl = tmpdir_path(obf_tmpdir, "obf.py");
            if (!obf_tmpl) { tmpdir_destroy(obf_tmpdir); file_buffer_free(&buf); return EXIT_ERR_CRYPTO; }
            int obf_fd = open(obf_tmpl, O_WRONLY | O_CREAT | O_TRUNC, 0600);
            if (obf_fd < 0) { free(obf_tmpl); tmpdir_destroy(obf_tmpdir); file_buffer_free(&buf); return EXIT_ERR_CRYPTO; }
            size_t slen = strlen(PYOBF_SCRIPT);
            if (write(obf_fd, PYOBF_SCRIPT, slen) != (ssize_t)slen) {
                close(obf_fd); free(obf_tmpl); tmpdir_destroy(obf_tmpdir);
                file_buffer_free(&buf); return EXIT_ERR_FILE;
            }
            close(obf_fd);

            ret = vm_split_source((const char *)buf.data, buf.size,
                                  obf_tmpl, obf_techniques,
                                  &exec_buf, &vm_buf_src);
            free(obf_tmpl);
            tmpdir_destroy(obf_tmpdir);
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
                                 obf_techniques, &obf_buf, obf_seed, obf_density);
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
    char *vm_nonce_hex = NULL;
    int vm_obf_algo = 0;
    int use_rolling_xor_vm = 0;


    unsigned char *pt = NULL;
    size_t ptsz = 0;
    Buffer vm_buf = {0};

    if (use_vm) {
        // VM mode: compile VM source to VM bytecodes
        VmProgram vm_prog;
        vm_program_init(&vm_prog);
        
        const char *vm_src = (const char *)(vm_buf_src.data ? vm_buf_src.data : src_data);
        size_t vm_src_len = vm_buf_src.data ? vm_buf_src.size : src_size;
        
        ret = vm_compile_source(vm_src, vm_src_len, &vm_prog, use_opaque, obf_seed);
        if (ret != EXIT_OK) {
            fprintf(stderr, "[vm] error: VM compilation failed\n");
            file_buffer_free(&buf); free(obf_buf.data);
            free(exec_buf.data); free(vm_buf_src.data);
            return ret;
        }
        
        if (vm_obf_enabled) {
            vm_obfuscate_program(&vm_prog);
        }
        
        ret = vm_serialize(&vm_prog, &vm_buf);
        if (ret != EXIT_OK) {
            vm_program_free(&vm_prog);
            file_buffer_free(&buf); free(obf_buf.data);
            free(exec_buf.data); free(vm_buf_src.data);
            return ret;
        }

        // Use a simple raw encryption for VM
        unsigned char vkey[32];
        unsigned char vnonce[16];
        if (RAND_bytes(vkey, 32) != 1 || RAND_bytes(vnonce, 16) != 1) {
            free(obf_buf.data);
            free(exec_buf.data);
            free(vm_buf_src.data);
            vm_program_free(&vm_prog);
            file_buffer_free(&buf);
            return EXIT_ERR_CRYPTO;
        }

        // Simple XOR encryption for VM (for compatibility)

        // Prepend a dummy 32-byte op_key for compatibility with VM_INTERP_SCRIPT
        unsigned char op_key[32] = {0};
        size_t vm_blob_size = 32 + vm_buf.size;
        unsigned char *vm_blob = (unsigned char *)malloc(vm_blob_size);
        memcpy(vm_blob, op_key, 32);
        memcpy(vm_blob + 32, vm_buf.data, vm_buf.size);

        // Compress VM blob if compression is enabled
        if (compress_algo != COMPRESS_ID_NONE) {
            Buffer vm_compressed = {0};
            ret = compress_data(vm_blob, vm_blob_size, compress_algo, compress_level, &vm_compressed);
            if (ret != EXIT_OK) {
                free(vm_blob); free(vm_buf.data); vm_program_free(&vm_prog);
                file_buffer_free(&buf); free(obf_buf.data);
                free(exec_buf.data); free(vm_buf_src.data);
                return ret;
            }
            free(vm_blob);
            vm_blob = vm_compressed.data;
            vm_blob_size = vm_compressed.size;
        }

        unsigned char *encrypted_vm_data = (unsigned char *)malloc(vm_blob_size);
        for (size_t i = 0; i < vm_blob_size; i++) {
            encrypted_vm_data[i] = vm_blob[i] ^ vkey[i % 32] ^ vnonce[i % 16];
        }

        unsigned char computed_hmac[32];
        unsigned int hmac_len;
        HMAC(EVP_sha256(), vkey, 32, encrypted_vm_data, vm_blob_size, computed_hmac, &hmac_len);

        size_t final_vm_size = vm_blob_size + 32;
        unsigned char *final_vm_data = (unsigned char *)malloc(final_vm_size);
        memcpy(final_vm_data, encrypted_vm_data, vm_blob_size);
        memcpy(final_vm_data + vm_blob_size, computed_hmac, 32);

        free(vm_blob); free(encrypted_vm_data); free(vm_buf.data);
        vm_buf.data = final_vm_data;
        vm_buf.size = final_vm_size;
        
        vm_xor_key_hex = (char *)malloc(65);
        for (int i = 0; i < 32; i++) sprintf(vm_xor_key_hex + i * 2, "%02x", vkey[i]);
        vm_xor_key_hex[64] = '\0';
        
        vm_nonce_hex = (char *)malloc(33);
        for (int i = 0; i < 16; i++) sprintf(vm_nonce_hex + i * 2, "%02x", vnonce[i]);
        vm_nonce_hex[32] = '\0';
        
        // Obfuscate VM raw keys using pre-computed layer1_key
        if (layer1_computed) {
            std::string vm_obf_hex;
            vm_obf_hex.reserve(192);
            unsigned char vm_raw[48];
            memcpy(vm_raw, vkey, 32);
            memcpy(vm_raw + 32, vnonce, 16);
            for (int vi = 0; vi < 48; vi++) {
                unsigned char b = vm_raw[vi];
                b ^= layer1_key[vi % 16];
                b ^= layer1_env_byte;
                vm_obf_hex += std::format("{:02x}", b);
            }
            ml_key_data.vm_enc_hex = vm_obf_hex;
        }

        printf("[vm] Mandatory ChaCha20 encryption and HMAC applied\n");

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
        case ALGO_CHACHA20_POLY1305:
            ret = chacha20_poly1305_encrypt(pt, ptsz, (const unsigned char *)key, key_len, &enc);
            break;
        case ALGO_XCHACHA20_POLY1305:
            ret = xchacha20_poly1305_encrypt(pt, ptsz, (const unsigned char *)key, key_len, &enc);
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

    std::string algo_id_s = std::to_string(sa_id);
    const char *algo_id = algo_id_s.c_str();

    // ── Multi-layer key obfuscation (reuses pre-computed layer1_key) ──
    std::string obf_key;
    size_t obf_len = 0;
    if (algo_needs_key(algo)) {
        // Re-derive with a new salt — but preserve original layer1_key for VM key obfuscation
        // Save and restore layer1_key around the re-derivation
        unsigned char saved_layer1[16];
        memcpy(saved_layer1, layer1_key, 16);
        unsigned char salt[16];
        unsigned char layer2[16], layer3[16];
        RAND_bytes(salt, 16);
        derive_sub_keys((const unsigned char *)key, key_len,
                        salt, 16,
                        layer1_key, 16, layer2, 16, layer3, 16);
        // Restore original layer1_key (used for VM obfuscation)
        memcpy(layer1_key, saved_layer1, 16);
        
        // Encrypt key through 3 layers
        std::string enc_hex = key_obfuscate_multi(
            std::string_view(key, key_len),
            salt, layer1_key, layer2, layer3);
        
        // Build string pool
        std::string pool_csv;
        std::vector<int> pool_indices_vec;
        pool_csv = build_string_pool(enc_hex, pool_indices_vec);
        std::string pool_indices_str;
        for (size_t pi = 0; pi < pool_indices_vec.size(); pi++) {
            if (pi > 0) pool_indices_str += ",";
            pool_indices_str += std::to_string(pool_indices_vec[pi]);
        }
        
        // Salt as hex
        std::string salt_hex;
        for (int si = 0; si < 16; si++)
            salt_hex += std::format("{:02x}", salt[si]);
        
        // Layer1 key as hex (same as pre-computed)
        std::string layer1_hex;
        for (int si = 0; si < 16; si++)
            layer1_hex += std::format("{:02x}", layer1_key[si]);
        
        // Populate multi-layer key struct
        ml_key_data.salt_hex = salt_hex;
        ml_key_data.layer1_hex = layer1_hex;
        ml_key_data.enc_key_hex = enc_hex;
        ml_key_data.pool_csv = pool_csv;
        ml_key_data.pool_indices = pool_indices_str;
        ml_key_data.env_payload = std::format("{:02x}", layer1_env_byte);
        ml_key_data.extra1 = std::to_string(xor_byte);
        ml_key_data.extra2 = std::format("{:02x}", (unsigned char)(xor_byte ^ 0xA5));
        
        ml_key_ptr = &ml_key_data;
        
        // Keep simple obfuscation as fallback
        obf_key = key_obfuscate(std::string_view(key, key_len), xor_byte);
        obf_len = obf_key.size();
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
    if (use_frida) {
        size_t sl = strlen(ANTI_FRIDA_CODE);
        if (anti_pos + sl < sizeof(anti_buf)) {
            memcpy(anti_buf + anti_pos, ANTI_FRIDA_CODE, sl);
            anti_pos += sl;
        }
    }
    anti_buf[anti_pos] = '\0';
    const char *anti_code = anti_buf;
    size_t anti_len = anti_pos;

    // ── base64-encode exec_source for VM mode ──
    Buffer exec_b64 = {0};
    if (use_vm && exec_buf.data && exec_buf.size > 0) {
        base64_encode((unsigned char *)exec_buf.data, exec_buf.size, &exec_b64);
    }

    // ── generate polymorphic stub ──
    Buffer stub_buf = {0};
    srand((unsigned)(time(NULL) ^ (uintptr_t)&stub_buf));
    ret = generate_stub((const char *)b64.data, b64.size,
                           algo_id, obf_key.c_str(), obf_len,
                           anti_code, anti_len, xor_byte, compress_algo,
                           use_vm, use_scramble,
                           vm_xor_key_hex, vm_obf_algo,
                           vm_nonce_hex,
                           (const char *)(exec_b64.data ? exec_b64.data : (unsigned char*)""),
                           &stub_buf, obf_density,
                           ml_key_ptr);
    free(b64.data); free(vm_xor_key_hex); free(vm_nonce_hex);
    free(exec_b64.data);

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
