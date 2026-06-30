#ifndef CRYPTO_PROTECT_INTERNAL_H
#define CRYPTO_PROTECT_INTERNAL_H

#include "crypto/common.h"
#include "crypto/file_util.h"
#include "vm/vm_types.h"
#include <string>
#include <vector>
#include <string_view>
#include <format>

#define HEADER_SIZE 4
#define SALT_SIZE 16
#define HMAC_SIZE 32

#define SB_SZ (65536 * 4)

#define ANTI_FRAG_GETTRACE \
    "    if __S__.gettrace() is not None:\n" \
    "        __S__.stderr.write('error: debugger detected\\n'); __S__.exit(1)\n" \
    "    __S__.settrace(None); __S__.setprofile(None)\n"
#define ANTI_FRAG_BREAKPOINT \
    "    __S__.breakpointhook = None\n" \
    "    for _qm in ('pydevd','pdb','ipdb','pdbpp','pydevconsole'):\n" \
    "        if _qm in __S__.modules:\n" \
    "            __S__.stderr.write('error: debugger detected\\n'); __S__.exit(1)\n" \
    "    try:\n" \
    "        import time\n" \
    "        _t1 = time.perf_counter()\n" \
    "        _ = [i for i in range(2000)]\n" \
    "        _t2 = time.perf_counter()\n" \
    "        if _t2 - _t1 > 5.0:\n" \
    "            __S__.stderr.write('error: slowdown detected\\n'); __S__.exit(1)\n" \
    "    except: pass\n" \
    "    try:\n" \
    "        _eh = type(getattr(__S__, 'excepthook', None))\n" \
    "        if _eh.__name__ != 'builtin_function_or_method':\n" \
    "            __S__.stderr.write('error: exception hook tampered\\n'); __S__.exit(1)\n" \
    "    except: pass\n" \
    "    try:\n" \
    "        import socket\n" \
    "        _s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n" \
    "        _s2.settimeout(1.0)\n" \
    "        if _s2.connect_ex(('127.0.0.1', 5678)) == 0:\n" \
    "            _s2.close(); __S__.stderr.write('error: debugger port detected\\n'); __S__.exit(1)\n" \
    "        _s2.close()\n" \
    "    except: pass\n"
#define ANTI_FRAG_HOOK \
    "    _BU = __S__.modules.get('builtins')\n" \
    "    for _qn in ('__import__','compile','exec','eval','open'):\n" \
    "        _qf = getattr(_BU, _qn, None)\n" \
    "        if _qf is None: __S__.stderr.write('error: hook detected\\n'); __S__.exit(1)\n" \
    "        _qg = getattr(_qf, '__name__', '')\n" \
    "        if _qg != _qn: __S__.stderr.write('error: hook detected\\n'); __S__.exit(1)\n" \
    "    _eh = type(getattr(__S__, 'excepthook', None))\n" \
    "    if _eh.__name__ != 'builtin_function_or_method':\n" \
    "        __S__.stderr.write('error: exception hook tampered\\n'); __S__.exit(1)\n"
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
    "    except: pass\n" \
    "    try:\n" \
    "        import gc\n" \
    "        for _O in gc.get_objects():\n" \
    "            _TN = type(_O).__name__\n" \
    "            if 'frida' in _TN.lower() or 'gum' in _TN.lower():\n" \
    "                __S__.stderr.write('error: instrumentation detected\\n'); __S__.exit(1)\n" \
    "    except: pass\n"

#define ANTI_FRAG_META \
    "    if len(__S__.meta_path) > 5:\n" \
    "        __S__.stderr.write('error: import hook detected\\n'); __S__.exit(1)\n" \
    "    if getattr(__S__, 'flags', None) and __S__.flags.no_user_site:\n" \
    "        __S__.stderr.write('error: sandbox detected\\n'); __S__.exit(1)\n" \
    "    import platform as _PF\n" \
    "    if any(x in _PF.platform().lower() for x in ['vmware', 'virtualbox', 'qemu', 'parallels']):\n" \
    "        __S__.stderr.write('error: virtual machine detected\\n'); __S__.exit(1)\n" \
    "    try:\n" \
    "        _G = __S__._getframe\n" \
    "        _FD = 0; _F = _G()\n" \
    "        while _F:\n" \
    "            _FD += 1\n" \
    "            if _FD > 50:\n" \
    "                __S__.stderr.write('error: deep frame detected\\n'); __S__.exit(1)\n" \
    "            _F = _F.f_back\n" \
    "    except: pass\n"

namespace protect {

struct MultiLayerKey {
    std::string salt_hex;
    std::string layer1_hex;
    std::string enc_key_hex;
    std::string pool_csv;
    std::string pool_indices;
    std::string env_payload;
    std::string extra1;
    std::string extra2;
    std::string vm_enc_hex;
};

struct KeyObfResult {
    std::string salt_hex;
    std::string layer1_key_hex;
    std::string env_payload;
    std::string pool_data;
    std::vector<int> pool_indices;
    std::string vm_key_hex;
    std::string vm_nonce_hex;
};

int has_tech(const char *techs, const char *target);
ExitCode apply_rolling_xor_obfuscation(const char *src, size_t src_len, Buffer *out);
ExitCode apply_xor_bit_rotation_obfuscation(const char *src, size_t src_len, Buffer *out);
int rand_csprng_range(int lo, int hi);
int rand_range(int lo, int hi);
std::string rand_name();

inline void sb_append(std::string &buf, std::string_view s) {
    buf += s;
}

template<typename... Args>
void sb_printf(std::string &buf, std::string_view fmt, const Args&... args) {
    buf += std::vformat(fmt, std::make_format_args(args...));
}

std::string patch_sys_name(std::string_view code, std::string_view sys_name);

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
                       float density = 1.0f,
                       const MultiLayerKey *ml_key = nullptr,
                       int use_antidump = 0);

bool derive_sub_keys(const unsigned char *key, size_t key_len,
                     const unsigned char *salt, size_t salt_len,
                     unsigned char *out_layer1, size_t l1_sz,
                     unsigned char *out_layer2, size_t l2_sz,
                     unsigned char *out_layer3, size_t l3_sz);

std::string key_obfuscate_multi(std::string_view key,
                                const unsigned char *salt,
                                const unsigned char *layer1_key,
                                const unsigned char *layer2_key,
                                const unsigned char *layer3_key);

std::string build_string_pool(const std::string &key_hex,
                              std::vector<int> &indices);

unsigned char gen_env_hash_byte(int xor_byte);
std::string key_obfuscate(std::string_view key, int xor_byte);
int stub_algo_id(Algorithm algo);

int run_python3_popen(const char **argv, const char *stdin_file, Buffer *out);
int run_python3(const char **argv, const char *stdin_file,
                const char *stdout_file, const char *stderr_file);
ExitCode obfuscate_source(const char *src, size_t src_len,
                          const char *techniques, Buffer *out,
                          int seed = -1, float density = 1.0f);
ExitCode vm_split_source(const char *src, size_t src_len,
                         const char *obf_tmpl_path,
                         const char *techniques,
                         Buffer *exec_out, Buffer *vm_out);
ExitCode vm_split_source_clean(const char *src, size_t src_len,
                               Buffer *exec_out, Buffer *vm_out);
void vm_obfuscate_program(VmProgram *prog);

extern const char *ANTI_DEBUG_CODE_PTR;
extern const char *ANTI_FRIDA_CODE_PTR;
extern const char *ANTI_HOOK_CODE_PTR;
extern const char *ANTI_INLINE_HOOK_CODE_PTR;
extern const char *ANTI_PLT_HOOK_CODE_PTR;
extern const char *ANTI_SYSCALL_HOOK_CODE_PTR;
extern const char *ANTI_MEM_INTEGRITY_CODE_PTR;

} /* namespace protect */

#endif
