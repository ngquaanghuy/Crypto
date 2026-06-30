#include "cli/protect_internal.h"
#include "encode/xorcode.h"
#include "encode/base64.h"
#include <openssl/rand.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <format>
#include <string>
#include <string_view>

namespace protect {

int has_tech(const char *techs, const char *target) {
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

ExitCode apply_rolling_xor_obfuscation(const char *src, size_t src_len, Buffer *out) {
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

ExitCode apply_xor_bit_rotation_obfuscation(const char *src, size_t src_len, Buffer *out) {
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

int rand_csprng_range(int lo, int hi) {
    unsigned char b;
    RAND_bytes(&b, 1);
    return lo + (b % ((unsigned int)hi - lo + 1));
}

int rand_range(int lo, int hi) {
    return lo + rand() % (hi - lo + 1);
}

std::string rand_name() {
    int len = rand_range(6, 10);
    std::string r;
    r += '_';
    for (int i = 1; i < len; i++)
        r += static_cast<char>('a' + rand() % 26);
    return r;
}

std::string patch_sys_name(std::string_view code, std::string_view sys_name) {
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

} /* namespace protect */
