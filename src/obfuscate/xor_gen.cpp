#include "crypto/obfuscate.h"
#include "obfuscate/xor_gen_crypto.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <algorithm>
#include <openssl/rand.h>

/* ── Generate Python ChaCha20+HMAC self-decrypting stub ── */
char *xorgen_generate_python_stub(const unsigned char *plaintext,
                                  size_t plaintext_len,
                                  const unsigned char *key, size_t key_len) {
    unsigned char *encrypted = nullptr;
    size_t encrypted_len = 0;

    ExitCode ret = xorgen_chacha20_encrypt(plaintext, plaintext_len,
                                           key, key_len,
                                           &encrypted, &encrypted_len);
    if (ret != EXIT_OK) return nullptr;

    std::string b64;
    b64.reserve((encrypted_len / 3 + 1) * 4 + 16);
    static const char *b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (size_t i = 0; i < encrypted_len; i += 3) {
        uint32_t triple = 0;
        int remaining = (int)(encrypted_len - i);
        for (int j = 0; j < 3; j++) {
            triple <<= 8;
            if (j < remaining) triple |= encrypted[i + j];
        }
        for (int j = 0; j < 4; j++) {
            if (j > remaining + 1 && remaining < 3)
                b64 += '=';
            else
                b64 += b64chars[(triple >> (18 - j * 6)) & 0x3F];
        }
    }

    free(encrypted);

    char key_hex[65];
    for (size_t i = 0; i < key_len && i < 32; i++)
        snprintf(key_hex + i * 2, 3, "%02x", key[i]);
    key_hex[64] = '\0';

    unsigned char rnd[4];
    RAND_bytes(rnd, sizeof(rnd));
    uint32_t tag = (uint32_t)rnd[0] | ((uint32_t)rnd[1] << 8) |
                   ((uint32_t)rnd[2] << 16) | ((uint32_t)rnd[3] << 24);

    std::string py;
    py.reserve(4096);

    py += "import base64 as _B" + std::to_string(tag & 0xFF) + "\n";
    py += "import hashlib as _H" + std::to_string((tag >> 8) & 0xFF) + "\n";
    py += "import hmac as _M" + std::to_string((tag >> 16) & 0xFF) + "\n";
    py += "import struct as _T" + std::to_string((tag >> 24) & 0xFF) + "\n\n";

    py += "_D = _B" + std::to_string(tag & 0xFF) + ".b64decode('" + b64 + "')\n";
    py += "_K = bytes.fromhex('" + std::string(key_hex) + "')\n\n";

    py += "def _QR(a,b,c,d):\n";
    py += "    a=(a+b)&0xFFFFFFFF;d^=a;d=((d<<16)|(d>>16))&0xFFFFFFFF\n";
    py += "    c=(c+d)&0xFFFFFFFF;b^=c;b=((b<<12)|(b>>20))&0xFFFFFFFF\n";
    py += "    a=(a+b)&0xFFFFFFFF;d^=a;d=((d<<8)|(d>>24))&0xFFFFFFFF\n";
    py += "    c=(c+d)&0xFFFFFFFF;b^=c;b=((b<<7)|(b>>25))&0xFFFFFFFF\n";
    py += "    return a,b,c,d\n\n";

    py += "def _CB(k,c,n):\n";
    py += "    s=[0x61707865,0x3320646e,0x79622d32,0x6b206574]\n";
    py += "    for i in range(0,32,4):s.append(_T.unpack('<I',k[i:i+4])[0])\n";
    py += "    s.append(c&0xFFFFFFFF)\n";
    py += "    for i in range(0,12,4):s.append(_T.unpack('<I',n[i:i+4])[0])\n";
    py += "    w=list(s)\n";
    py += "    for _ in range(10):\n";
    py += "        w[0],w[4],w[8],w[12]=_QR(w[0],w[4],w[8],w[12])\n";
    py += "        w[1],w[5],w[9],w[13]=_QR(w[1],w[5],w[9],w[13])\n";
    py += "        w[2],w[6],w[10],w[14]=_QR(w[2],w[6],w[10],w[14])\n";
    py += "        w[3],w[7],w[11],w[15]=_QR(w[3],w[7],w[11],w[15])\n";
    py += "        w[0],w[5],w[10],w[15]=_QR(w[0],w[5],w[10],w[15])\n";
    py += "        w[1],w[6],w[11],w[12]=_QR(w[1],w[6],w[11],w[12])\n";
    py += "        w[2],w[7],w[8],w[13]=_QR(w[2],w[7],w[8],w[13])\n";
    py += "        w[3],w[4],w[9],w[14]=_QR(w[3],w[4],w[9],w[14])\n";
    py += "    r=bytearray()\n";
    py += "    for i in range(16):r.extend(_T.pack('<I',(s[i]+w[i])&0xFFFFFFFF))\n";
    py += "    return bytes(r)\n\n";

    py += "def _DEC(data, key):\n";
    py += "    salt = data[:16]\n";
    py += "    nonce = data[16:28]\n";
    py += "    ct = data[28:-32]\n";
    py += "    tag = data[-32:]\n";
    py += "    prk = _M.new(salt, key, _H.sha256).digest()\n";
    py += "    t1 = _M.new(prk, b'\\x01', _H.sha256).digest()\n";
    py += "    ek = t1\n";
    py += "    hk_input = bytearray(t1)\n";
    py += "    hk_input.append(2)\n";
    py += "    hk = _M.new(prk, bytes(hk_input), _H.sha256).digest()\n";
    py += "    expected = _M.new(hk, salt+nonce+ct, _H.sha256).digest()[:32]\n";
    py += "    if not _M.compare_digest(tag, expected):\n";
    py += "        raise ValueError('integrity check failed')\n";
    py += "    result = bytearray()\n";
    py += "    counter = 0\n";
    py += "    while len(result) < len(ct):\n";
    py += "        ks = _CB(ek, counter, nonce)\n";
    py += "        for i in range(min(64, len(ct) - len(result))):\n";
    py += "            result.append(ct[len(result)] ^ ks[i])\n";
    py += "        counter += 1\n";
    py += "    return bytes(result)\n\n";

    py += "exec(compile(_DEC(_D, _K), '<x>', 'exec'), globals())\n";

    return strdup(py.c_str());
}

/* ── Generate Python multi-pass XOR self-decrypting stub (no crypto lib) ── */
char *xorgen_generate_xor_stub(const unsigned char *plaintext,
                               size_t plaintext_len,
                               const unsigned char *key, size_t key_len) {
    if (!plaintext || !key) return nullptr;

    unsigned char rnd[1];
    RAND_bytes(rnd, 1);
    int num_passes = 3 + (rnd[0] % 6);

    char key_hex[65];
    for (size_t i = 0; i < key_len && i < 32; i++)
        snprintf(key_hex + i * 2, 3, "%02x", key[i]);
    key_hex[64] = '\0';

    std::vector<unsigned char> encrypted(plaintext, plaintext + plaintext_len);
    for (int p = 0; p < num_passes; p++) {
        int shift = (3 + p) & 7;
        unsigned char const_byte = (unsigned char)((p * 0x1B + 0x5A) & 0xFF);
        for (size_t i = 0; i < encrypted.size(); i++) {
            unsigned char b = encrypted[i];
            b ^= key[(size_t)(p * encrypted.size() + i) % key_len];
            b = (unsigned char)((b << shift) | (b >> (8 - shift)));
            b ^= const_byte;
            encrypted[i] = b;
        }
    }

    std::string b64;
    static const char *b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (size_t i = 0; i < encrypted.size(); i += 3) {
        uint32_t triple = 0;
        int remaining = (int)(encrypted.size() - i);
        for (int j = 0; j < 3; j++) {
            triple <<= 8;
            if (j < remaining) triple |= encrypted[i + j];
        }
        for (int j = 0; j < 4; j++) {
            if (j > remaining + 1 && remaining < 3)
                b64 += '=';
            else
                b64 += b64chars[(triple >> (18 - j * 6)) & 0x3F];
        }
    }

    unsigned char rnd2[4];
    RAND_bytes(rnd2, sizeof(rnd2));
    uint32_t tag = (uint32_t)rnd2[0] | ((uint32_t)rnd2[1] << 8) |
                   ((uint32_t)rnd2[2] << 16) | ((uint32_t)rnd2[3] << 24);

    std::string py;
    py.reserve(2048);

    py += "import base64 as _B\n";
    py += "_D = _B.b64decode('" + b64 + "')\n";
    py += "_K = bytes.fromhex('" + std::string(key_hex) + "')\n";
    py += "_N = " + std::to_string(num_passes) + "\n\n";

    py += "def _MD(d, k, n):\n";
    py += "    r = bytearray(d)\n";
    py += "    for p in range(n - 1, -1, -1):\n";
    py += "        sh = (3 + p) & 7\n";
    py += "        co = (p * 0x1B + 0x5A) & 0xFF\n";
    py += "        for i in range(len(r)):\n";
    py += "            r[i] ^= co\n";
    py += "            r[i] = ((r[i] >> sh) | ((r[i] << (8 - sh)) & 0xFF))\n";
    py += "            r[i] ^= k[(p * len(r) + i) % len(k)]\n";
    py += "    return bytes(r)\n\n";

    py += "exec(compile(_MD(_D, _K, _N), '<x>', 'exec'), globals())\n";

    return strdup(py.c_str());
}
