#include "crypto/obfuscate.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <algorithm>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>

/* ── HMAC-based key derivation (HKDF-expand style) ── */
ExitCode xorgen_derive_keys(const unsigned char *master_key, size_t master_len,
                            const unsigned char *salt, size_t salt_len,
                            unsigned char *out_enc_key, size_t enc_key_len,
                            unsigned char *out_hmac_key, size_t hmac_key_len) {
    if (!master_key || master_len == 0) return EXIT_ERR_ARGS;

    /* HKDF extract: PRK = HMAC-SHA256(salt, master_key) */
    unsigned char prk[32];
    unsigned int prk_len = 32;
    HMAC(EVP_sha256(), salt, (int)salt_len,
         master_key, (int)master_len, prk, &prk_len);

    /* HKDF expand (RFC 5869) with empty info:
     * T(1) = HMAC(PRK, 0x01)
     * T(2) = HMAC(PRK, T(1) || 0x02)
     * Output = T(1) || T(2)  (64 bytes total)
     */
    unsigned char derived[64];
    unsigned char t1[32];
    unsigned int tlen = 32;

    /* T(1) = HMAC(PRK, 0x01) */
    unsigned char one = 1;
    HMAC(EVP_sha256(), prk, 32, &one, 1, t1, &tlen);
    memcpy(derived, t1, 32);

    /* T(2) = HMAC(PRK, T(1) || 0x02) */
    unsigned char input[33];
    memcpy(input, t1, 32);
    input[32] = 2;
    HMAC(EVP_sha256(), prk, 32, input, 33, t1, &tlen);
    memcpy(derived + 32, t1, 32);

    size_t to_copy = enc_key_len < 32 ? enc_key_len : 32;
    memcpy(out_enc_key, derived, to_copy);

    to_copy = hmac_key_len < 32 ? hmac_key_len : 32;
    memcpy(out_hmac_key, derived + 32, to_copy);

    return EXIT_OK;
}

/* ── ChaCha20 encryption + HMAC integrity tag ── */
ExitCode xorgen_chacha20_encrypt(const unsigned char *plain, size_t plain_len,
                                 const unsigned char *key, size_t key_len,
                                 unsigned char **out, size_t *out_len) {
    if (!plain || !out || plain_len == 0) return EXIT_ERR_INTERNAL;

    unsigned char salt[OBFUSCATE_SALT_SIZE];
    unsigned char nonce[OBFUSCATE_NONCE_SIZE];
    if (RAND_bytes(salt, OBFUSCATE_SALT_SIZE) != 1) return EXIT_ERR_CRYPTO;
    if (RAND_bytes(nonce, OBFUSCATE_NONCE_SIZE) != 1) return EXIT_ERR_CRYPTO;

    unsigned char enc_key[OBFUSCATE_CHACHA20_KEY_SIZE];
    unsigned char hmac_key[OBFUSCATE_HMAC_KEY_SIZE];
    ExitCode ret = xorgen_derive_keys(key, key_len, salt, OBFUSCATE_SALT_SIZE,
                                      enc_key, OBFUSCATE_CHACHA20_KEY_SIZE,
                                      hmac_key, OBFUSCATE_HMAC_KEY_SIZE);
    if (ret != EXIT_OK) return ret;

    /* ChaCha20 via OpenSSL. EVP_chacha20() takes a 16-byte IV:
     *   IV[0..3] = initial block counter (set to 0 for IETF compat)
     *   IV[4..15] = 12-byte nonce
     */
    unsigned char iv[16];
    memset(iv, 0, 4);           /* initial counter = 0 */
    memcpy(iv + 4, nonce, 12);  /* 12-byte nonce */

    size_t ciphertext_len = plain_len;
    unsigned char *ciphertext = (unsigned char *)malloc(ciphertext_len);
    if (!ciphertext) return EXIT_ERR_CRYPTO;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { free(ciphertext); return EXIT_ERR_CRYPTO; }

    int len = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, enc_key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx); free(ciphertext);
        return EXIT_ERR_CRYPTO;
    }
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plain, (int)plain_len) != 1) {
        EVP_CIPHER_CTX_free(ctx); free(ciphertext);
        return EXIT_ERR_CRYPTO;
    }
    ciphertext_len = (size_t)len;
    EVP_CIPHER_CTX_free(ctx);

    /* HMAC integrity tag over salt || nonce || ciphertext */
    size_t tag_input_len = OBFUSCATE_SALT_SIZE + OBFUSCATE_NONCE_SIZE + ciphertext_len;
    unsigned char *tag_input = (unsigned char *)malloc(tag_input_len);
    if (!tag_input) { free(ciphertext); return EXIT_ERR_CRYPTO; }

    memcpy(tag_input, salt, OBFUSCATE_SALT_SIZE);
    memcpy(tag_input + OBFUSCATE_SALT_SIZE, nonce, OBFUSCATE_NONCE_SIZE);
    memcpy(tag_input + OBFUSCATE_SALT_SIZE + OBFUSCATE_NONCE_SIZE,
           ciphertext, ciphertext_len);

    unsigned char tag[OBFUSCATE_TAG_SIZE];
    unsigned int tag_len = OBFUSCATE_TAG_SIZE;
    HMAC(EVP_sha256(), hmac_key, OBFUSCATE_HMAC_KEY_SIZE,
         tag_input, tag_input_len, tag, &tag_len);
    free(tag_input);

    /* Output: [salt(16)][nonce(12)][ciphertext][tag(16)] */
    *out_len = OBFUSCATE_SALT_SIZE + OBFUSCATE_NONCE_SIZE + ciphertext_len + OBFUSCATE_TAG_SIZE;
    *out = (unsigned char *)malloc(*out_len);
    if (!*out) { free(ciphertext); return EXIT_ERR_CRYPTO; }

    memcpy(*out, salt, OBFUSCATE_SALT_SIZE);
    memcpy(*out + OBFUSCATE_SALT_SIZE, nonce, OBFUSCATE_NONCE_SIZE);
    memcpy(*out + OBFUSCATE_SALT_SIZE + OBFUSCATE_NONCE_SIZE,
           ciphertext, ciphertext_len);
    memcpy(*out + OBFUSCATE_SALT_SIZE + OBFUSCATE_NONCE_SIZE + ciphertext_len,
           tag, OBFUSCATE_TAG_SIZE);

    free(ciphertext);
    return EXIT_OK;
}

/* ── ChaCha20 decryption + integrity verification ── */
ExitCode xorgen_chacha20_decrypt(const unsigned char *in, size_t in_len,
                                 const unsigned char *key, size_t key_len,
                                 unsigned char **out, size_t *out_len) {
    if (!in || !out) return EXIT_ERR_INTERNAL;

    size_t min_len = OBFUSCATE_SALT_SIZE + OBFUSCATE_NONCE_SIZE + OBFUSCATE_TAG_SIZE;
    if (in_len <= min_len) return EXIT_ERR_CRYPTO;

    const unsigned char *salt       = in;
    const unsigned char *nonce      = in + OBFUSCATE_SALT_SIZE;
    const unsigned char *ciphertext = in + OBFUSCATE_SALT_SIZE + OBFUSCATE_NONCE_SIZE;
    size_t ciphertext_len = in_len - OBFUSCATE_SALT_SIZE - OBFUSCATE_NONCE_SIZE - OBFUSCATE_TAG_SIZE;
    const unsigned char *stored_tag = in + in_len - OBFUSCATE_TAG_SIZE;

    unsigned char enc_key[OBFUSCATE_CHACHA20_KEY_SIZE];
    unsigned char hmac_key[OBFUSCATE_HMAC_KEY_SIZE];
    ExitCode ret = xorgen_derive_keys(key, key_len, salt, OBFUSCATE_SALT_SIZE,
                                      enc_key, OBFUSCATE_CHACHA20_KEY_SIZE,
                                      hmac_key, OBFUSCATE_HMAC_KEY_SIZE);
    if (ret != EXIT_OK) return ret;

    /* Verify HMAC tag */
    size_t tag_input_len = OBFUSCATE_SALT_SIZE + OBFUSCATE_NONCE_SIZE + ciphertext_len;
    unsigned char *tag_input = (unsigned char *)malloc(tag_input_len);
    if (!tag_input) return EXIT_ERR_CRYPTO;

    memcpy(tag_input, salt, OBFUSCATE_SALT_SIZE);
    memcpy(tag_input + OBFUSCATE_SALT_SIZE, nonce, OBFUSCATE_NONCE_SIZE);
    memcpy(tag_input + OBFUSCATE_SALT_SIZE + OBFUSCATE_NONCE_SIZE,
           ciphertext, ciphertext_len);

    unsigned char computed_tag[OBFUSCATE_TAG_SIZE];
    unsigned int computed_tag_len = OBFUSCATE_TAG_SIZE;
    HMAC(EVP_sha256(), hmac_key, OBFUSCATE_HMAC_KEY_SIZE,
         tag_input, tag_input_len, computed_tag, &computed_tag_len);
    free(tag_input);

    if (computed_tag_len != OBFUSCATE_TAG_SIZE ||
        CRYPTO_memcmp(computed_tag, stored_tag, OBFUSCATE_TAG_SIZE) != 0) {
        return EXIT_ERR_CRYPTO;
    }

    /* Decrypt */
    *out_len = ciphertext_len;
    *out = (unsigned char *)malloc(ciphertext_len);
    if (!*out) return EXIT_ERR_CRYPTO;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { free(*out); *out = nullptr; return EXIT_ERR_CRYPTO; }

    unsigned char iv[16];
    memset(iv, 0, 4);
    memcpy(iv + 4, nonce, 12);

    int len;
    if (EVP_DecryptInit_ex(ctx, EVP_chacha20(), NULL, enc_key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx); free(*out); *out = nullptr;
        return EXIT_ERR_CRYPTO;
    }
    if (EVP_DecryptUpdate(ctx, *out, &len, ciphertext, (int)ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx); free(*out); *out = nullptr;
        return EXIT_ERR_CRYPTO;
    }
    EVP_CIPHER_CTX_free(ctx);

    return EXIT_OK;
}

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

    /* Base64 encode the encrypted payload */
    std::string b64;
    b64.reserve((encrypted_len / 3 + 1) * 4 + 16);
    /* Simple base64 encode inline */
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

    /* Key as hex */
    char key_hex[65];
    for (size_t i = 0; i < key_len && i < 32; i++)
        snprintf(key_hex + i * 2, 3, "%02x", key[i]);
    key_hex[64] = '\0';

    /* Generate Python stub with random names */
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

    /* ChaCha20 block function */
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

    /* HKDF derive + ChaCha20 decrypt + HMAC verify */
    py += "def _DEC(data, key):\n";
    py += "    salt = data[:16]\n";
    py += "    nonce = data[16:28]\n";
    py += "    ct = data[28:-16]\n";
    py += "    tag = data[-16:]\n";
    py += "    prk = _M.new(salt, key, _H.sha256).digest()\n";
    py += "    t1 = _M.new(prk, b'\\x01', _H.sha256).digest()\n";
    py += "    ek = t1\n";
    py += "    hk_input = bytearray(t1)\n";
    py += "    hk_input.append(2)\n";
    py += "    hk = _M.new(prk, bytes(hk_input), _H.sha256).digest()\n";
    py += "    expected = _M.new(hk, salt+nonce+ct, _H.sha256).digest()[:16]\n";
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

    /* Generate multi-pass XOR encryption */
    unsigned char rnd[1];
    RAND_bytes(rnd, 1);
    int num_passes = 3 + (rnd[0] % 6); /* 3-8 passes */

    /* Key as hex */
    char key_hex[65];
    for (size_t i = 0; i < key_len && i < 32; i++)
        snprintf(key_hex + i * 2, 3, "%02x", key[i]);
    key_hex[64] = '\0';

    /* Encrypt: multi-pass XOR + rotation */
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

    /* Base64 encode */
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

    /* Generate Python stub */
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