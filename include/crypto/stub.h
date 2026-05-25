#ifndef CRYPTO_STUB_H
#define CRYPTO_STUB_H

static const char STUB_TEMPLATE[] = R"raw(#!/usr/bin/env python3
import hashlib as _h, hmac as _m, base64 as _b, sys as _s, zlib as _z

_P = """__PAYLOAD__"""
_A = __ALGO__

def _():
__ANTI_CODE__
    _k = bytes.fromhex("__KEY_OBS__")
    if _k:
        _k = bytes(_ ^ 0x55 for _ in _k).decode()
    _r = _b.b64decode(_P)
    if _A <= 3:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _c, algorithms as _a, modes as _d
        except ImportError:
            _s.stderr.write("error: cryptography not installed\n"); _s.exit(1)
    if _A == 0:
        ...
        _0 = _r[:16]; _2 = _r[-32:]; _1 = _r[16:-32]
        _3 = _h.pbkdf2_hmac('sha256', _k.encode(), _0, 100000, dklen=64)
        _4 = _3[:32]; _6 = _3[32:64]
        _7 = _m.new(_6, _1, _h.sha256).digest()
        if not _m.compare_digest(_2, _7):
            _s.stderr.write("error: integrity check failed\n"); _s.exit(1)
        _8 = _c(_a.AES(_4), _d.ECB())
        _9 = _8.decryptor()
        _10 = _9.update(_1) + _9.finalize()
        _11 = _10[-1]
        if _11 < 1 or _11 > 16 or not all(_ == _11 for _ in _10[-_11:]):
            _s.stderr.write("error: decryption failed\n"); _s.exit(1)
        _10 = _10[:-_11]
    elif _A == 1:
        _0 = _r[:16]; _2 = _r[-32:]; _1 = _r[16:-32]
        _3 = _h.pbkdf2_hmac('sha256', _k.encode(), _0, 100000, dklen=80)
        _4 = _3[:32]; _5 = _3[32:48]; _6 = _3[48:80]
        _7 = _m.new(_6, _1, _h.sha256).digest()
        if not _m.compare_digest(_2, _7):
            _s.stderr.write("error: integrity check failed\n"); _s.exit(1)
        _8 = _c(_a.AES(_4), _d.CBC(_5))
        _9 = _8.decryptor()
        _10 = _9.update(_1) + _9.finalize()
        _11 = _10[-1]
        if _11 < 1 or _11 > 16 or not all(_ == _11 for _ in _10[-_11:]):
            _s.stderr.write("error: decryption failed\n"); _s.exit(1)
        _10 = _10[:-_11]
    elif _A == 2:
        _0 = _r[:16]; _2 = _r[-32:]; _1 = _r[16:-32]
        _3 = _h.pbkdf2_hmac('sha256', _k.encode(), _0, 100000, dklen=80)
        _4 = _3[:32]; _5 = _3[32:48]; _6 = _3[48:80]
        _7 = _m.new(_6, _1, _h.sha256).digest()
        if not _m.compare_digest(_2, _7):
            _s.stderr.write("error: integrity check failed\n"); _s.exit(1)
        _8 = _c(_a.AES(_4), _d.CTR(_5))
        _10 = _8.decryptor().update(_1)
    elif _A == 3:
        _0 = _r[:16]; _2 = _r[-32:]; _9 = _r[16:-32]
        _1 = _9[:-16]; _t = _9[-16:]
        _3 = _h.pbkdf2_hmac('sha256', _k.encode(), _0, 100000, dklen=76)
        _4 = _3[:32]; _5 = _3[32:44]; _6 = _3[44:76]
        _7 = _m.new(_6, _9, _h.sha256).digest()
        if not _m.compare_digest(_2, _7):
            _s.stderr.write("error: integrity check failed\n"); _s.exit(1)
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _ae
        _10 = _ae(_4).decrypt(_5, _1 + _t, None)
    elif _A == 4:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _c, algorithms as _a, modes as _d
        except ImportError:
            _s.stderr.write("error: cryptography not installed\n"); _s.exit(1)
        _0 = _r[:16]; _2 = _r[-32:]; _1 = _r[16:-32]
        _3 = _h.pbkdf2_hmac('sha256', _k.encode(), _0, 100000, dklen=80)
        _4 = _3[:32]; _5 = _3[32:48]; _6 = _3[48:80]
        _7 = _m.new(_6, _1, _h.sha256).digest()
        if not _m.compare_digest(_2, _7):
            _s.stderr.write("error: integrity check failed\n"); _s.exit(1)
        _8 = _c(_a.ChaCha20(_4, _5), mode=None)
        _10 = _8.decryptor().update(_1)
    elif _A == 5:
        _0 = _r[:16]; _2 = _r[-32:]; _1 = _r[16:-32]
        _3 = _h.pbkdf2_hmac('sha256', _k.encode(), _0, 100000, dklen=64)
        _4 = _3[:32]; _6 = _3[32:64]
        _7 = _m.new(_6, _1, _h.sha256).digest()
        if not _m.compare_digest(_2, _7):
            _s.stderr.write("error: integrity check failed\n"); _s.exit(1)
        _10 = bytes(_1[i] ^ _4[i % 32] for i in range(len(_1)))
    elif _A == 6:
        _10 = _b.b64decode(_r)
    elif _A == 7:
        _10 = _b.b32decode(_r)
    elif _A == 8:
        _85t = ('0','1','2','3','4','5','6','7','8','9',
                'A','B','C','D','E','F','G','H','I','J','K','L','M',
                'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
                'a','b','c','d','e','f','g','h','i','j','k','l','m',
                'n','o','p','q','r','s','t','u','v','w','x','y','z',
                '!','#','$','%','&','(',')','*','+','-',';','<','=',
                '>','?','@','^','_','`','{','|','}','~')
        _85d = {c:i for i,c in enumerate(_85t)}
        def _zd(_b):
            _d = bytearray(); _i = 0
            while _i < len(_b):
                _n = 0; _cnt = 0
                while _i < len(_b) and _cnt < 5:
                    _n = _n * 85 + _85d[chr(_b[_i])]; _i += 1; _cnt += 1
                _nb = _cnt - 1
                if _nb > 0: _d.extend(_n.to_bytes(4, 'big')[4-_nb:])
            return bytes(_d)
        _10 = _zd(_r)
    elif _A == 9:
        def _ad(_b):
            if _b[:2] == b'<~': _b = _b[2:]
            if _b[-2:] == b'~>': _b = _b[:-2]
            _d = bytearray(); _i = 0
            while _i < len(_b):
                if _b[_i] == 122:
                    _d.extend(b'\x00\x00\x00\x00'); _i += 1; continue
                _n = 0; _cnt = 0
                while _i < len(_b) and _cnt < 5:
                    _n = _n * 85 + (_b[_i] - 33); _i += 1; _cnt += 1
                _nb = _cnt - 1
                if _nb > 0: _d.extend(_n.to_bytes(4, 'big')[4-_nb:])
            return bytes(_d)
        _10 = _ad(_r)
    elif _A == 10:
        _10 = bytes.fromhex(_r.decode('ascii'))
    else:
        _s.stderr.write("error: unsupported algorithm\n"); _s.exit(1)
    if _10[1] & 1:
        _10 = _z.decompress(_10[4:])
    else:
        _10 = _10[4:]
    exec(compile(_10, '<protected>', 'exec'), globals())

if __name__ == '__main__':
    _()
)raw";

#endif
