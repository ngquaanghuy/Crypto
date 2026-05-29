#!/usr/bin/env python3
def _njnvh(_bpt):
    return _bpt % 3282 + 1

import hashlib as _szry, hmac as _miy, base64 as _tjc, sys as _wmuppxn, zlib as _bbki
_bpt = 223779
_ywvh = """zWcxWOCJEjBrSmayFcWdCLDBxIWs2omVChKw2zsaj6iqJfn3I63rn6xvTPho34/SG+ntyocNWrO8K0Za9cpy7S2D2bxyllFO34UhPbY+hmC3lfYyX+ATGRZmMK+4KibDqLvvGVyEekUuBNyDzFnxjE5kMJus846/6erLOMCRQ0lrvi/e1GZcMsZrx3IgzlabmyL9HLwaaA62tQRX6zjD8DuztUQNPIg4El5KmlhAV5yIdih2g+ZdadAnl2NeTMYPDYkKFdgfQhRp/jVl74ht3s5MaZ9jy8adPVaSh6Ea4Rw7wDAh7Qyrxq2vNuXmvZuqPnrGy257nykKhxkIpZSYRCJrD3ziCLf/V4iB14S9yitutiqexIl5sEiKf0a5u4k4zx7E0WGeEzK8XyHE9xDogJuLJk7JMYihL+1C7mZxYTINCEhVPeeTRvaXtHB70T/xErViyRgILbw6PpeMimadbOjFMENh2XkQ+HQ+iujEfQO2Nu4oo8tQtGMllw=="""
_niy = 3
_djqml = _njnvh(_bpt)
def _zhuf():
    _hkwg = bytes.fromhex("d1c7c1d0c7d6")
    _hkwg = bytes(_ ^ 162 for _ in _hkwg).decode()
    _srylnki = _tjc.b64decode(_ywvh)
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher as _lcs, algorithms as _jfhr, modes as _qpssszv
    except ImportError:
        _wmuppxn.stderr.write("error: cryptography not installed\n"); _wmuppxn.exit(1)

    if _niy == 7:
        _tmtqg = _tjc.b32decode(_srylnki)
    elif _niy == 2:
        _vsvn = _srylnki[:16]; _jxorhm = _srylnki[-32:]; _rkzy = _srylnki[16:-32]
        _deqbsfl = _szry.pbkdf2_hmac('sha256', _hkwg.encode(), _vsvn, 100000, dklen=80)
        _knjeut = _deqbsfl[:32]; _moodiae = _deqbsfl[32:48]; _aodq = _deqbsfl[48:80]
        _ndgqhyt = _miy.new(_aodq, _rkzy, _szry.sha256).digest()
        if not _miy.compare_digest(_jxorhm, _ndgqhyt):
            _wmuppxn.stderr.write("error: integrity check failed\n"); _wmuppxn.exit(1)
        _dgb = _lcs(_jfhr.AES(_knjeut), _qpssszv.CTR(_moodiae))
        _tmtqg = _dgb.decryptor().update(_rkzy)
    elif _niy == 11:
        _vsvn = _srylnki[:16]; _jxorhm = _srylnki[-32:]; _rkzy = _srylnki[16:-32]
        _deqbsfl = _szry.pbkdf2_hmac('sha256', _hkwg.encode(), _vsvn, 100000, dklen=64)
        _knjeut = _deqbsfl[:32]; _aodq = _deqbsfl[32:64]
        _ndgqhyt = _miy.new(_aodq, _rkzy, _szry.sha256).digest()
        if not _miy.compare_digest(_jxorhm, _ndgqhyt):
            _wmuppxn.stderr.write("error: integrity check failed\n"); _wmuppxn.exit(1)
        _cwkh = _knjeut[0]
        _tmtqg = bytearray()
        for _uidkoa in range(len(_rkzy)):
            _vsvn = _rkzy[_uidkoa] ^ _cwkh
            _tmtqg.append(_vsvn)
            _cwkh = _rkzy[_uidkoa] ^ _knjeut[ (_uidkoa + 1) % len(_knjeut) ]
            _cwkh = (((_cwkh << 3) & 0xFF) | (_cwkh >> 5)) ^ 0x5A
        _tmtqg = bytes(_tmtqg)
    elif _niy == 5:
        _vsvn = _srylnki[:16]; _jxorhm = _srylnki[-32:]; _rkzy = _srylnki[16:-32]
        _deqbsfl = _szry.pbkdf2_hmac('sha256', _hkwg.encode(), _vsvn, 100000, dklen=64)
        _knjeut = _deqbsfl[:32]; _aodq = _deqbsfl[32:64]
        _ndgqhyt = _miy.new(_aodq, _rkzy, _szry.sha256).digest()
        if not _miy.compare_digest(_jxorhm, _ndgqhyt):
            _wmuppxn.stderr.write("error: integrity check failed\n"); _wmuppxn.exit(1)
        _tmtqg = bytes(_rkzy[i] ^ _knjeut[i % 32] for i in range(len(_rkzy)))
    elif _niy == 0:
        _vsvn = _srylnki[:16]; _jxorhm = _srylnki[-32:]; _rkzy = _srylnki[16:-32]
        _deqbsfl = _szry.pbkdf2_hmac('sha256', _hkwg.encode(), _vsvn, 100000, dklen=64)
        _knjeut = _deqbsfl[:32]; _aodq = _deqbsfl[32:64]
        _ndgqhyt = _miy.new(_aodq, _rkzy, _szry.sha256).digest()
        if not _miy.compare_digest(_jxorhm, _ndgqhyt):
            _wmuppxn.stderr.write("error: integrity check failed\n"); _wmuppxn.exit(1)
        _dgb = _lcs(_jfhr.AES(_knjeut), _qpssszv.ECB())
        _tmtqg = _dgb.decryptor()
        _tmtqg = _tmtqg.update(_rkzy) + _tmtqg.finalize()
        _cwkh = _tmtqg[-1]
        if _cwkh < 1 or _cwkh > 16 or not all(_ == _cwkh for _ in _tmtqg[-_cwkh:]):
            _wmuppxn.stderr.write("error: decryption failed\n"); _wmuppxn.exit(1)
        _tmtqg = _tmtqg[:-_cwkh]
    elif _niy == 9:
        def _elygbr(_bkaaool):
            if _bkaaool[:2] == b'<~': _bkaaool = _bkaaool[2:]
            if _bkaaool[-2:] == b'~>': _bkaaool = _bkaaool[:-2]
            _cmz = bytearray(); _kh = 0
            while _kh < len(_bkaaool):
                if _bkaaool[_kh] == 122:
                    _cmz.extend(b'\x00\x00\x00\x00'); _kh += 1; continue
                _wxxolvl = 0; _prx = 0
                while _kh < len(_bkaaool) and _prx < 5:
                    _wxxolvl = _wxxolvl * 85 + (_bkaaool[_kh] - 33); _kh += 1; _prx += 1
                _yye = _prx - 1
                if _yye > 0: _cmz.extend(_wxxolvl.to_bytes(4, 'big')[4-_yye:])
            return bytes(_cmz)
        _tmtqg = _elygbr(_srylnki)
    elif _niy == 6:
        _tmtqg = _tjc.b64decode(_srylnki)
    elif _niy == 8:
        _mkwtxkg = ('0','1','2','3','4','5','6','7','8','9',
                'A','B','C','D','E','F','G','H','I','J','K','L','M',
                'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
                'a','b','c','d','e','f','g','h','i','j','k','l','m',
                'n','o','p','q','r','s','t','u','v','w','x','y','z',
                '!','#','$','%','&','(',')','*','+','-',';','<','=',
                '>','?','@','^','_','`','{','|','}','~')
        _oypxgwo = {c:i for i,c in enumerate(_mkwtxkg)}
        def _ofy(_yxci):
            _kneantm = bytearray(); _rfxenk = 0
            while _rfxenk < len(_yxci):
                _mzsuxi = 0; _moz = 0
                while _rfxenk < len(_yxci) and _moz < 5:
                    _mzsuxi = _mzsuxi * 85 + _oypxgwo[chr(_yxci[_rfxenk])]; _rfxenk += 1; _moz += 1
                _oyuy = _moz - 1
                if _oyuy > 0: _kneantm.extend(_mzsuxi.to_bytes(4, 'big')[4-_oyuy:])
            return bytes(_kneantm)
        _tmtqg = _ofy(_srylnki)
    elif _niy == 3:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _lo
        _vsvn = _srylnki[:16]; _jxorhm = _srylnki[-32:]; _tmtqg = _srylnki[16:-32]
        _rkzy = _tmtqg[:-16]; _cwkh = _tmtqg[-16:]
        _deqbsfl = _szry.pbkdf2_hmac('sha256', _hkwg.encode(), _vsvn, 100000, dklen=76)
        _knjeut = _deqbsfl[:32]; _moodiae = _deqbsfl[32:44]; _aodq = _deqbsfl[44:76]
        _ndgqhyt = _miy.new(_aodq, _tmtqg, _szry.sha256).digest()
        if not _miy.compare_digest(_jxorhm, _ndgqhyt):
            _wmuppxn.stderr.write("error: integrity check failed\n"); _wmuppxn.exit(1)
        _tmtqg = _lo(_knjeut).decrypt(_moodiae, _rkzy + _cwkh, None)
    elif _niy == 4:
        _vsvn = _srylnki[:16]; _jxorhm = _srylnki[-32:]; _rkzy = _srylnki[16:-32]
        _deqbsfl = _szry.pbkdf2_hmac('sha256', _hkwg.encode(), _vsvn, 100000, dklen=80)
        _knjeut = _deqbsfl[:32]; _moodiae = _deqbsfl[32:48]; _aodq = _deqbsfl[48:80]
        _ndgqhyt = _miy.new(_aodq, _rkzy, _szry.sha256).digest()
        if not _miy.compare_digest(_jxorhm, _ndgqhyt):
            _wmuppxn.stderr.write("error: integrity check failed\n"); _wmuppxn.exit(1)
        _dgb = _lcs(_jfhr.ChaCha20(_knjeut, _moodiae), mode=None)
        _tmtqg = _dgb.decryptor().update(_rkzy)
    elif _niy == 1:
        _vsvn = _srylnki[:16]; _jxorhm = _srylnki[-32:]; _rkzy = _srylnki[16:-32]
        _deqbsfl = _szry.pbkdf2_hmac('sha256', _hkwg.encode(), _vsvn, 100000, dklen=80)
        _knjeut = _deqbsfl[:32]; _moodiae = _deqbsfl[32:48]; _aodq = _deqbsfl[48:80]
        _ndgqhyt = _miy.new(_aodq, _rkzy, _szry.sha256).digest()
        if not _miy.compare_digest(_jxorhm, _ndgqhyt):
            _wmuppxn.stderr.write("error: integrity check failed\n"); _wmuppxn.exit(1)
        _dgb = _lcs(_jfhr.AES(_knjeut), _qpssszv.CBC(_moodiae))
        _tmtqg = _dgb.decryptor()
        _tmtqg = _tmtqg.update(_rkzy) + _tmtqg.finalize()
        _cwkh = _tmtqg[-1]
        if _cwkh < 1 or _cwkh > 16 or not all(_ == _cwkh for _ in _tmtqg[-_cwkh:]):
            _wmuppxn.stderr.write("error: decryption failed\n"); _wmuppxn.exit(1)
        _tmtqg = _tmtqg[:-_cwkh]
    elif _niy == 10:
        _tmtqg = bytes.fromhex(_srylnki.decode('ascii'))
    else:
        _wmuppxn.stderr.write("error: unsupported algorithm\n"); _wmuppxn.exit(1)
    if _tmtqg[1] == 1:
        import zlib as _bbki
        _tmtqg = _bbki.decompress(_tmtqg[4:])
    elif _tmtqg[1] == 2:
        import lzma as _bbki
        _tmtqg = _bbki.decompress(_tmtqg[4:])
    elif _tmtqg[1] == 3:
        import bz2 as _bbki
        _tmtqg = _bbki.decompress(_tmtqg[4:])
    elif _tmtqg[1] == 4:
        import brotli as _bbki
        _tmtqg = _bbki.decompress(_tmtqg[4:])
    elif _tmtqg[1] == 5:
        import zstandard as _bbki
        _tmtqg = _bbki.decompress(_tmtqg[4:])
    elif _tmtqg[1] == 6:
        import gzip as _bbki
        _tmtqg = _bbki.decompress(_tmtqg[4:])
    elif _tmtqg[1] == 7:
        import lz4.frame as _bbki
        _tmtqg = _bbki.decompress(_tmtqg[4:])
    elif _tmtqg[1] == 8:
        import snappy as _bbki
        _tmtqg = _bbki.decompress(_tmtqg[4:])
    elif _tmtqg[1] == 9:
        import gzip as _bbki
        _tmtqg = _bbki.decompress(_tmtqg[4:])
    elif _tmtqg[1] == 10:
        import blosc as _bbki
        _tmtqg = _bbki.decompress(_tmtqg[4:])
    else:
        _tmtqg = _tmtqg[4:]
    exec(compile(_tmtqg, '<protected>', 'exec'), globals())

if __name__ == '__main__':
    _zhuf()
