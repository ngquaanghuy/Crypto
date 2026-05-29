#!/usr/bin/env python3
def _qwfuv(_yya):
    return _yya % 9133 + 1

import hashlib as _yxc, hmac as _xcwq, base64 as _dhr, sys as _jajpq, zlib as _gkuoi
_yya = 319729
_ozwkvl = """auNGSviYRAMgaFW3qq4XoHNnJQzKkkYksRWo5Ta3FKnzI2Gw3A1B3AtFLk5gn9VZKl4J1MIX3zlAczo9G6FbLy2nZlkwXjRY08MGS1QRMSp993YI7QmyY0/fRGmNwXtNZr0Gs59Mn42JNTTw6ZC/aFYgFyd+T95tL8Pe+IHQKgLDosumtpnDbyk2cjGvUfiz6IwVOj5ksRBKvSiaQNT3KfK93ETxUxcNX4xn5lY7kPrdobXfHJnNJC02FmmTL8eK+dqkQFB/RG8e/8Dgmzwas4Fm4FWlTGzTzf8lVZ9scH/wjOLe5PaaW5kG4/BO6pxn8L1dO+qY408kIIGHVrxq3QhtrlQHBIIPC41vXyxoOzhuKaBtTodk/N0iO1KGTc606RwuirF5O13DH0Ra7ofkCxkkaAsa7Cjlv2kqKqJtfBoKqOgFnF1wg9ifdKfXFfEBYoWlgcZiP4OJfr7tikvRCXp7L6OOEoN10ZggoGJYwT5pWzzoddwCF9E/o6mW5RRYOg=="""
_snl = 3
_fxwg = _qwfuv(_yya)
def _ktpuj():
    _shipnrg = bytes.fromhex("f1e7e1f0e7f6dde9e7fb")
    _shipnrg = bytes(_ ^ 130 for _ in _shipnrg).decode()
    _bizsaz = _dhr.b64decode(_ozwkvl)
    if _snl == 4:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _mz, algorithms as _njvvitd, modes as _ec
        except ImportError:
            _jajpq.stderr.write("error: cryptography not installed\n"); _jajpq.exit(1)
        _wfotqzn = _bizsaz[:16]; _oo = _bizsaz[-32:]; _mez = _bizsaz[16:-32]
        _gwz = _yxc.pbkdf2_hmac('sha256', _shipnrg.encode(), _wfotqzn, 100000, dklen=80)
        _ebb = _gwz[:32]; _aartpoc = _gwz[32:48]; _kjjdbis = _gwz[48:80]
        _wwislw = _xcwq.new(_kjjdbis, _mez, _yxc.sha256).digest()
        if not _xcwq.compare_digest(_oo, _wwislw):
            _jajpq.stderr.write("error: integrity check failed\n"); _jajpq.exit(1)
        _tvb = _mz(_njvvitd.ChaCha20(_ebb, _aartpoc), mode=None)
        _zc = _tvb.decryptor().update(_mez)
    elif _snl == 3:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _obq
        except ImportError:
            _jajpq.stderr.write("error: cryptography not installed\n"); _jajpq.exit(1)
        _wfotqzn = _bizsaz[:16]; _oo = _bizsaz[-32:]; _zc = _bizsaz[16:-32]
        _mez = _zc[:-16]; _geeyz = _zc[-16:]
        _gwz = _yxc.pbkdf2_hmac('sha256', _shipnrg.encode(), _wfotqzn, 100000, dklen=76)
        _ebb = _gwz[:32]; _aartpoc = _gwz[32:44]; _kjjdbis = _gwz[44:76]
        _wwislw = _xcwq.new(_kjjdbis, _zc, _yxc.sha256).digest()
        if not _xcwq.compare_digest(_oo, _wwislw):
            _jajpq.stderr.write("error: integrity check failed\n"); _jajpq.exit(1)
        _zc = _obq(_ebb).decrypt(_aartpoc, _mez + _geeyz, None)
    elif _snl == 0:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _mz, algorithms as _njvvitd, modes as _ec
        except ImportError:
            _jajpq.stderr.write("error: cryptography not installed\n"); _jajpq.exit(1)
        _wfotqzn = _bizsaz[:16]; _oo = _bizsaz[-32:]; _mez = _bizsaz[16:-32]
        _gwz = _yxc.pbkdf2_hmac('sha256', _shipnrg.encode(), _wfotqzn, 100000, dklen=64)
        _ebb = _gwz[:32]; _kjjdbis = _gwz[32:64]
        _wwislw = _xcwq.new(_kjjdbis, _mez, _yxc.sha256).digest()
        if not _xcwq.compare_digest(_oo, _wwislw):
            _jajpq.stderr.write("error: integrity check failed\n"); _jajpq.exit(1)
        _tvb = _mz(_njvvitd.AES(_ebb), _ec.ECB())
        _zc = _tvb.decryptor()
        _zc = _zc.update(_mez) + _zc.finalize()
        _geeyz = _zc[-1]
        if _geeyz < 1 or _geeyz > 16 or not all(_ == _geeyz for _ in _zc[-_geeyz:]):
            _jajpq.stderr.write("error: decryption failed\n"); _jajpq.exit(1)
        _zc = _zc[:-_geeyz]
    elif _snl == 10:
        _zc = bytes.fromhex(_bizsaz.decode('ascii'))
    elif _snl == 5:
        _wfotqzn = _bizsaz[:16]; _oo = _bizsaz[-32:]; _mez = _bizsaz[16:-32]
        _gwz = _yxc.pbkdf2_hmac('sha256', _shipnrg.encode(), _wfotqzn, 100000, dklen=64)
        _ebb = _gwz[:32]; _kjjdbis = _gwz[32:64]
        _wwislw = _xcwq.new(_kjjdbis, _mez, _yxc.sha256).digest()
        if not _xcwq.compare_digest(_oo, _wwislw):
            _jajpq.stderr.write("error: integrity check failed\n"); _jajpq.exit(1)
        _zc = bytes(_mez[i] ^ _ebb[i % 32] for i in range(len(_mez)))
    elif _snl == 11:
        _wfotqzn = _bizsaz[:16]; _oo = _bizsaz[-32:]; _mez = _bizsaz[16:-32]
        _gwz = _yxc.pbkdf2_hmac('sha256', _shipnrg.encode(), _wfotqzn, 100000, dklen=64)
        _ebb = _gwz[:32]; _kjjdbis = _gwz[32:64]
        _wwislw = _xcwq.new(_kjjdbis, _mez, _yxc.sha256).digest()
        if not _xcwq.compare_digest(_oo, _wwislw):
            _jajpq.stderr.write("error: integrity check failed\n"); _jajpq.exit(1)
        _geeyz = _ebb[0]
        _zc = bytearray()
        for _zx in range(len(_mez)):
            _wfotqzn = _mez[_zx] ^ _geeyz
            _zc.append(_wfotqzn)
            _geeyz = _mez[_zx] ^ _ebb[ (_zx + 1) % len(_ebb) ]
            _geeyz = (((_geeyz << 3) & 0xFF) | (_geeyz >> 5)) ^ 0x5A
        _zc = bytes(_zc)
    elif _snl == 1:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _mz, algorithms as _njvvitd, modes as _ec
        except ImportError:
            _jajpq.stderr.write("error: cryptography not installed\n"); _jajpq.exit(1)
        _wfotqzn = _bizsaz[:16]; _oo = _bizsaz[-32:]; _mez = _bizsaz[16:-32]
        _gwz = _yxc.pbkdf2_hmac('sha256', _shipnrg.encode(), _wfotqzn, 100000, dklen=80)
        _ebb = _gwz[:32]; _aartpoc = _gwz[32:48]; _kjjdbis = _gwz[48:80]
        _wwislw = _xcwq.new(_kjjdbis, _mez, _yxc.sha256).digest()
        if not _xcwq.compare_digest(_oo, _wwislw):
            _jajpq.stderr.write("error: integrity check failed\n"); _jajpq.exit(1)
        _tvb = _mz(_njvvitd.AES(_ebb), _ec.CBC(_aartpoc))
        _zc = _tvb.decryptor()
        _zc = _zc.update(_mez) + _zc.finalize()
        _geeyz = _zc[-1]
        if _geeyz < 1 or _geeyz > 16 or not all(_ == _geeyz for _ in _zc[-_geeyz:]):
            _jajpq.stderr.write("error: decryption failed\n"); _jajpq.exit(1)
        _zc = _zc[:-_geeyz]
    elif _snl == 9:
        def _tdfyz(_ravwmzs):
            if _ravwmzs[:2] == b'<~': _ravwmzs = _ravwmzs[2:]
            if _ravwmzs[-2:] == b'~>': _ravwmzs = _ravwmzs[:-2]
            _veyju = bytearray(); _wbwb = 0
            while _wbwb < len(_ravwmzs):
                if _ravwmzs[_wbwb] == 122:
                    _veyju.extend(b'\x00\x00\x00\x00'); _wbwb += 1; continue
                _utmn = 0; _zi = 0
                while _wbwb < len(_ravwmzs) and _zi < 5:
                    _utmn = _utmn * 85 + (_ravwmzs[_wbwb] - 33); _wbwb += 1; _zi += 1
                _eglezm = _zi - 1
                if _eglezm > 0: _veyju.extend(_utmn.to_bytes(4, 'big')[4-_eglezm:])
            return bytes(_veyju)
        _zc = _tdfyz(_bizsaz)
    elif _snl == 2:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _mz, algorithms as _njvvitd, modes as _ec
        except ImportError:
            _jajpq.stderr.write("error: cryptography not installed\n"); _jajpq.exit(1)
        _wfotqzn = _bizsaz[:16]; _oo = _bizsaz[-32:]; _mez = _bizsaz[16:-32]
        _gwz = _yxc.pbkdf2_hmac('sha256', _shipnrg.encode(), _wfotqzn, 100000, dklen=80)
        _ebb = _gwz[:32]; _aartpoc = _gwz[32:48]; _kjjdbis = _gwz[48:80]
        _wwislw = _xcwq.new(_kjjdbis, _mez, _yxc.sha256).digest()
        if not _xcwq.compare_digest(_oo, _wwislw):
            _jajpq.stderr.write("error: integrity check failed\n"); _jajpq.exit(1)
        _tvb = _mz(_njvvitd.AES(_ebb), _ec.CTR(_aartpoc))
        _zc = _tvb.decryptor().update(_mez)
    elif _snl == 6:
        _zc = _dhr.b64decode(_bizsaz)
    elif _snl == 8:
        _bwjff = ('0','1','2','3','4','5','6','7','8','9',
                'A','B','C','D','E','F','G','H','I','J','K','L','M',
                'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
                'a','b','c','d','e','f','g','h','i','j','k','l','m',
                'n','o','p','q','r','s','t','u','v','w','x','y','z',
                '!','#','$','%','&','(',')','*','+','-',';','<','=',
                '>','?','@','^','_','`','{','|','}','~')
        _lfogtrx = {c:i for i,c in enumerate(_bwjff)}
        def _dywqktn(_mtutvy):
            _uf = bytearray(); _sqzxfk = 0
            while _sqzxfk < len(_mtutvy):
                _tsvk = 0; _opskhed = 0
                while _sqzxfk < len(_mtutvy) and _opskhed < 5:
                    _tsvk = _tsvk * 85 + _lfogtrx[chr(_mtutvy[_sqzxfk])]; _sqzxfk += 1; _opskhed += 1
                _ysosl = _opskhed - 1
                if _ysosl > 0: _uf.extend(_tsvk.to_bytes(4, 'big')[4-_ysosl:])
            return bytes(_uf)
        _zc = _dywqktn(_bizsaz)
    elif _snl == 7:
        _zc = _dhr.b32decode(_bizsaz)
    else:
        _jajpq.stderr.write("error: unsupported algorithm\n"); _jajpq.exit(1)
    if _zc[1] == 1:
        import zlib as _gkuoi
        _zc = _gkuoi.decompress(_zc[4:])
    elif _zc[1] == 2:
        import lzma as _gkuoi
        _zc = _gkuoi.decompress(_zc[4:])
    elif _zc[1] == 3:
        import bz2 as _gkuoi
        _zc = _gkuoi.decompress(_zc[4:])
    elif _zc[1] == 4:
        import brotli as _gkuoi
        _zc = _gkuoi.decompress(_zc[4:])
    elif _zc[1] == 5:
        import zstandard as _gkuoi
        _zc = _gkuoi.decompress(_zc[4:])
    elif _zc[1] == 6:
        import gzip as _gkuoi
        _zc = _gkuoi.decompress(_zc[4:])
    elif _zc[1] == 7:
        import lz4.frame as _gkuoi
        _zc = _gkuoi.decompress(_zc[4:])
    elif _zc[1] == 8:
        import snappy as _gkuoi
        _zc = _gkuoi.decompress(_zc[4:])
    elif _zc[1] == 9:
        import gzip as _gkuoi
        _zc = _gkuoi.decompress(_zc[4:])
    elif _zc[1] == 10:
        import blosc as _gkuoi
        _zc = _gkuoi.decompress(_zc[4:])
    else:
        _zc = _zc[4:]
    exec(compile(_zc, '<protected>', 'exec'), globals())

if __name__ == '__main__':
    _ktpuj()
