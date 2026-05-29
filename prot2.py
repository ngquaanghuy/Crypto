#!/usr/bin/env python3
def _mg(_aq):
    return _aq % 3332 + 1

import hashlib as _syuiu, hmac as _oubm, base64 as _cs, sys as _ktollye, zlib as _cmrlmxj
_aq = 558687
_qcykk = """NV+gWR19+Z2itTiP8pDOW/aRHBE4Y0Hnypdgft5hlKo5/vWju07yzh4tgXCxWBD1GWocKMaFlbarsumDzNZFqbhkWGTYFHOQHOurEGa75/aNOBGd+4XWi2yQTEabFz+HVp14jET1H9OES+eL6J72vWCi3YSjdWuhKggQIlSpWB54yXVJMXu0ipkWD5VgB9B0qx2uCINewC0SNsclR3jsLb2HYpE0DMx+f/poECGD637tBgYpgT4vNuY="""
_uamv = 3
_mg = _mg(_aq)

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

def _qpvemg():
    _bagqkz = bytes.fromhex("5d4b4d5c4b5a71454b57")
    _bagqkz = bytes(_ ^ 46 for _ in _bagqkz).decode()
    _xlfby = _cs.b64decode(_qcykk)
    if _uamv == 6:
        _ask = _cs.b64decode(_xlfby)
    elif _uamv == 11:
        _diap = _xlfby[:16]; _jh = _xlfby[-32:]; _uk = _xlfby[16:-32]
        _khra = _syuiu.pbkdf2_hmac('sha256', _bagqkz.encode(), _diap, 100000, dklen=64)
        _qhpdp = _khra[:32]; _rungcp = _khra[32:64]
        _nrahlmg = _oubm.new(_rungcp, _uk, _syuiu.sha256).digest()
        if not _oubm.compare_digest(_jh, _nrahlmg):
            _ktollye.stderr.write("error: integrity check failed\n"); _ktollye.exit(1)
        _hchgl = _qhpdp[0]
        _ask = bytearray()
        for _jcnpj in range(len(_uk)):
            _diap = _uk[_jcnpj] ^ _hchgl
            _ask.append(_diap)
            _hchgl = _uk[_jcnpj] ^ _qhpdp[ (_jcnpj + 1) % len(_qhpdp) ]
            _hchgl = (((_hchgl << 3) & 0xFF) | (_hchgl >> 5)) ^ 0x5A
        _ask = bytes(_ask)
    elif _uamv == 4:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _pssiubt, algorithms as _hqd, modes as _yghh
        except ImportError:
            _ktollye.stderr.write("error: cryptography not installed\n"); _ktollye.exit(1)
        _diap = _xlfby[:16]; _jh = _xlfby[-32:]; _uk = _xlfby[16:-32]
        _khra = _syuiu.pbkdf2_hmac('sha256', _bagqkz.encode(), _diap, 100000, dklen=80)
        _qhpdp = _khra[:32]; _cz = _khra[32:48]; _rungcp = _khra[48:80]
        _nrahlmg = _oubm.new(_rungcp, _uk, _syuiu.sha256).digest()
        if not _oubm.compare_digest(_jh, _nrahlmg):
            _ktollye.stderr.write("error: integrity check failed\n"); _ktollye.exit(1)
        _uqgbhj = _pssiubt(_hqd.ChaCha20(_qhpdp, _cz), mode=None)
        _ask = _uqgbhj.decryptor().update(_uk)
    elif _uamv == 0:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _pssiubt, algorithms as _hqd, modes as _yghh
        except ImportError:
            _ktollye.stderr.write("error: cryptography not installed\n"); _ktollye.exit(1)
        _diap = _xlfby[:16]; _jh = _xlfby[-32:]; _uk = _xlfby[16:-32]
        _khra = _syuiu.pbkdf2_hmac('sha256', _bagqkz.encode(), _diap, 100000, dklen=64)
        _qhpdp = _khra[:32]; _rungcp = _khra[32:64]
        _nrahlmg = _oubm.new(_rungcp, _uk, _syuiu.sha256).digest()
        if not _oubm.compare_digest(_jh, _nrahlmg):
            _ktollye.stderr.write("error: integrity check failed\n"); _ktollye.exit(1)
        _uqgbhj = _pssiubt(_hqd.AES(_qhpdp), _yghh.ECB())
        _ask = _uqgbhj.decryptor()
        _ask = _ask.update(_uk) + _ask.finalize()
        _hchgl = _ask[-1]
        if _hchgl < 1 or _hchgl > 16 or not all(_ == _hchgl for _ in _ask[-_hchgl:]):
            _ktollye.stderr.write("error: decryption failed\n"); _ktollye.exit(1)
        _ask = _ask[:-_hchgl]
    elif _uamv == 3:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _cyh
        except ImportError:
            _ktollye.stderr.write("error: cryptography not installed\n"); _ktollye.exit(1)
        _diap = _xlfby[:16]; _jh = _xlfby[-32:]; _ask = _xlfby[16:-32]
        _uk = _ask[:-16]; _hchgl = _ask[-16:]
        _khra = _syuiu.pbkdf2_hmac('sha256', _bagqkz.encode(), _diap, 100000, dklen=76)
        _qhpdp = _khra[:32]; _cz = _khra[32:44]; _rungcp = _khra[44:76]
        _nrahlmg = _oubm.new(_rungcp, _ask, _syuiu.sha256).digest()
        if not _oubm.compare_digest(_jh, _nrahlmg):
            _ktollye.stderr.write("error: integrity check failed\n"); _ktollye.exit(1)
        _ask = _cyh(_qhpdp).decrypt(_cz, _uk + _hchgl, None)
    elif _uamv == 8:
        _yqdzub = ('0','1','2','3','4','5','6','7','8','9',
                'A','B','C','D','E','F','G','H','I','J','K','L','M',
                'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
                'a','b','c','d','e','f','g','h','i','j','k','l','m',
                'n','o','p','q','r','s','t','u','v','w','x','y','z',
                '!','#','$','%','&','(',')','*','+','-',';','<','=',
                '>','?','@','^','_','`','{','|','}','~')
        _zsyt = {c:i for i,c in enumerate(_yqdzub)}
        def _tv(_cenfe):
            _novp = bytearray(); _xeohw = 0
            while _xeohw < len(_cenfe):
                _zzm = 0; _cvx = 0
                while _xeohw < len(_cenfe) and _cvx < 5:
                    _zzm = _zzm * 85 + _zsyt[chr(_cenfe[_xeohw])]; _xeohw += 1; _cvx += 1
                _vqwons = _cvx - 1
                if _vqwons > 0: _novp.extend(_zzm.to_bytes(4, 'big')[4-_vqwons:])
            return bytes(_novp)
        _ask = _tv(_xlfby)
    elif _uamv == 5:
        _diap = _xlfby[:16]; _jh = _xlfby[-32:]; _uk = _xlfby[16:-32]
        _khra = _syuiu.pbkdf2_hmac('sha256', _bagqkz.encode(), _diap, 100000, dklen=64)
        _qhpdp = _khra[:32]; _rungcp = _khra[32:64]
        _nrahlmg = _oubm.new(_rungcp, _uk, _syuiu.sha256).digest()
        if not _oubm.compare_digest(_jh, _nrahlmg):
            _ktollye.stderr.write("error: integrity check failed\n"); _ktollye.exit(1)
        _ask = bytes(_uk[i] ^ _qhpdp[i % 32] for i in range(len(_uk)))
    elif _uamv == 9:
        def _shzw(_nkrek):
            if _nkrek[:2] == b'<~': _nkrek = _nkrek[2:]
            if _nkrek[-2:] == b'~>': _nkrek = _nkrek[:-2]
            _iaxf = bytearray(); _ygc = 0
            while _ygc < len(_nkrek):
                if _nkrek[_ygc] == 122:
                    _iaxf.extend(b'\x00\x00\x00\x00'); _ygc += 1; continue
                _jxtfsj = 0; _jx = 0
                while _ygc < len(_nkrek) and _jx < 5:
                    _jxtfsj = _jxtfsj * 85 + (_nkrek[_ygc] - 33); _ygc += 1; _jx += 1
                _brddnz = _jx - 1
                if _brddnz > 0: _iaxf.extend(_jxtfsj.to_bytes(4, 'big')[4-_brddnz:])
            return bytes(_iaxf)
        _ask = _shzw(_xlfby)
    elif _uamv == 7:
        _ask = _cs.b32decode(_xlfby)
    elif _uamv == 10:
        _ask = bytes.fromhex(_xlfby.decode('ascii'))
    elif _uamv == 1:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _pssiubt, algorithms as _hqd, modes as _yghh
        except ImportError:
            _ktollye.stderr.write("error: cryptography not installed\n"); _ktollye.exit(1)
        _diap = _xlfby[:16]; _jh = _xlfby[-32:]; _uk = _xlfby[16:-32]
        _khra = _syuiu.pbkdf2_hmac('sha256', _bagqkz.encode(), _diap, 100000, dklen=80)
        _qhpdp = _khra[:32]; _cz = _khra[32:48]; _rungcp = _khra[48:80]
        _nrahlmg = _oubm.new(_rungcp, _uk, _syuiu.sha256).digest()
        if not _oubm.compare_digest(_jh, _nrahlmg):
            _ktollye.stderr.write("error: integrity check failed\n"); _ktollye.exit(1)
        _uqgbhj = _pssiubt(_hqd.AES(_qhpdp), _yghh.CBC(_cz))
        _ask = _uqgbhj.decryptor()
        _ask = _ask.update(_uk) + _ask.finalize()
        _hchgl = _ask[-1]
        if _hchgl < 1 or _hchgl > 16 or not all(_ == _hchgl for _ in _ask[-_hchgl:]):
            _ktollye.stderr.write("error: decryption failed\n"); _ktollye.exit(1)
        _ask = _ask[:-_hchgl]
    elif _uamv == 2:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _pssiubt, algorithms as _hqd, modes as _yghh
        except ImportError:
            _ktollye.stderr.write("error: cryptography not installed\n"); _ktollye.exit(1)
        _diap = _xlfby[:16]; _jh = _xlfby[-32:]; _uk = _xlfby[16:-32]
        _khra = _syuiu.pbkdf2_hmac('sha256', _bagqkz.encode(), _diap, 100000, dklen=80)
        _qhpdp = _khra[:32]; _cz = _khra[32:48]; _rungcp = _khra[48:80]
        _nrahlmg = _oubm.new(_rungcp, _uk, _syuiu.sha256).digest()
        if not _oubm.compare_digest(_jh, _nrahlmg):
            _ktollye.stderr.write("error: integrity check failed\n"); _ktollye.exit(1)
        _uqgbhj = _pssiubt(_hqd.AES(_qhpdp), _yghh.CTR(_cz))
        _ask = _uqgbhj.decryptor().update(_uk)
    else:
        _ktollye.stderr.write("error: unsupported algorithm\n"); _ktollye.exit(1)
    _v_k = bytes.fromhex("b0b1025a1f75a376db33350d790368d7991318d2f356d6d6b68b577b6a71dd3c")
    _v_s = _v_k[0]
    _v_r = bytearray()
    for i in range(len(_ask[4:])):
        _v_v = _ask[4+i] ^ _v_s
        _v_r.append(_v_v)
        _v_s = (_ask[4+i] ^ _v_k[(i+1)%len(_v_k)])
        _v_s = (((_v_s << 3) & 0xFF) | (_v_s >> 5)) ^ 0x5A
    _xd = bytes(_v_r)
    _ask, _c, _k, _m = _vm_deserialize(_xd)
    exec(compile(_ask, '<vm>', 'exec'), globals())
    _vm_run(_c, _k, _m, globals(), locals())
if __name__ == '__main__':
    _qpvemg()
