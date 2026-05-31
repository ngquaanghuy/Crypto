#!/usr/bin/env python3
def _drzocix(_hizqhxz):
    return _hizqhxz % 5598 + 1

import hashlib as _kwawijcu, hmac as _ilyvmks, base64 as _uxujbpzjd, sys as _jwfcgd, zlib as _dolhi
_hizqhxz = 560155
_rtwmhg = """HgPAicwqanUgGsWCQjW8JJVAJXCcIfwohRo4ATPJmDVBsqlT8iCvp7FBq/v4IcjMIab66NGc/pZbs2nUDLHtsB5mEQN9N9TlT6I22wI0JUttWq3f0VozIRLoShC0RcGlRP5cB6D+Lu2NtXv36ypw6HYLxDyAK/n3722spBeJ926MNr7MTOprBMMg2S0F/3OFMZkrQ5XSpC4d6o1mNsz1iIE0obaC/nDl6iMKcq3fUQkiB5jT+/eMPX6ChfHdjolLAGTjYdt1IK9l6iwBEa77bS2t78BIclBb+9HjidOjVVkbhrpXVDnb6sf9oZECJ844MhrxBr3wny/1Xr6CbdjVtw33foufa2X/BwFl6J8T8NNTZDtJ/4hjb8r0t8XKW02bQ3bvtiMpZe7/3V5u4BJtNK2gTJNnsFDU3HrJ33HSSheqpWWSjnUGxR+U7SSp/Vv/WM5/d6IDudiZ3c5YWZNTpjuzfWSZ5/VjVDqf9EWJj5UZSHXIxzeLAmdKKBnlpLvasqYxVq5HfZYtXs0mZT1/1bP1qPQM5FgqXaxDqn77sjprGcBTR812hdda2YDpG/2ju69zAEz0P7yPXqnu7mI8n3Wuv9j3bZRWbvtrqt/wIVD7b+2TtL4xY84kGUf8z2uzg5Kb6zSrTCq5zNOExH3Vf45QiaE8C8VBM9WtsqdCRx+WV7KIaBzHGcBQFG4wyU3zjlUnSDrzJ7TE/sBl6BJZAWq+FpBTBA7kw33ynnyfRpIJy2uQBWwXLDjB8eoLaeHPv/D4PMeppL+M2FGyZnIu28Ow3EbQmX3DjjL0vRXv5aaj5doGdzrBaIlNGIR6+JTbn/ysNlCLnNY2x6QT391sp3Fmki/pidphiNeEy8AwP3kTSFjUHMwT3oaiZMj+Ec0maGTcQxC1l6yQwzzd0mi9lICv1xQZgQAspBfWMNltekhsIvS2ht6r6KKoSZJPMjaK6fu/bji/pLlaCaweL40qORoL15Avhgqkzkb6Ypgx3z54vyQNMDT1Fh7WjCU+Mz8M2Xq3RyFttPJMgKw9TebCPvBTHZOowO9RmA/cacUw4zHpGFec/eJy6l0Lc2ZLnCp0rJJ8s3y4aEeldUmafPbeBPOFEkoD8d+lxtEWZw=="""
_padllgc = 3
_jcdvntmg = _drzocix(_hizqhxz)

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




def _ralpr():
    if _jwfcgd.gettrace() is not None:
        _jwfcgd.stderr.write('error: debugger detected\n'); _jwfcgd.exit(1)
    _qhdzf = bytes.fromhex("465b794e4d7b2e7d71605a2252605f67237b205952605c7321606d562f477f705b72257f442e7c47706727564172594450737921616d62234f4422702256216f2178505a277441665a45205054794f60437520664d6642204566797240615a606e537e6d74726f42504e6d73514f535a5b5d4446635c404f5562737e424d506d6e677a745d6321655e715a72467127736d5d6344747946785b4642214d624022527552202575235864407421587f6e446d2444214d515c6e7e5f515b71447d4721544e5e7d65786074516665642261675e7c452555517f236f24582252506e746d43417e56644e7d4e735367267a4f202126452e754320744e656467272755445b4e46457f5e5e6d51734e2225662f255a5c416643657d7f5c7b24714e23547f5d6e23466620742f4d562e27707c6f4d647a7f5e647a7d614059737f7a23665223464e245e236246535373405d45255440526e5f44532245636e2067676d42227c6e535550545a21636d797b237f67265a5c5f7b737f5c715f755b2470605f424124525a5e4540416d635e2660605a5b7d654d267b645f657f787f2f6e757b5c2740242e5c217876236127767027247b2e595323717e73707d5350417b6f65412f41635075725c534e5558566d7b505146586e204d65755f422f585b7b2f646425504e404e7f606576437d4461796770237f255570404672426f67746e5f5379427379222247592667545f7b6e6f786e7f7f2179617a2f23545f6f62785c4562766e405f7a47432e50515d5847266426735253745b455e5542726024765e64526e707061622250544d795a265658455b4671237b64524371265a25472f662641225f4e52527f202e627d4d4679247c507d4766615c6f4e5622794d40265e275c516e2f5f225e477d7a2e7d4d427a7f4e2225795f6f4e7541225f717c5055205c51216e7955552178447b235e72614d4250254e5b7b536d7c705f6555237d2253552e42252e5523725c43785e76567579532361632446585b557e41754160415653707d6420556041615d7b242779432355507a7b646745716f4d43587d227b406e5541527655646559502e527f2f5b6f455f4547726453546d66457d5b4055756158554258605e5e5d5e5526437f75766e7c4f705f635b42614e7445632f7c795d647b44745970615d277d525a757922635f596d587c45507b417f46635c63674166667d512f536661757c5943247b26646e7441505f56615341465465437245707e65677a75766e615c2076227c454e217f5456665563744d472f59465a4d716d784170432065657b227b6472504d7652584e52627263627351552f56647a276070505f7c4d7b5f47447c41517879587c215c2f6d547a615f4d56796546565a2526764e5f6d5b5c4456446221735c2351607f7f5f50595c23552f5e5e767d2f")
    _qhdzf = bytes(_ ^ 23 for _ in _qhdzf).decode()
    _jwfcgd.breakpointhook = None
    for _qm in ('pydevd','pdb','ipdb','pdbpp','pydevconsole'):
        if _qm in _jwfcgd.modules:
            _jwfcgd.stderr.write('error: debugger detected\n'); _jwfcgd.exit(1)
    _dmpfr = _uxujbpzjd.b64decode(_rtwmhg)
    for _qn in ('__import__','compile','exec'):
        _qf = getattr(_jwfcgd.modules.get('builtins'), _qn, None)
        if _qf is not None:
            _qg = getattr(_qf, '__name__', '')
            if _qg != _qn:
                _jwfcgd.stderr.write('error: hook detected\n'); _jwfcgd.exit(1)
    if len(_jwfcgd.meta_path) > 5:
        _jwfcgd.stderr.write('error: import hook detected\n'); _jwfcgd.exit(1)
    if getattr(_jwfcgd, 'flags', None) and _jwfcgd.flags.no_user_site:
        _jwfcgd.stderr.write('error: sandbox detected\n'); _jwfcgd.exit(1)
    import os
    if any(x in str(_jwfcgd.platform) or any(y in os.listdir('/proc/sys/kernel') for y in ['//', 'vm']) for x in ['vmware', 'virtualbox', 'qemu']):
        _jwfcgd.stderr.write('error: virtual machine detected\n'); _jwfcgd.exit(1)
    if _padllgc == 3:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _nergrzltw
        except ImportError:
            _jwfcgd.stderr.write("error: cryptography not installed\n"); _jwfcgd.exit(1)
        _ldntjew = _dmpfr[:16]; _mjlpxdxqg = _dmpfr[-32:]; _wrelk = _dmpfr[16:-32]
        _sjuwwke = _wrelk[:-16]; _ordocues = _wrelk[-16:]
        _qsfha = _kwawijcu.pbkdf2_hmac('sha256', _qhdzf.encode(), _ldntjew, 100000, dklen=76)
        _konvuj = _qsfha[:32]; _mtejroptc = _qsfha[32:44]; _guajrqqh = _qsfha[44:76]
        _koskid = _ilyvmks.new(_guajrqqh, _wrelk, digestmod='sha256').digest()
        if not _ilyvmks.compare_digest(_mjlpxdxqg, _koskid):
            _jwfcgd.stderr.write("error: integrity check failed\n"); _jwfcgd.exit(1)
        _wrelk = _nergrzltw(_konvuj).decrypt(_mtejroptc, _sjuwwke + _ordocues, None)
    elif _padllgc == 4:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _qbxcb, algorithms as _yvqmfz, modes as _ycobwuvb
        except ImportError:
            _jwfcgd.stderr.write("error: cryptography not installed\n"); _jwfcgd.exit(1)
        _ldntjew = _dmpfr[:16]; _mjlpxdxqg = _dmpfr[-32:]; _sjuwwke = _dmpfr[16:-32]
        _qsfha = _kwawijcu.pbkdf2_hmac('sha256', _qhdzf.encode(), _ldntjew, 100000, dklen=80)
        _konvuj = _qsfha[:32]; _mtejroptc = _qsfha[32:48]; _guajrqqh = _qsfha[48:80]
        _koskid = _ilyvmks.new(_guajrqqh, _sjuwwke, digestmod='sha256').digest()
        if not _ilyvmks.compare_digest(_mjlpxdxqg, _koskid):
            _jwfcgd.stderr.write("error: integrity check failed\n"); _jwfcgd.exit(1)
        _vaxfkla = _qbxcb(_yvqmfz.ChaCha20(_konvuj, _mtejroptc), mode=None)
        _wrelk = _vaxfkla.decryptor().update(_sjuwwke)
    elif _padllgc == 10:
        _wrelk = bytes.fromhex(_dmpfr.decode('ascii'))
    elif _padllgc == 1:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _qbxcb, algorithms as _yvqmfz, modes as _ycobwuvb
        except ImportError:
            _jwfcgd.stderr.write("error: cryptography not installed\n"); _jwfcgd.exit(1)
        _ldntjew = _dmpfr[:16]; _mjlpxdxqg = _dmpfr[-32:]; _sjuwwke = _dmpfr[16:-32]
        _qsfha = _kwawijcu.pbkdf2_hmac('sha256', _qhdzf.encode(), _ldntjew, 100000, dklen=80)
        _konvuj = _qsfha[:32]; _mtejroptc = _qsfha[32:48]; _guajrqqh = _qsfha[48:80]
        _koskid = _ilyvmks.new(_guajrqqh, _sjuwwke, digestmod='sha256').digest()
        if not _ilyvmks.compare_digest(_mjlpxdxqg, _koskid):
            _jwfcgd.stderr.write("error: integrity check failed\n"); _jwfcgd.exit(1)
        _vaxfkla = _qbxcb(_yvqmfz.AES(_konvuj), _ycobwuvb.CBC(_mtejroptc))
        _wrelk = _vaxfkla.decryptor()
        _wrelk = _wrelk.update(_sjuwwke) + _wrelk.finalize()
        _ordocues = _wrelk[-1]
        if _ordocues < 1 or _ordocues > 16 or not all(_ == _ordocues for _ in _wrelk[-_ordocues:]):
            _jwfcgd.stderr.write("error: decryption failed\n"); _jwfcgd.exit(1)
        _wrelk = _wrelk[:-_ordocues]
    elif _padllgc == 7:
        _wrelk = _uxujbpzjd.b32decode(_dmpfr)
    elif _padllgc == 5:
        _ldntjew = _dmpfr[:16]; _mjlpxdxqg = _dmpfr[-32:]; _sjuwwke = _dmpfr[16:-32]
        _qsfha = _kwawijcu.pbkdf2_hmac('sha256', _qhdzf.encode(), _ldntjew, 100000, dklen=64)
        _konvuj = _qsfha[:32]; _guajrqqh = _qsfha[32:64]
        _koskid = _ilyvmks.new(_guajrqqh, _sjuwwke, digestmod='sha256').digest()
        if not _ilyvmks.compare_digest(_mjlpxdxqg, _koskid):
            _jwfcgd.stderr.write("error: integrity check failed\n"); _jwfcgd.exit(1)
        _wrelk = bytes(_sjuwwke[i] ^ _konvuj[i % 32] for i in range(len(_sjuwwke)))
    elif _padllgc == 11:
        _ldntjew = _dmpfr[:16]; _mjlpxdxqg = _dmpfr[-32:]; _sjuwwke = _dmpfr[16:-32]
        _qsfha = _kwawijcu.pbkdf2_hmac('sha256', _qhdzf.encode(), _ldntjew, 100000, dklen=64)
        _konvuj = _qsfha[:32]; _guajrqqh = _qsfha[32:64]
        _koskid = _ilyvmks.new(_guajrqqh, _sjuwwke, digestmod='sha256').digest()
        if not _ilyvmks.compare_digest(_mjlpxdxqg, _koskid):
            _jwfcgd.stderr.write("error: integrity check failed\n"); _jwfcgd.exit(1)
        _ordocues = _konvuj[0]
        _wrelk = bytearray()
        for _ausrt in range(len(_sjuwwke)):
            _ldntjew = _sjuwwke[_ausrt] ^ _ordocues
            _wrelk.append(_ldntjew)
            _ordocues = _sjuwwke[_ausrt] ^ _konvuj[ (_ausrt + 1) % len(_konvuj) ]
            _ordocues = (((_ordocues << 3) & 0xFF) | (_ordocues >> 5)) ^ 0x5A
        _wrelk = bytes(_wrelk)
    elif _padllgc == 9:
        def _cimbryr(_gzuows):
            if _gzuows[:2] == b'<~': _gzuows = _gzuows[2:]
            if _gzuows[-2:] == b'~>': _gzuows = _gzuows[:-2]
            _zwubc = bytearray(); _xyhlkd = 0
            while _xyhlkd < len(_gzuows):
                if _gzuows[_xyhlkd] == 122:
                    _zwubc.extend(b'\x00\x00\x00\x00'); _xyhlkd += 1; continue
                _ljnpr = 0; _riailjj = 0
                while _xyhlkd < len(_gzuows) and _riailjj < 5:
                    _ljnpr = _ljnpr * 85 + (_gzuows[_xyhlkd] - 33); _xyhlkd += 1; _riailjj += 1
                _xfanh = _riailjj - 1
                if _xfanh > 0: _zwubc.extend(_ljnpr.to_bytes(4, 'big')[4-_xfanh:])
            return bytes(_zwubc)
        _wrelk = _cimbryr(_dmpfr)
    elif _padllgc == 2:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _qbxcb, algorithms as _yvqmfz, modes as _ycobwuvb
        except ImportError:
            _jwfcgd.stderr.write("error: cryptography not installed\n"); _jwfcgd.exit(1)
        _ldntjew = _dmpfr[:16]; _mjlpxdxqg = _dmpfr[-32:]; _sjuwwke = _dmpfr[16:-32]
        _qsfha = _kwawijcu.pbkdf2_hmac('sha256', _qhdzf.encode(), _ldntjew, 100000, dklen=80)
        _konvuj = _qsfha[:32]; _mtejroptc = _qsfha[32:48]; _guajrqqh = _qsfha[48:80]
        _koskid = _ilyvmks.new(_guajrqqh, _sjuwwke, digestmod='sha256').digest()
        if not _ilyvmks.compare_digest(_mjlpxdxqg, _koskid):
            _jwfcgd.stderr.write("error: integrity check failed\n"); _jwfcgd.exit(1)
        _vaxfkla = _qbxcb(_yvqmfz.AES(_konvuj), _ycobwuvb.CTR(_mtejroptc))
        _wrelk = _vaxfkla.decryptor().update(_sjuwwke)
    elif _padllgc == 13:
        _ldntjew = _dmpfr[:16]; _mjlpxdxqg = _dmpfr[-32:]; _sjuwwke = _dmpfr[16:-32]
        _qsfha = _kwawijcu.pbkdf2_hmac('sha256', _qhdzf.encode(), _ldntjew, 100000, dklen=80)
        _konvuj = _qsfha[:32]; _mtejroptc = _qsfha[32:48]; _guajrqqh = _qsfha[48:80]
        _koskid = _ilyvmks.new(_guajrqqh, _sjuwwke, digestmod='sha256').digest()
        if not _ilyvmks.compare_digest(_mjlpxdxqg, _koskid):
            _jwfcgd.stderr.write("error: integrity check failed\n"); _jwfcgd.exit(1)
        import struct as _jcdvntmg
        def _drzocix(k,c,n):
            s=[0x61707865,0x3320646e,0x79622d32,0x6b206574]
            for i in range(0,32,4):s.append(_jcdvntmg.unpack('<I',k[i:i+4])[0])
            s.append(c&0xFFFFFFFF)
            for i in range(0,12,4):s.append(_jcdvntmg.unpack('<I',n[i:i+4])[0])
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
            for i in range(16):r.extend(_jcdvntmg.pack('<I',(s[i]+w[i])&0xFFFFFFFF))
            return bytes(r)
        _ausrt = _jcdvntmg.unpack('<I',_mtejroptc[:4])[0]
        _mtejroptc = _mtejroptc[4:]
        _ldntjew = bytearray()
        while len(_ldntjew) < len(_sjuwwke):
            _ordocues = _drzocix(_konvuj, _ausrt, _mtejroptc)
            for _hizqhxz in range(min(64, len(_sjuwwke) - len(_ldntjew))):
                _ldntjew.append(_sjuwwke[len(_ldntjew)] ^ _ordocues[_hizqhxz])
            _ausrt += 1
        _wrelk = bytes(_ldntjew)
    elif _padllgc == 0:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _qbxcb, algorithms as _yvqmfz, modes as _ycobwuvb
        except ImportError:
            _jwfcgd.stderr.write("error: cryptography not installed\n"); _jwfcgd.exit(1)
        _ldntjew = _dmpfr[:16]; _mjlpxdxqg = _dmpfr[-32:]; _sjuwwke = _dmpfr[16:-32]
        _qsfha = _kwawijcu.pbkdf2_hmac('sha256', _qhdzf.encode(), _ldntjew, 100000, dklen=64)
        _konvuj = _qsfha[:32]; _guajrqqh = _qsfha[32:64]
        _koskid = _ilyvmks.new(_guajrqqh, _sjuwwke, digestmod='sha256').digest()
        if not _ilyvmks.compare_digest(_mjlpxdxqg, _koskid):
            _jwfcgd.stderr.write("error: integrity check failed\n"); _jwfcgd.exit(1)
        _vaxfkla = _qbxcb(_yvqmfz.AES(_konvuj), _ycobwuvb.ECB())
        _wrelk = _vaxfkla.decryptor()
        _wrelk = _wrelk.update(_sjuwwke) + _wrelk.finalize()
        _ordocues = _wrelk[-1]
        if _ordocues < 1 or _ordocues > 16 or not all(_ == _ordocues for _ in _wrelk[-_ordocues:]):
            _jwfcgd.stderr.write("error: decryption failed\n"); _jwfcgd.exit(1)
        _wrelk = _wrelk[:-_ordocues]
    elif _padllgc == 12:
        _ldntjew = _dmpfr[:16]; _mjlpxdxqg = _dmpfr[-32:]; _sjuwwke = _dmpfr[16:-32]
        _qsfha = _kwawijcu.pbkdf2_hmac('sha256', _qhdzf.encode(), _ldntjew, 100000, dklen=64)
        _konvuj = _qsfha[:32]; _guajrqqh = _qsfha[32:64]
        _koskid = _ilyvmks.new(_guajrqqh, _sjuwwke, digestmod='sha256').digest()
        if not _ilyvmks.compare_digest(_mjlpxdxqg, _koskid):
            _jwfcgd.stderr.write("error: integrity check failed\n"); _jwfcgd.exit(1)
        _ordocues = 3 + (_ldntjew[0] & 7)
        _ldntjew = bytearray(_sjuwwke)
        for _ausrt in range(_ordocues - 1, -1, -1):
            _drzocix = (3 + _ausrt) & 7
            _hizqhxz = (_ausrt * 0x1B + 0x5A) & 0xFF
            for _mtejroptc in range(len(_ldntjew)):
                _ordocues = _ldntjew[_mtejroptc]
                _ordocues ^= _hizqhxz
                _ordocues = ((_ordocues >> _drzocix) | ((_ordocues << (8 - _drzocix)) & 0xFF))
                _ordocues ^= _konvuj[(_ausrt * len(_ldntjew) + _mtejroptc) % len(_konvuj)]
                _ldntjew[_mtejroptc] = _ordocues
        _wrelk = bytes(_ldntjew)
    elif _padllgc == 6:
        _wrelk = _uxujbpzjd.b64decode(_dmpfr)
    elif _padllgc == 8:
        _kpqdt = ('0','1','2','3','4','5','6','7','8','9',
                'A','B','C','D','E','F','G','H','I','J','K','L','M',
                'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
                'a','b','c','d','e','f','g','h','i','j','k','l','m',
                'n','o','p','q','r','s','t','u','v','w','x','y','z',
                '!','#','$','%','&','(',')','*','+','-',';','<','=',
                '>','?','@','^','_','`','{','|','}','~')
        _fwbdrrpzq = {c:i for i,c in enumerate(_kpqdt)}
        def _xsfaq(_yrkylcrgh):
            _yzgtpn = bytearray(); _rtjkkid = 0
            while _rtjkkid < len(_yrkylcrgh):
                _hxhkojih = 0; _ivvzdeebe = 0
                while _rtjkkid < len(_yrkylcrgh) and _ivvzdeebe < 5:
                    _hxhkojih = _hxhkojih * 85 + _fwbdrrpzq[chr(_yrkylcrgh[_rtjkkid])]; _rtjkkid += 1; _ivvzdeebe += 1
                _utammtvze = _ivvzdeebe - 1
                if _utammtvze > 0: _yzgtpn.extend(_hxhkojih.to_bytes(4, 'big')[4-_utammtvze:])
            return bytes(_yzgtpn)
        _wrelk = _xsfaq(_dmpfr)
    else:
        _jwfcgd.stderr.write("error: unsupported algorithm\n"); _jwfcgd.exit(1)
    _vk = bytes.fromhex("6f3fb079f1971799500c54b60ac47af2b7d3af930d6fc0a3a1abd9e9e92f69b3")
    _vn = bytes.fromhex("8d45f3c0c991f69d426624a9eacd01d5")
    _sig = _wrelk[-32:]
    _pl = _wrelk[4:-32]
    import hmac, hashlib
    if not hmac.compare_digest(_sig, hmac.new(_vk, _pl, hashlib.sha256).digest()):
        _jwfcgd.stderr.write('error: VM integrity check failed\n'); _jwfcgd.exit(1)
    _pd = bytes([_pl[i] ^ _vk[i % 32] ^ _vn[i % 16] for i in range(len(_pl))])
    if _wrelk[1] == 1:
        import zlib as _dolhi
        _pd = _dolhi.decompress(_pd)
    elif _wrelk[1] == 2:
        import lzma as _dolhi
        _pd = _dolhi.decompress(_pd)
    elif _wrelk[1] == 3:
        import bz2 as _dolhi
        _pd = _dolhi.decompress(_pd)
    elif _wrelk[1] == 4:
        import brotli as _dolhi
        _pd = _dolhi.decompress(_pd)
    elif _wrelk[1] == 5:
        import zstandard as _dolhi
        _pd = _dolhi.decompress(_pd)
    elif _wrelk[1] == 6:
        import gzip as _dolhi
        _pd = _dolhi.decompress(_pd)
    elif _wrelk[1] == 7:
        import lz4.frame as _dolhi
        _pd = _dolhi.decompress(_pd)
    elif _wrelk[1] == 8:
        import snappy as _dolhi
        _pd = _dolhi.decompress(_pd)
    elif _wrelk[1] == 9:
        import gzip as _dolhi
        _pd = _dolhi.decompress(_pd)
    elif _wrelk[1] == 10:
        import blosc as _dolhi
        _pd = _dolhi.decompress(_pd)
    else:
        pass
    _c, _k, _m, _map, _ok = _vm_deserialize(_pd)
    exec(compile(_uxujbpzjd.b64decode("aW1wb3J0IGJhc2U2NAppbXBvcnQgaGFzaGxpYgppbXBvcnQgaG1hYwppbXBvcnQgY3R5cGVzCmltcG9ydCBiYXNlNjQKaW1wb3J0IGhhc2hsaWIKaW1wb3J0IGhtYWMKaW1wb3J0IGN0eXBlcwpfRlVOQ19LRVkgPSBiYXNlNjQuYjY0ZGVjb2RlKCcvNDB6NlBuVndycDQ3cmI5Zk5PUmJTbndmeGdSekFLdmlJc3owcHdFVi9zPScpCl9GRU5DX0RBVEEgPSBbYmFzZTY0LmI2NGRlY29kZSgnYUJVd1ZjNTdjSnBKcHJmRzlBUlpZKzJKNnN6WFVFL0JtVjZWU0NqNVhqTjIzc0NDeDh2bkhiZUlDbmhJS2FTTHhkelR5RFlhQlF2bEN0UkYrc2pzYW9YczlHUm5XcUVUVHo2OUlEMHpvVEhKM3QveUk4bEc3UGxYZnEreVN3TUp6SlM2ZlFmRHBCSi9KYWt4UXlIQ1MrNXJQRVFuTTJpTkxhWEFMZFZPNm9walk3VmJoc2NNMVdkUWowMXpuK1gzRFdjVDlTeGtQV1crd3RDK1lRL3FJK0N3UzAyL044cHdLQlRNK2U1ek9JQVVFYStlYlZaYnI3TjZ4Q0JEbkdQeHZZRWkrN1Y5QWpodE1OS1JadzdrUHB0M3Q4RHE0QXQvOVRGc3ZCSVNKcHp6eVdBVjViSlI3T0FTL0dCbTZvbnVwSVdaOWNqQk9tazMvN01GUTN5ZjJ1TlJ0WG92eGVESSt6RHZRbitINXNpZDdFL1piZXR2SDRsbGlldWlSdCtNL3FVdm9DdnJwMzRVYVBRbFdHOFpEYUxyS3RyN3hQZVl1aGRrZFBCRCs5SXFqWnVMMWtqRlRaNFVDWjZITVVzRXlQT3pTVHFielBzSWE3V29EUVU0SGRhL2JFTnQyc0RzS2dWT1NwL0tKdVU0SGJhNGZQNFRSQTdhZDRIamRzR2NlNmVta2RqR3paYkRFWUdzYVZuNEZ0NE55VGIvK01nRHk0clYxLzZNM2Irai8wcHRvRHYwMWN1UHloZXdBalhMbHBuQzNiMmVJcXoxaUN0R2lvckdBdFI1b0hmbzNFY3hua2MySjBsQnR1dmdrNWNBN09YeTBvdDZZUTF4bkp2OVk4a2JvMlpMaHcwVmNYMmZob3h0bkpJVUpScFI1WDFiTE12WGN1WmNKWHlRNlUyZ3RkQWJlc25HRUZQQkdjOHBjeEl1UTlTR3UvVzQyNTdVVmtwekhPRThEUFdmNkRiR1Y0aVl0OXdQaTN4NzJoNzhKcTI4OGpqaUk2UjlaUFFIUFNZRU9DenpPejlvRDdGY2dPMHpaUkR3Zng1RkF1SkJxck9FYVNNM3JueGpob1dxQXJnR1dkOE1iY0hkNHpXMlVMMGN5bFo5ekNSVFZpdTJTWm1rNTJxVHJMUUVnTldLUDY3aE5MSDdtYVU4U0hiVDlQckwyQnB2aUVGbEowS0VDaVQyUFlFNXVGL0J0MVU3Yko3UVdwNWZZWTRqak9PaWs4V1k2eC9ab2xjTGFVYUVKdnVwY0h3THR1T2c1VStJbEZsT0pxTTlhUTFCQ0x3Um5TSHhQRFYrZno3YVB2YXAyL1NJUzZSTk9OcS80T1NkbmZGb1RmZElWdU1DT1UyRklqU0dzT2Vxc3FBNnRTdHJxQkVWOEMwVW1pQ3lvNVdNTlBEYWdqSkt0YXNHR3dYRHJaVjlSdmhxRUk5YzBnSXJIT09ZVDRmM0IxbGFBNEsza05XMDdEQ1VsVDV1YlFhK09CVkhTUnVtbk9RT1E4Mlc3clg1VldWQkV5a1JGMzFrWkZWdU5BZHB1WDhZVjdDVm9IRTZLVXU5ek9iWkUyVmp2YjZYQ0dhKzNWeDdKdmhweHo3RHFheC9UcWxGR2MvNW83QXFyZWU0dFN0a1loUmpDSDd0Qk5MNDU5cXc1Mnc4NjE0VlJsdW15SnA0bVhIVys4T29wNkVWSWhDM1dQbi9YRytieHhTWEt2ZzRYQ0Myd3orTW4rZ0xZbWx0SnEwdXBpZ0Z4VWVyeW1nc2ZLRVVpdWNBNmo1UDlaYUtLS2IzYTRTbFNZaXdyejNoa3cyMVYzZ3N2Vngwc1RxL2drUmpqNWlTTGNsSGtmRHRZR0I0M2NqUmhNSnJWd0pOc01vb3N2V3BQVThJVWF0a0lxUVlSS1ZPQlRhSEtma1IxZkc5S1A4Y2pxMmN2UUpvVVZjMHJlTGZ4ZlNiTXBMRFgzQXhZSWcvRUU5SHZwMGY0eVF1T1lZY3piOFY1WWVib1UyTHEvbU93dmdUdU9nYXZia2RYUHl2WnN6UjJjUUJHdXRYM0k5TENRbW9nR3EvOEw1YVFpaVRjdTVUTit4L0c5c1NtMjZlSk1BeG9lWms3MWV5N1V0TzBNQllab2dsWStqV0FiRzRwTnpQTmlEdEhoQU5ENGdQblFoMDk2MThRSk9tL0JmNnJ5TWR5QjFQM1d3b3hTbWtwS2pGdzkxdTJmZkNjZXBkUWVaOVpyRHNvTG9wOHI2Q2RmUENNb0NvTmc9PScpLCBiYXNlNjQuYjY0ZGVjb2RlKCdURi9iaFZ6dk1vNUpzbnFhazdkem5mUHNpOG1mMFVGVi9FRzBuUk1TZ1AxcnNNb3NQOE4wcFJJZTZhZU9wczB6eU8waGxhSlA5YVR5TnpHaWVHc1FYVTMyYmpSSk5CSHR1alorMjIxV2V1QXBlZ2tOb1BFZk5GRmR5NzRDQU5FWDZqdzhoMUl4VkQwUFB4dk5hNWlyZlhodXRuSzBuc3N1NGJUN0xnekRYeG9xS3pwaXVmRWg0T2d6WU5YSmljYmw3KzNGSjdKTkxSQ0hUNzhtNkVVanZHdTBJNFNTZTNYdzhQUVNXYnFINWdvY296R21HMDFoTmRRVlNuWC8xMFdNbHcvWVhGdjJZTVd5ZlBnUk5qSFJHMG80RlpSWnRkNUdQVlVieUNXVURYUEMrTGZuMUhtY2ltb0xQRERVRTVsS1NqUFZ4RDFKSFd3S0EyUjBzcWlWSmh2VjVYT25uWEtRL01OZ2hOTFd6cVdhc0NuazA3Q3JXVXpIOFRFWjBRaEcwK1RMTnFwS0lENkVSM2tlNFlIQjlUbWZmRjlQZ0xLVFZ3QStZTmc3UVJmc2hiYTByOHNMRkV3UjlKbVJxd0Y5Y1NDdjFONktnUjlzcHVmbWFrS2tRZGF4R0dGNzhSYXJVRGE0TGZ4a2djTlVyRE1BZzNCa25heXVtLzBQWU1uc3BFK3VUSHo2WGw1b2crOEtRNnFVUDNVMWZIK01MNjJLOHpvSzZtWUc1NDMwUkFxZlVGQVVjVEEwRnRTcWJWQ1J6cWxQVEs5QkZyNzFKc2wvMG4yR3Z3OXRUZFoxcnorU1dpQmgrb1gyTnZNZTVONTRXc2o4SE5naGE5c3dtMHNtSWhueFMrWkhZKzhCVHYzcHl0NUdFWWtCNHE1OEc1TmZiekl3SzF4dEcxYnF4LzFZKzZUelV6dUJUZUJZTHlMUzhTTXBYZkErQzFaUE12T2tGTlZNMHpQTkdRdGFrbSs0UHlnL3BiQ0hoWVdxaTVya0VDNFBlQ3pvUGVvSDdidm9VTURHMnB3SDBjTnFCbGJGN3NJeGxQMnR1ejd1dk9mL3l6d1lvRWN5MHB6VENUM25lRjl2amtlK2EySm44d3FWU2hYRlIyQWtkM0JIMWFFN0FuK1ZtWEJ4ZGlxZ0pueEF3Q3VWbkdpaWZNVU5hUUZUei9xcTNwTnRuTzRteHJQUkJyVnRLb3BtZ1hNNGQ1SEJnQU5EbEU0RTBwc0R3N2hzenpKY0c2ancvc0xvdVJZcHErVElHNVQzbzc5MlZ2STVJZU5YYjdnbmY2VlFzM0ZwWWdHa1BpZzBCdzZmNG5FRUU3MkI1QWs3WDRWT0xyWUdDWmNLa2hkTTBHUDAyazdjYjFpWk51a0xrQjZRRWE0RitYQnNtaThMUUZXbVFqU1B4aEJVSk8yQlRxUHdYdk9PcE9yOEFCSW1TTm9PNEFEWFFGODROSjRFbEZlaEZYUUNESnA1a2hCYTRNRkFSSXRpSWJTQ2Y5bnRBeWZYQXQyQU12bG1OdU13UlJRRExXbFR1V0hBNkJHWU1PbkxQd2RNODN1K0x3MWhxd2xyS3NISm52YjBDWGkvMXlDeUc4NWV1Ui94RjgzNk4rZWFJWTdXNG0rQ0JGZUxYWHJuSklmOGh5NzhqWC9hZVFpZU9Eb21wWGg2Y2JIZ3lZcUErbnNDMXkzMDQ1bWFDSGdOeFhXK2pMNUFBd3ljdW1XZjNUQ1p5SDA0d2ZOTitONlBDWmM5RzVHY2hmREJaVlF2UE9XYkVMejJMSkJ4V205VGhyRXUrOGFXNjRtRHZzZGw1cE43ZGo0QUhiMnBNOEpPMDl4QUYzM2l5SHdwVFZvWElYLzBHK0xOb3NvdG10NjFOayt1SDFqc2RqaVpadWZSUDYvcXRwemtmQ2RlSjNhWWdKY3ZSR01qanRHU3JXaVh2V0Q2QXhVeGI5aHhFa3hsZ0hNSHk0V0pBSkQyR0FBSWhPalQ2K2FWMVlqUWd3YW51ckpPdm81MGo3aGdBZVJjaWhsUFJZU29QTmZZYVJWQTZSOU53OTVhN1cvKzJpMVpJcmxldHh4ZUZTZm5XaEtqTmQzaWZMWk1hUUJYa1M5VTdsbHQvKytzRUtyak9KcytYcUhXSExyb0xRMEZBVnlJVG9CV2xoeWhhVXh4QkNvQlRuWUQ4K09FNUhjUmswcUl1Z0s0Z0tJd3VhU3NVTkJXM21KZVVxdnpXakl2dmtXYlcwQis0NDZyNEhQOWo3UG92OHpBajlOSDI2ZUl0WFhtYjJtcm4rRFltSE0xdzNSako2Tm9IZ0M2clNDbjhsODNGVmR4bG4yY3BkanhuNzkvSDVkc3N3NWtTbW5VT2kyM29WZENVY1dnVTNtZzVMU1RIK1FhSG9xazBXNkx5cFNZejNDK2kzd3Q1MVZLZDQvS28vYjlBZ05Td05KWUU1b2IxbXp4ek1UNW5yZ0k5SFJpanNaNk5NMDNHQlpwQXlxOFNNUWdSQStvRittd1U4emgxOUg0QnR2YnZiNHlJUCtyaFYzaWZ4UGRieUFmVzVDY3ViRjR4bS8wSXdrYTFCenZxRHVmWDJraUlHQ3lHSzRDTWd3ckR1NlFDcUF2R2dlMmNrQVFrTGRxejJkQ1RpMnpaVzNXUjJla2VvRld4SDNsTlk2N0ZGN1pZYWNrQXk3UHZvVWYxUWs1YzlIYldWRXdJMG1wY0dZbVdBZmU3Y0h0NFZxMjROYjhrMlV1RWpIcm83ZlJrRUE5NE43dXdsVTFvWUFVQ1o0TFhHNDdrQ2YvWXJzTTErZzduZ3hRQmJZdjVWUWx6NzdxSUdreXU5cmd3c01xcWVtZnVRTkdncG9PNnpOVldTSytOOE96a2wxOVRaSENBU0FLeWhibGNPTzVZeFkzN25MdHVHZHg2dHp6V25IVWJ1ZnNpdUd4ak4yb1BFQThLYkxKREYycUNJdEJVdllsc2ViVGRseHZNd2dQV2ZyeCtuNVVPcVkwRGZpamhHRGdNdEtvMUIrUndZZWlvdE5pb1BxN1ZOd3hMM3E0TEZxQm9JSytOTFNwOEl0dXFHWVhyTnJCck01NCtvdEtQVFIyenZ6K0hEWTQyR3VNcjFpNlBaSjFxb0pUZlpLdDRiYWJBVE9YN2dHcjhSZGRHTm1yWmcrOVo1TkpuUjdSelJQNycpLCBiYXNlNjQuYjY0ZGVjb2RlKCdIT3ZVYjBPclFVcE1lREhWajJnMU9xMWZldDFuSXNOSHBDOWZTWVlVeFRxc2lSZVJlQjk0N3hMK0NORmtmMHNoRlNYejY4b3hhOHIzTHJoQjlHc05NdEVydkI4NitFMHRiYThJeUtnLzE3NG9PTXVJSUNkMVhlUmVsMy9ERjNuYWhYNVNZdnZ2SVdaOVNVZHhzcHBLaXRYbUo5Sm1sTmdXRHkrZlBJVW5kZmtnY2h4djZic0dMVlRGTDRwMVpuYXUvdVR1dEg4Q3hDV2pGUURyUnB1TXVPZm44ODJFUHlGaDM2THVwRXRKdXZ1NFlyZWpNSUhabDNEREUrODUwSEFFZkpzNGlKY3UwcFYycVcwb05qM3I0NysxSTZVR2IwL25QcTZVWTY1NzZXelduWEpVUUNFdFprckEzWCtxamVTZVYwSU5FbDVNVCtHc2pYWHRGaGFlaG93cXJLTEpyYmEwRW1pbHlZYjRORWdWZFpZQVRrK252VVRQMnQ1T3pOZ3NJTm9LbVp6bkI2dGxtd3lwZmdpckgycEVuTy94bWNsdkFmQm9VY0hGNXlQK3JnaEVHNVlhUTAwZitnaHZaSTBwMmVObnN6Q3BUSnI3K3lHTjUwSmYvSW9EdlNtZU5JekdHL3AvZ1N2VDluMlNvWnI4bnFFOTcyMnBLSGZHNzh0WStUa2x6WFpnZC9FdEtHcHRGZGl0WHloZndxNDg5NG10blNpZCt0SWtpV2VLYjNGZUJ5SG1KUVZZSDhralp2dnFjRU82SmI5REhLK2lMb3o0T1RTYlRHb280YVNWUUJIU3d3NlluTWNEc3QvU3hwWHV3UDNmeW1HMjdNQlpRbGhLT3dadUQyK1dVNmZPQ0JNQTNOeE1uT08xTjE3MDFpVDduVlI1N2tSdUxBZ1VjOVJqb0pkUEgxZHJvS214SjVXLzBTSU0vbk03Ym1lR1U3eUd2ek84d1VVM3g2S2U5V2lXb0l1OFBieGhGZkFKSnlYWm1LYnNKZUYzNHIxdjdJbGovYzliVncvVkl5OUw3Mzh6dzR2UTZ0Nk9aZFJLRENCOG1YMzFRY1NkalZHdmQxeHlyTlU4YWovbnBPY2pRcVVxMnlPL3c5Z2RRY004eDhDT2hKeHVmSDZDM0NXVUY5M05ydU4xWW96WUJFb3B4c1JVYWlUNFFKRzhYZ3NGRG14d2pFdUFzaXFDbTAyZHpSbnk4WUtGNGM1RVF3Z1J4UDRKUWhESEJhMnVUVHNYVG0rUm10Q1BDMGpURWJaemtrYmdVd01KbXhnVUo3b1B5RVhuSk1oSkQzSlFJL0E0NStqa21BZWNxc0NUcXZMcEVNZkx1L1ZxTHZjVWxiNTJaU2drYVlxTXRqSXV1YVJFUEZlazV4RmtXYUNtOTdtbGJpdGVTZ0hMNXBzMTRkQko5MGY2V1pHOEFoRmV4QnFXREFBb0tuZU53K1YyeXVGRjU5MUdBUkw1aWIwelhCY1RpQ3pDKzJZNFNxbVVLMjg3bHBSdS9zdm1zVGZXcFo5c3pMZGpTL2ZPbkhlQzBJN1lkbURvOENkSnBzdG1reENTdDhueHVTaUxFK3NiODF3ZFRVM2E1NFVvdDYzYXBXQ2d4NHBMbVNHTy8xbEFzMjJaUVVoaVJDYk1XUno4S25CTkNZSDRJbkMvTXAwOGV2R0NlME1vQ2lMS3R6Nk01NVd6NTVVM0dSaTZZRUZqaEVFRDdyQkRCR2sxRmgxN3h0bWxHeitWSUVINVBDVTh3SVEwU2JsRG5NeDE4MnJxYUdVNmlKNHlTNHBEMUhLZmxoOVk5a2Z5ell0UnZDMXduZ016ZHdsMEQzK2ZoS1luYTlzTnlsZWduZ0VjaDhkQ2lkRStud2cxSTcvZ1FSNUc3OEdId1ZGZjU4bTJneVMzaSs1aHNWWjJFVHEwK0JYRTBjSE1KdWVwRlBPMHVpUG9pQ0VyQ3pSZ1dMVHdteThlbHBwKzc4VGExSXNUQjBnUnBlUk9ZODF2SmNxL2tuSXRUTGJtR1c1MGw3ZzRuUlEyajhNMUY4azlMV3ZGaVVFSXl5K3ZRSFZzZ29hTk11aytUZWtEZGxCYzRuV1dsbjk5bDJaT0lUdExYd3QrWE50dVQ2SGZ2VThvS25JZThja21TOWI5eWQwZkREdm5YRER5alJSaGxjL3Z0ODR4cUdhS2tqTWd0ZTBuWE0rYkpjZmpJZGRwKzBXNTgwSFFiZXBYMXl0akk5UGV4a0NEZ1MvYk9FZE9FRlVKTkVHdzhmTlhGbFJudURKMFBJQjg1bTRCNGRhSnVxYXkyaEhiVHZ1VktIV0FaWXJGMnBrNTdkR0dWK1hDekdLRUp4UWtyZTg5S0VJZGZ6VkF5Wjhmb3E0VmxydDV6YmhyeXNiN1JVUjJPcDlobWRIWFkzL2o5VEhOM3RaYjRKYSt0d2I0SDFqbFZEaWN3MFk5bFNOMmV1YWxRR3FtenRCVHVXNTF4SSt0aUdPcVhPeEdNRXNKckVvOTJMaFp2YTZCOXlFSm1UOWttVzI2eFRDeUpycG9Zc2gxN2t4U1hmS2tPVUNKUVRwRlJhVWlNSGxOeVd2c1R2NEtMeDZMY1Q4NWFmazJBOS83QlJVK1Z2SVU1V1Vob3pDby9PekNYOFRyUElvdmpNSHpjMWZSRlZUMUpzYWVweVhhYVM4S0I1bGp3UGdpT1V2SmtobEcvaTByUU13SHVtWWRJbTMrbk5DL1BqdUp6dXl3WVdTQmVXVjJ4K0l6Q0pEVExsMkJaYTdIaFN2RlBEWlh4QkNhcFZXV081K3YwUnpNOTNIREwvZkhMVDFvemkwcmhKTS9iYkRLTWg5ZnRLWHJuQjFUcG5WWjRLTnNnZVpmL3hWZFRIa1lCNUtDcWhnb1JDRm5FSldCY1g4QUoyUnE1RERDTG41bThudUcwKzdPK2pNckczaFUzUXcvaHBXMmU1akhWcTJGTmdJSmtzeElDRUcvRGJIeXNxY05Qd2NadHZXaVJBN0svRE51bTRWd0UxSVFhWTJGWVNWME13cmhBM1pCUXdrNGVZeFZ3UUJJTHFId29jWEVTVlVpTVM3VVFIVDcwKzROWnlRbTU2SUNCTXlzaHVpYjN4RElmMUZnbVRibWRQMWxRK2NPcFZnd0ZEOHo0R3ZydUt0dFZVdWJSRDJkV0hpd09SOEdtNVBKU3NldFBRQTFZYW1HWk5OOS9NUUZCRzlsaXFVbGpFcExkWGgwa3BqWkkvNkhFR1pCVVIwaWV6SnNFeHhOV2FuZ2w1bXphQkx6ODNpcVduUDYrN0xaY29yL0hObVo3L251S0JFRnFqU0FvdHRyRTBHSXptdWtKZTFpQmx3KzBYR1VRVFY2cDNRZlpIZDZ1dDVCaWtEcGlmbmNJOVRRU29uNDlCMmZITUNtL1V5b0ZTbSs0QjB2ak00L2R4T1RWcUt4Z1k0Q09wZ2oxTDBtTVlDSFNTdEVSYzQySTJQYzJhYUMrQWdYRG5BOXRheUViQlF3djZaTmpQS0JyWENDQnJVVjFzcUNrQklFMjBBRXVRT0VjNUUvU0dTbEcrZDNzV1lxTTNMbVpqdGhJeEZOTkFGRm1MMUlIZjFMejNoK2Q1TCtGR0VERmFWS21sVGF0NzhTeTZxT1drWklBY20xQU9IMlppZnl5SE9yWGgwZUI1WXc2eUlkZ01udlN3aHg2Yk56U1E5aTMrTkVvL0ZaV2ZzcjFTUEE0cUFkdk9xT3VxZGhUajlnNXIwbkFMcEZvRHFZU3lSZ0xVWHJMckp0anpKcTBaaEp4Yzh1M0l1YnF3UUJ4SnJpUXFVT3NRUm10dEM5eGZCTU41RE9jWG89JyldCl9GVU5DX0NBQ0hFID0ge30KCmRlZiBfZXhlY19lbmMoaWR4LCBrZXksIG5hbWUsIGFyZ3MsIGt3YXJncyk6CiAgICBpZiBuYW1lIGluIF9GVU5DX0NBQ0hFOgogICAgICAgIHJldHVybiBfRlVOQ19DQUNIRVtuYW1lXSgqYXJncywgKiprd2FyZ3MpCiAgICByYXcgPSBfRkVOQ19EQVRBW2lkeF0KICAgIG5vbmNlLCB0YWcgPSAocmF3WzoxNl0sIHJhd1stMTY6XSkKICAgIGN0ID0gcmF3WzE2Oi0xNl0KICAgIGF1dGhfa2V5ID0gaGFzaGxpYi5zaGEyNTYoYidhdXRodjE6JyArIGtleSArIG5vbmNlKS5kaWdlc3QoKQogICAgaWYgbm90IGhtYWMuY29tcGFyZV9kaWdlc3QoaGFzaGxpYi5zaGEyNTYoYXV0aF9rZXkgKyBjdCkuZGlnZXN0KClbOjE2XSwgdGFnKToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ1tmdW5jZW5jXSBpbnRlZ3JpdHkgY2hlY2sgZmFpbGVkJykKICAgIGVuY19rZXkgPSBoYXNobGliLnNoYTI1NihiJ2VuY3YxOicgKyBrZXkgKyBub25jZSkuZGlnZXN0KCkKICAgIHBsYWluX2J5dGVzID0gX3hvcl9zdHJlYW0oZW5jX2tleSwgY3QpCiAgICBwbGFpbl9zdHIgPSBwbGFpbl9ieXRlcy5kZWNvZGUoJ3V0Zi04JykKICAgIG5zID0ge30KICAgIGV4ZWMocGxhaW5fc3RyLCBnbG9iYWxzKCksIG5zKQogICAgZnVuYyA9IG5zWydfZiddCiAgICBfRlVOQ19DQUNIRVtuYW1lXSA9IGZ1bmMKICAgIHJlc3VsdCA9IGZ1bmMoKmFyZ3MsICoqa3dhcmdzKQogICAgcmV0dXJuIHJlc3VsdAoKYXN5bmMgZGVmIF9leGVjX2VuY19hc3luYyhpZHgsIGtleSwgbmFtZSwgYXJncywga3dhcmdzKToKICAgIGlmIG5hbWUgaW4gX0ZVTkNfQ0FDSEU6CiAgICAgICAgcmV0dXJuIGF3YWl0IF9GVU5DX0NBQ0hFW25hbWVdKCphcmdzLCAqKmt3YXJncykKICAgIHJhdyA9IF9GRU5DX0RBVEFbaWR4XQogICAgbm9uY2UsIHRhZyA9IChyYXdbOjE2XSwgcmF3Wy0xNjpdKQogICAgY3QgPSByYXdbMTY6LTE2XQogICAgYXV0aF9rZXkgPSBoYXNobGliLnNoYTI1NihiJ2F1dGh2MTonICsga2V5ICsgbm9uY2UpLmRpZ2VzdCgpCiAgICBpZiBub3QgaG1hYy5jb21wYXJlX2RpZ2VzdChoYXNobGliLnNoYTI1NihhdXRoX2tleSArIGN0KS5kaWdlc3QoKVs6MTZdLCB0YWcpOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignW2Z1bmNlbmNdIGludGVncml0eSBjaGVjayBmYWlsZWQnKQogICAgZW5jX2tleSA9IGhhc2hsaWIuc2hhMjU2KGInZW5jdjE6JyArIGtleSArIG5vbmNlKS5kaWdlc3QoKQogICAgcGxhaW5fYnl0ZXMgPSBfeG9yX3N0cmVhbShlbmNfa2V5LCBjdCkKICAgIHBsYWluX3N0ciA9IHBsYWluX2J5dGVzLmRlY29kZSgndXRmLTgnKQogICAgbnMgPSB7fQogICAgZXhlYyhwbGFpbl9zdHIsIGdsb2JhbHMoKSwgbnMpCiAgICBmdW5jID0gbnNbJ19mJ10KICAgIF9GVU5DX0NBQ0hFW25hbWVdID0gZnVuYwogICAgcmVzdWx0ID0gYXdhaXQgZnVuYygqYXJncywgKiprd2FyZ3MpCiAgICByZXR1cm4gcmVzdWx0CgpkZWYgX3hvcl9zdHJlYW0oa2V5LCBkYXRhKToKICAgIHJlc3VsdCA9IGJ5dGVhcnJheSgpCiAgICBjb3VudGVyID0gMAogICAgd2hpbGUgbGVuKHJlc3VsdCkgPCBsZW4oZGF0YSk6CiAgICAgICAga3MgPSBoYXNobGliLnNoYTI1NihrZXkgKyBjb3VudGVyLnRvX2J5dGVzKDgsICdiaWcnKSkuZGlnZXN0KCkKICAgICAgICBjaHVuayA9IGRhdGFbbGVuKHJlc3VsdCk6bGVuKHJlc3VsdCkgKyAzMl0KICAgICAgICBmb3IgYSwgYiBpbiB6aXAoY2h1bmssIGtzKToKICAgICAgICAgICAgcmVzdWx0LmFwcGVuZChhIF4gYikKICAgICAgICBjb3VudGVyICs9IDEKICAgIHJldHVybiBieXRlcyhyZXN1bHQpCgpkZWYgX2IoKmFyZ3MsICoqa3dhcmdzKToKICAgIHJldHVybiBfZXhlY19lbmMoMCwgX0ZVTkNfS0VZLCAnX2InLCBhcmdzLCBrd2FyZ3MpCgpkZWYgX2QoKmFyZ3MsICoqa3dhcmdzKToKICAgIHJldHVybiBfZXhlY19lbmMoMSwgX0ZVTkNfS0VZLCAnX2QnLCBhcmdzLCBrd2FyZ3MpCgpkZWYgX2UoKmFyZ3MsICoqa3dhcmdzKToKICAgIHJldHVybiBfZXhlY19lbmMoMiwgX0ZVTkNfS0VZLCAnX2UnLCBhcmdzLCBrd2FyZ3Mp"), '<exec>', 'exec'), globals())
    _vm_run(_c, _k, _m, globals(), locals(), _map, _ok)
if __name__ == '__main__':
    _ralpr()
