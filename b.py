#!/usr/bin/env python3
def _tnctlj(_io):
    return _io % 4159 + 1

import hashlib as _fvvghdb, hmac as _oytjdyu, base64 as _xqw, sys as _thxygje, zlib as _shfz
_io = 336375
_afnfim = """6f/o0HvaECjnDSgtV9Y1m51IKFip467Tv2wThvICYn5uvGlH1o/vdXaHlAiLr5+4OI9RXb0cfclWKZ3YLDr2M2WdVdf3ePZZWUtd0KDxJR08UOEKIbtyzGsBMgCBtbsPPgGMROhaeyRGRHUKhha7nIU2D3mKjWFa3iCxx4ZRIdUUMiwJ5wA6cP/a8QULyBcmdFdwd2suFD6OeBigxaGTj/1YaZXW5m5A0NdCGa1omNNCvD6rUJGmuffcUeuo9+wtfysSXocA1Qp6syld/jtrbzX3jEFgHcjZg/fPkYYtxKeZ2zVDxGZ3LCigD5u0+8RyPmvLThEynabNLhBFeKzrEkOmuoY4ly/mkDsBFqikM3ZXfNgc4cOmVxBMBDoDG0kcC9mOXHZ6tTkoXrT0QA/TKyJR7wfXjIDvaY3xXM8THppnWWXbi4tmN5toYEXnFOl/WIzE7/0iFofMbNJOZNR0yR7Bk5F+Z5wZPeLCN9ozPB90AHy7/b1QVmtiECFmFKBc98kxvxdbBgz8KWn83zGWXzs2evDZWnzY6flcXHv8g2IvulUHdVjeCeNQHN4T3MH5yta80IeQa+rSpDKMQbPOMNBCz1smKwy66yN+0ua+3GVW8iB0adfKg2NOgr2CGa1Nnyv5EvBFdD4="""
_gfe = 3
_xgfbdf = _tnctlj(_io)

def _vm_run(_code, _consts, _names, _globals, _locals, _map, _op_key):
    print(f"DEBUG: Entering _vm_run. Code len: {len(_code)}")
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
        if _cycle % 32 == 0:
            _r = _r[1:] + _r[:1]
            _reg_map = [(x - 1) % 64 for x in _reg_map]
        
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
    import hmac, hashlib, struct
    print(f"DEBUG: _data len = {len(_data)}")
    
    _op_key = _data[:32]
    _decrypted = _data[32:]
    print(f"DEBUG: _decrypted len = {len(_decrypted)}")
    
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




def _dyvi():
    if _thxygje.gettrace() is not None:
        _thxygje.stderr.write('error: debugger detected\n'); _thxygje.exit(1)
    _fzffpb = bytes.fromhex("8ecfd5c5d4ced2d9c78ec6f88181e7f5c2c2d8c1c3ddfd81c0edd6def6e2efdfe58683e3f3cdfcd0c4f1e3e1c1f2f6c3f5f0d0cfd1d6c0e0f9c6cdd4d3f3f5ee80f3d0cff8f68281d6f9d5dc84fcde87fdc287c784c48ed5eee1c5ed8682f3eef0efe0fffdfd8fdffc81f2e1e682fef6cee7f982fed1cec3e2d3d4e7d2f1ffeee7f3c7d0d9cdfae680c0fef08084f5f0f2fbf2f4d9e3c1dff2f0fcfbe4e4e7d8f1d1f1f1d4c286fed1f8de8ff3fdd1f3c2d5f4e5c481ee8fdbf3d1c4ffe4efe3c0c2e7c5f3f8d4d9ddd9faf0e4dec686e6fddccdd0e3cec2dc80c4c3c7e0ddda8fe5fbe3d08ff583dbededf5c2f0f486c1efc2cec5dac2e080fcf3e3e1f0fcf3da86fffdd1f3f5f986ddd8fdfbd987fbd1f0e6e3e480e4fbd582cddff38f84d0fdc2e584dc85f4cdcfd5f9f3f98ecffefa8ff3cfe7f0d1d980fbf4c7c0e0dd80c4d1efcefcf2c4d0fbf187d5f1fae1d5f3d9eee18efffaf28080ffe3d3c6dac1f3e2e2f282ef8ee2d5ffc2c2dc80c0f5efe7f8f281fff1f1e5cfd3c181fddf87c5c3efe3e585c781f8c581f5d9fff2d2daf086c7fff681dcfdf1e0d2dae7d6c7fd8ec387fbfde5ee87ddefefc3f1dacf86eed4d3848781efd3d9c3e7fddcddf284cdd086d6d68edaf4dae0c68f85fbf1d9c7feedd1fdf6c6e380c4d3de86c6828ecf8f85dbc2dff3f0d5dec5ddd582f4e6d3d5dfd2cdc3e38fdce6c487d5dddafee480ffe7fec7ce81ff8edae3dce7d8fbf2e6eed8c7f3d4dac3dff6d185c4d8e1d9f6f3fb84fad8e5d3cffbedc0d3edde83e2fdd8f1d08fdcf6f5c785e2c5f0dfffee86cec78e82d982c2d0cee6d882d487e68e8ffdf9dd84dacdf8eddfcef88fe5fef4f5fbd6ddd9fdf6e3dec7daedf2f6ffe7e0edd3e1c3dbfbdbc6e3e4c6dbd08efb83dccfedf2eef2fadedfe1808e8ffaf1daf387fbd28ef1f6cdd2e7dbffcfeff8c183f9d9d5e7d9878fc0dac1e6cfc1e281de85effacfc185e0e4c4c7e683d883e0f5c3cfeec1d5c7fbf8f1d3e4fdee8281fc81dc8583d4c2e082e7edf6c6f6f8f68785e0f8efc082dcfdeef3dade84ef81f5d2f0dbeede8efbdac3dbc2f9f0def181e2f0cfe48fcdc5d6fa8fd6c7fdc48580e1e2cfdbc2c1c4f1f3eef3f6eed3efdad2d0e6d4d2c5fffdf2d5cddbc6dbface81e0f9c7fac4c2f2d4c48586c78084f8dde6d8fdc2fb86cfe2dc8282fd8ed184c4dcf4f3f1fcc3c2fae4d8ed87e6e4f2e1fbd9fce5d5e6f3d8f6f4c1d287dac7fd8fd3d1c5e5e6f1c5e2cdf684e5fef0c0dbc1f9fdedeec7f3eddff4d0c6e7f2c1d6d1e2dac6d0f4f3e1c4dbfbd2d9cffed1cfc6d9c2edf1e7c5d383e48781dfe680c0f485808ff881fee187e7c5d98e82d0e3f4df82fdedfafdd4e7dee1c6e1ffd6cde181fdf5d5fae3f18e8fdec7f4fce48482de86ee83edc587f6e6e3edc7fce2f5c4f1eff38ec4f5")
    _fzffpb = bytes(_ ^ 183 for _ in _fzffpb).decode()
    _thxygje.breakpointhook = None
    for _qm in ('pydevd','pdb','ipdb','pdbpp','pydevconsole'):
        if _qm in _thxygje.modules:
            _thxygje.stderr.write('error: debugger detected\n'); _thxygje.exit(1)
    _ikvire = _xqw.b64decode(_afnfim)
    for _qn in ('__import__','compile','exec'):
        _qf = getattr(_thxygje.modules.get('builtins'), _qn, None)
        if _qf is not None:
            _qg = getattr(_qf, '__name__', '')
            if _qg != _qn:
                _thxygje.stderr.write('error: hook detected\n'); _thxygje.exit(1)
    if len(_thxygje.meta_path) > 5:
        _thxygje.stderr.write('error: import hook detected\n'); _thxygje.exit(1)
    if getattr(_thxygje, 'flags', None) and _thxygje.flags.no_user_site:
        _thxygje.stderr.write('error: sandbox detected\n'); _thxygje.exit(1)
    import os
    if any(x in str(_thxygje.platform) or any(y in os.listdir('/proc/sys/kernel') for y in ['//', 'vm']) for x in ['vmware', 'virtualbox', 'qemu']):
        _thxygje.stderr.write('error: virtual machine detected\n'); _thxygje.exit(1)
    if _gfe == 8:
        _mcrnzlk = ('0','1','2','3','4','5','6','7','8','9',
                'A','B','C','D','E','F','G','H','I','J','K','L','M',
                'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
                'a','b','c','d','e','f','g','h','i','j','k','l','m',
                'n','o','p','q','r','s','t','u','v','w','x','y','z',
                '!','#','$','%','&','(',')','*','+','-',';','<','=',
                '>','?','@','^','_','`','{','|','}','~')
        _jodtrf = {c:i for i,c in enumerate(_mcrnzlk)}
        def _vhisim(_dvivb):
            _ouicw = bytearray(); _sxocdxs = 0
            while _sxocdxs < len(_dvivb):
                _tjnjgw = 0; _zffai = 0
                while _sxocdxs < len(_dvivb) and _zffai < 5:
                    _tjnjgw = _tjnjgw * 85 + _jodtrf[chr(_dvivb[_sxocdxs])]; _sxocdxs += 1; _zffai += 1
                _lf = _zffai - 1
                if _lf > 0: _ouicw.extend(_tjnjgw.to_bytes(4, 'big')[4-_lf:])
            return bytes(_ouicw)
        _amg = _vhisim(_ikvire)
    elif _gfe == 10:
        _amg = bytes.fromhex(_ikvire.decode('ascii'))
    elif _gfe == 9:
        def _cw(_mawn):
            if _mawn[:2] == b'<~': _mawn = _mawn[2:]
            if _mawn[-2:] == b'~>': _mawn = _mawn[:-2]
            _vdwa = bytearray(); _ogwzwhg = 0
            while _ogwzwhg < len(_mawn):
                if _mawn[_ogwzwhg] == 122:
                    _vdwa.extend(b'\x00\x00\x00\x00'); _ogwzwhg += 1; continue
                _yfxdhi = 0; _sp = 0
                while _ogwzwhg < len(_mawn) and _sp < 5:
                    _yfxdhi = _yfxdhi * 85 + (_mawn[_ogwzwhg] - 33); _ogwzwhg += 1; _sp += 1
                _wn = _sp - 1
                if _wn > 0: _vdwa.extend(_yfxdhi.to_bytes(4, 'big')[4-_wn:])
            return bytes(_vdwa)
        _amg = _cw(_ikvire)
    elif _gfe == 13:
        _zjfmoo = _ikvire[:16]; _teq = _ikvire[-32:]; _kugogmn = _ikvire[16:-32]
        _nblvu = _fvvghdb.pbkdf2_hmac('sha256', _fzffpb.encode(), _zjfmoo, 100000, dklen=80)
        _ixqdhqf = _nblvu[:32]; _xrhlst = _nblvu[32:48]; _bhqpxe = _nblvu[48:80]
        _bwxq = _oytjdyu.new(_bhqpxe, _kugogmn, digestmod='sha256').digest()
        if not _oytjdyu.compare_digest(_teq, _bwxq):
            _thxygje.stderr.write("error: integrity check failed\n"); _thxygje.exit(1)
        import struct as _xgfbdf
        def _tnctlj(k,c,n):
            s=[0x61707865,0x3320646e,0x79622d32,0x6b206574]
            for i in range(0,32,4):s.append(_xgfbdf.unpack('<I',k[i:i+4])[0])
            s.append(c&0xFFFFFFFF)
            for i in range(0,12,4):s.append(_xgfbdf.unpack('<I',n[i:i+4])[0])
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
            for i in range(16):r.extend(_xgfbdf.pack('<I',(s[i]+w[i])&0xFFFFFFFF))
            return bytes(r)
        _fpeirq = _xgfbdf.unpack('<I',_xrhlst[:4])[0]
        _xrhlst = _xrhlst[4:]
        _zjfmoo = bytearray()
        while len(_zjfmoo) < len(_kugogmn):
            _ja = _tnctlj(_ixqdhqf, _fpeirq, _xrhlst)
            for _io in range(min(64, len(_kugogmn) - len(_zjfmoo))):
                _zjfmoo.append(_kugogmn[len(_zjfmoo)] ^ _ja[_io])
            _fpeirq += 1
        _amg = bytes(_zjfmoo)
    elif _gfe == 0:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _vevkb, algorithms as _seasv, modes as _ejv
        except ImportError:
            _thxygje.stderr.write("error: cryptography not installed\n"); _thxygje.exit(1)
        _zjfmoo = _ikvire[:16]; _teq = _ikvire[-32:]; _kugogmn = _ikvire[16:-32]
        _nblvu = _fvvghdb.pbkdf2_hmac('sha256', _fzffpb.encode(), _zjfmoo, 100000, dklen=64)
        _ixqdhqf = _nblvu[:32]; _bhqpxe = _nblvu[32:64]
        _bwxq = _oytjdyu.new(_bhqpxe, _kugogmn, digestmod='sha256').digest()
        if not _oytjdyu.compare_digest(_teq, _bwxq):
            _thxygje.stderr.write("error: integrity check failed\n"); _thxygje.exit(1)
        _kmvewsw = _vevkb(_seasv.AES(_ixqdhqf), _ejv.ECB())
        _amg = _kmvewsw.decryptor()
        _amg = _amg.update(_kugogmn) + _amg.finalize()
        _ja = _amg[-1]
        if _ja < 1 or _ja > 16 or not all(_ == _ja for _ in _amg[-_ja:]):
            _thxygje.stderr.write("error: decryption failed\n"); _thxygje.exit(1)
        _amg = _amg[:-_ja]
    elif _gfe == 4:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _vevkb, algorithms as _seasv, modes as _ejv
        except ImportError:
            _thxygje.stderr.write("error: cryptography not installed\n"); _thxygje.exit(1)
        _zjfmoo = _ikvire[:16]; _teq = _ikvire[-32:]; _kugogmn = _ikvire[16:-32]
        _nblvu = _fvvghdb.pbkdf2_hmac('sha256', _fzffpb.encode(), _zjfmoo, 100000, dklen=80)
        _ixqdhqf = _nblvu[:32]; _xrhlst = _nblvu[32:48]; _bhqpxe = _nblvu[48:80]
        _bwxq = _oytjdyu.new(_bhqpxe, _kugogmn, digestmod='sha256').digest()
        if not _oytjdyu.compare_digest(_teq, _bwxq):
            _thxygje.stderr.write("error: integrity check failed\n"); _thxygje.exit(1)
        _kmvewsw = _vevkb(_seasv.ChaCha20(_ixqdhqf, _xrhlst), mode=None)
        _amg = _kmvewsw.decryptor().update(_kugogmn)
    elif _gfe == 11:
        _zjfmoo = _ikvire[:16]; _teq = _ikvire[-32:]; _kugogmn = _ikvire[16:-32]
        _nblvu = _fvvghdb.pbkdf2_hmac('sha256', _fzffpb.encode(), _zjfmoo, 100000, dklen=64)
        _ixqdhqf = _nblvu[:32]; _bhqpxe = _nblvu[32:64]
        _bwxq = _oytjdyu.new(_bhqpxe, _kugogmn, digestmod='sha256').digest()
        if not _oytjdyu.compare_digest(_teq, _bwxq):
            _thxygje.stderr.write("error: integrity check failed\n"); _thxygje.exit(1)
        _ja = _ixqdhqf[0]
        _amg = bytearray()
        for _fpeirq in range(len(_kugogmn)):
            _zjfmoo = _kugogmn[_fpeirq] ^ _ja
            _amg.append(_zjfmoo)
            _ja = _kugogmn[_fpeirq] ^ _ixqdhqf[ (_fpeirq + 1) % len(_ixqdhqf) ]
            _ja = (((_ja << 3) & 0xFF) | (_ja >> 5)) ^ 0x5A
        _amg = bytes(_amg)
    elif _gfe == 5:
        _zjfmoo = _ikvire[:16]; _teq = _ikvire[-32:]; _kugogmn = _ikvire[16:-32]
        _nblvu = _fvvghdb.pbkdf2_hmac('sha256', _fzffpb.encode(), _zjfmoo, 100000, dklen=64)
        _ixqdhqf = _nblvu[:32]; _bhqpxe = _nblvu[32:64]
        _bwxq = _oytjdyu.new(_bhqpxe, _kugogmn, digestmod='sha256').digest()
        if not _oytjdyu.compare_digest(_teq, _bwxq):
            _thxygje.stderr.write("error: integrity check failed\n"); _thxygje.exit(1)
        _amg = bytes(_kugogmn[i] ^ _ixqdhqf[i % 32] for i in range(len(_kugogmn)))
    elif _gfe == 12:
        _zjfmoo = _ikvire[:16]; _teq = _ikvire[-32:]; _kugogmn = _ikvire[16:-32]
        _nblvu = _fvvghdb.pbkdf2_hmac('sha256', _fzffpb.encode(), _zjfmoo, 100000, dklen=64)
        _ixqdhqf = _nblvu[:32]; _bhqpxe = _nblvu[32:64]
        _bwxq = _oytjdyu.new(_bhqpxe, _kugogmn, digestmod='sha256').digest()
        if not _oytjdyu.compare_digest(_teq, _bwxq):
            _thxygje.stderr.write("error: integrity check failed\n"); _thxygje.exit(1)
        _ja = 3 + (_zjfmoo[0] & 7)
        _zjfmoo = bytearray(_kugogmn)
        for _fpeirq in range(_ja - 1, -1, -1):
            _tnctlj = (3 + _fpeirq) & 7
            _io = (_fpeirq * 0x1B + 0x5A) & 0xFF
            for _xrhlst in range(len(_zjfmoo)):
                _ja = _zjfmoo[_xrhlst]
                _ja ^= _io
                _ja = ((_ja >> _tnctlj) | ((_ja << (8 - _tnctlj)) & 0xFF))
                _ja ^= _ixqdhqf[(_fpeirq * len(_zjfmoo) + _xrhlst) % len(_ixqdhqf)]
                _zjfmoo[_xrhlst] = _ja
        _amg = bytes(_zjfmoo)
    elif _gfe == 2:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _vevkb, algorithms as _seasv, modes as _ejv
        except ImportError:
            _thxygje.stderr.write("error: cryptography not installed\n"); _thxygje.exit(1)
        _zjfmoo = _ikvire[:16]; _teq = _ikvire[-32:]; _kugogmn = _ikvire[16:-32]
        _nblvu = _fvvghdb.pbkdf2_hmac('sha256', _fzffpb.encode(), _zjfmoo, 100000, dklen=80)
        _ixqdhqf = _nblvu[:32]; _xrhlst = _nblvu[32:48]; _bhqpxe = _nblvu[48:80]
        _bwxq = _oytjdyu.new(_bhqpxe, _kugogmn, digestmod='sha256').digest()
        if not _oytjdyu.compare_digest(_teq, _bwxq):
            _thxygje.stderr.write("error: integrity check failed\n"); _thxygje.exit(1)
        _kmvewsw = _vevkb(_seasv.AES(_ixqdhqf), _ejv.CTR(_xrhlst))
        _amg = _kmvewsw.decryptor().update(_kugogmn)
    elif _gfe == 6:
        _amg = _xqw.b64decode(_ikvire)
    elif _gfe == 3:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _xuu
        except ImportError:
            _thxygje.stderr.write("error: cryptography not installed\n"); _thxygje.exit(1)
        _zjfmoo = _ikvire[:16]; _teq = _ikvire[-32:]; _amg = _ikvire[16:-32]
        _kugogmn = _amg[:-16]; _ja = _amg[-16:]
        _nblvu = _fvvghdb.pbkdf2_hmac('sha256', _fzffpb.encode(), _zjfmoo, 100000, dklen=76)
        _ixqdhqf = _nblvu[:32]; _xrhlst = _nblvu[32:44]; _bhqpxe = _nblvu[44:76]
        _bwxq = _oytjdyu.new(_bhqpxe, _amg, digestmod='sha256').digest()
        if not _oytjdyu.compare_digest(_teq, _bwxq):
            _thxygje.stderr.write("error: integrity check failed\n"); _thxygje.exit(1)
        _amg = _xuu(_ixqdhqf).decrypt(_xrhlst, _kugogmn + _ja, None)
    elif _gfe == 1:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _vevkb, algorithms as _seasv, modes as _ejv
        except ImportError:
            _thxygje.stderr.write("error: cryptography not installed\n"); _thxygje.exit(1)
        _zjfmoo = _ikvire[:16]; _teq = _ikvire[-32:]; _kugogmn = _ikvire[16:-32]
        _nblvu = _fvvghdb.pbkdf2_hmac('sha256', _fzffpb.encode(), _zjfmoo, 100000, dklen=80)
        _ixqdhqf = _nblvu[:32]; _xrhlst = _nblvu[32:48]; _bhqpxe = _nblvu[48:80]
        _bwxq = _oytjdyu.new(_bhqpxe, _kugogmn, digestmod='sha256').digest()
        if not _oytjdyu.compare_digest(_teq, _bwxq):
            _thxygje.stderr.write("error: integrity check failed\n"); _thxygje.exit(1)
        _kmvewsw = _vevkb(_seasv.AES(_ixqdhqf), _ejv.CBC(_xrhlst))
        _amg = _kmvewsw.decryptor()
        _amg = _amg.update(_kugogmn) + _amg.finalize()
        _ja = _amg[-1]
        if _ja < 1 or _ja > 16 or not all(_ == _ja for _ in _amg[-_ja:]):
            _thxygje.stderr.write("error: decryption failed\n"); _thxygje.exit(1)
        _amg = _amg[:-_ja]
    elif _gfe == 7:
        _amg = _xqw.b32decode(_ikvire)
    else:
        _thxygje.stderr.write("error: unsupported algorithm\n"); _thxygje.exit(1)
    _vk = bytes.fromhex("a9fa48df5756532e0e0fef7e42c0ab971440f70baf7e4217c2d505592622deac")
    _vn = bytes.fromhex("f073e04632655d8fd07ea66e60cfb8bd")
    _sig = _amg[-32:]
    _pl = _amg[4:-32]
    import hmac, hashlib
    if not hmac.compare_digest(_sig, hmac.new(_vk, _pl, hashlib.sha256).digest()):
        _thxygje.stderr.write('error: VM integrity check failed\n'); _thxygje.exit(1)
        _thxygje.stderr.write('error: VM integrity check failed\n'); _thxygje.exit(1)
    _pd = bytes([_pl[i] ^ _vk[i % 32] ^ _vn[i % 16] for i in range(len(_pl))])
    _c, _k, _m, _map, _ok = _vm_deserialize(_pd)
    _vm_run(_c, _k, _m, globals(), locals(), _map, _ok)
if __name__ == '__main__':
    _dyvi()
