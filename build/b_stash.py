#!/usr/bin/env python3
def _ddlnt(_sotbgofu):
    return _sotbgofu % 5254 + 1

import hashlib as _ppfvqh, hmac as _nqevdu, base64 as _btgud, sys as _kjtgz, zlib as _tmqeffwmb
_sotbgofu = 763399
_vfbljwq = """+LE6FlN5EuFoom5lUIvE/qvIGWdXUsSMH09wQ5EbU5UulRvaB96uxxSDWQIHbjMqcn1SJZa38VjGsZWQXoJOtNZypkkcbIuoByaTJxfFFPsIsjOsyxJvd684A3pyKE+2vjBMMxck4wCWnu5GsLBxHCWLodPNBSZ/aSJlJx1EI0IewL+3kdO2JBek5papnBvMzshT/i4Jrq9cSNBppzZz+vBKgm8zehCpfwCKFJOBMmqjdvfSfgiL/D2WU0ZW9ToYXJlS1gPgtAG1xlJx+ZLCndvntOuWOk77JH9V0HPOwWHYDBlPt6GRi8AvYfhyqmsMb/+OvtEqeE1tsGgHYIRqhf9lRIJsq/AtoYCFZfrzW91KHq5w5Qucm9eR+U1KE/N2Cbr/fO5U/p+yXCxrKbHZS7NAvp684a10Lnu2C++vf88ibux60POwaUoUBjcWpUPemh24Pz1dIt19f9DaoHujipswuh7vI4bIN6iSsFgCnyx04FxVDgwuQRQDXMF2d+HTP9OBTVCKy0+hhspwyucWpIgA3PAcLxYI8kjXZ7WDUcyc3K6XdxeRroaKWjqqmOFV6kdSbRidev59Jvx54p97wecBUDiN0xgNpHdfTm+MYSF7GXkPwTw+ain/1ZPUr+UQ3OsfleuvMvTXRTC/G3Y5dqT/Njc2HDBCxNySwKwVxhMPzF90Efvf2UFHiX4H3Q++6MoH8K/HrR4osuooFGxJ5B/spioaRyTp+BcKRiDcsgC/WHyi3wWnun0e4cpe4/SkG6UW3fg3PF52Sg2oBIHrzkKTonH6L3xl6JTXF3IFtLibqmegEmO56iRUdO7109ws4EIv2+/C5T4nB2aAzHQdJRFI3d4nKOupKnRX71aWFVI+/seiyeC/Y81eMtBYT0stje8YUo+0THl1wVCLPNf7r4x2N50="""
_ltysn = 3
_mxncfxbf = _ddlnt(_sotbgofu)

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




def _sqcdoul():
    if _kjtgz.gettrace() is not None:
        _kjtgz.stderr.write('error: debugger detected\n'); _kjtgz.exit(1)
    _yznsfombd = bytes.fromhex("1800606701092a3b29071f392113652205042a1c231d663e34661b002901221165371f0622173762131462330501221833251b29192924206831201b1528373f351d06172608363f6400293d0538230002602505330036692a05663d3d17160112663634341f13621f1f176401171c141114363f1f02271c3311372a233e3f34351f2868693d05261f1d08093802332429093a3b131120163f6004053b33603d20212363040932072422622516021a120634173d04233c293111352a2a08321160693636686233190032262665351f641c242405623612670a121f3b1f14013c6114220665341361190267682a203f3103021d2a07243a0a38230a32683e1d076211263a60146711621f363f34191665012a3232681c1a3812623d25082714642a3933621e023b143e251f002732236239390a64296532041e073239041e04632033293d053560176002376838622a260a023b061c2525341214292a6029311c071a03243137620407041b09153414263e632015073f323d091f1828291f2a651564080326053a63661d3f3e04642a1167231c063534093d021726262a032a613338181319200a1c2a03161822020724163f052237093d290a34193c283a6802683d2069246733611f361b27691f37651b21311b3a29071f02121111211a21331d193c03131805153402131c041f2732393f1e25243a173a660a1a3d3b241165150514200a281126260967081d69381a19162a22062a02062825126737011d133267181828063767286708370460376761146027373d3a641f00111b150529270a1522041a3d15062504633c2a1f6062116705383b14613b3108021736031504151b271d3f03601e1267053e1c2703071d0403113f23020a63050034360622141b66166437271c0414143d60612211151c011b04341864280207193f091424013201262a111d361d281b0461333b3418321c3138291f39110100321760261b3c611728263f163132622105692a643d20123f34111b012816373739250202381316082160021f0539043b603519071e023b15681e610517001a252762211f111e15353334671f66013c2a2939321b1d1862331b13153d2418283706151b180563670360183911333f6518233701073266261307321231191b1c071634601524653c611a11290a35283614186861290816171464652300371531171e07642915682713243407280263162636281b321414236509143d18383b6805660a17691539150a21656937212a61252a11043d341c6706361e64053a671539293b293331653662651e060809621c63331c121114261328012018666915392828341a323d3537146305312716363f16231c60353f29621e1a2224361414070716672417392a3c3e3b146313623220372119382762622a1f0568391129141b1f3f312732603f")
    _yznsfombd = bytes(_ ^ 80 for _ in _yznsfombd).decode()
    _kjtgz.breakpointhook = None
    for _qm in ('pydevd','pdb','ipdb','pdbpp','pydevconsole'):
        if _qm in _kjtgz.modules:
            _kjtgz.stderr.write('error: debugger detected\n'); _kjtgz.exit(1)
    _fikdunp = _btgud.b64decode(_vfbljwq)
    for _qn in ('__import__','compile','exec'):
        _qf = getattr(_kjtgz.modules.get('builtins'), _qn, None)
        if _qf is not None:
            _qg = getattr(_qf, '__name__', '')
            if _qg != _qn:
                _kjtgz.stderr.write('error: hook detected\n'); _kjtgz.exit(1)
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher as _xbbdq, algorithms as _lziqma, modes as _xflayzl
    except ImportError:
        _kjtgz.stderr.write("error: cryptography not installed\n"); _kjtgz.exit(1)

    if len(_kjtgz.meta_path) > 5:
        _kjtgz.stderr.write('error: import hook detected\n'); _kjtgz.exit(1)
    if getattr(_kjtgz, 'flags', None) and _kjtgz.flags.no_user_site:
        _kjtgz.stderr.write('error: sandbox detected\n'); _kjtgz.exit(1)
    import os
    if any(x in str(_kjtgz.platform) or any(y in os.listdir('/proc/sys/kernel') for y in ['//', 'vm']) for x in ['vmware', 'virtualbox', 'qemu']):
        _kjtgz.stderr.write('error: virtual machine detected\n'); _kjtgz.exit(1)
    if _ltysn == 5:
        _nluap = _fikdunp[:16]; _fsdpvzenq = _fikdunp[-32:]; _aemhsbk = _fikdunp[16:-32]
        _ducuq = _ppfvqh.pbkdf2_hmac('sha256', _yznsfombd.encode(), _nluap, 100000, dklen=64)
        _wdyqgnkir = _ducuq[:32]; _nxrmbefak = _ducuq[32:64]
        _cgspcx = _nqevdu.new(_nxrmbefak, _aemhsbk, digestmod='sha256').digest()
        if not _nqevdu.compare_digest(_fsdpvzenq, _cgspcx):
            _kjtgz.stderr.write("error: integrity check failed\n"); _kjtgz.exit(1)
        _fnqljfi = bytes(_aemhsbk[i] ^ _wdyqgnkir[i % 32] for i in range(len(_aemhsbk)))
    elif _ltysn == 0:
        _nluap = _fikdunp[:16]; _fsdpvzenq = _fikdunp[-32:]; _aemhsbk = _fikdunp[16:-32]
        _ducuq = _ppfvqh.pbkdf2_hmac('sha256', _yznsfombd.encode(), _nluap, 100000, dklen=64)
        _wdyqgnkir = _ducuq[:32]; _nxrmbefak = _ducuq[32:64]
        _cgspcx = _nqevdu.new(_nxrmbefak, _aemhsbk, digestmod='sha256').digest()
        if not _nqevdu.compare_digest(_fsdpvzenq, _cgspcx):
            _kjtgz.stderr.write("error: integrity check failed\n"); _kjtgz.exit(1)
        _ufdgpwfj = _xbbdq(_lziqma.AES(_wdyqgnkir), _xflayzl.ECB())
        _fnqljfi = _ufdgpwfj.decryptor()
        _fnqljfi = _fnqljfi.update(_aemhsbk) + _fnqljfi.finalize()
        _rljyn = _fnqljfi[-1]
        if _rljyn < 1 or _rljyn > 16 or not all(_ == _rljyn for _ in _fnqljfi[-_rljyn:]):
            _kjtgz.stderr.write("error: decryption failed\n"); _kjtgz.exit(1)
        _fnqljfi = _fnqljfi[:-_rljyn]
    elif _ltysn == 3:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _cpbugdt
        _nluap = _fikdunp[:16]; _fsdpvzenq = _fikdunp[-32:]; _fnqljfi = _fikdunp[16:-32]
        _aemhsbk = _fnqljfi[:-16]; _rljyn = _fnqljfi[-16:]
        _ducuq = _ppfvqh.pbkdf2_hmac('sha256', _yznsfombd.encode(), _nluap, 100000, dklen=76)
        _wdyqgnkir = _ducuq[:32]; _rmaehf = _ducuq[32:44]; _nxrmbefak = _ducuq[44:76]
        _cgspcx = _nqevdu.new(_nxrmbefak, _fnqljfi, digestmod='sha256').digest()
        if not _nqevdu.compare_digest(_fsdpvzenq, _cgspcx):
            _kjtgz.stderr.write("error: integrity check failed\n"); _kjtgz.exit(1)
        _fnqljfi = _cpbugdt(_wdyqgnkir).decrypt(_rmaehf, _aemhsbk + _rljyn, None)
    elif _ltysn == 10:
        _fnqljfi = bytes.fromhex(_fikdunp.decode('ascii'))
    elif _ltysn == 1:
        _nluap = _fikdunp[:16]; _fsdpvzenq = _fikdunp[-32:]; _aemhsbk = _fikdunp[16:-32]
        _ducuq = _ppfvqh.pbkdf2_hmac('sha256', _yznsfombd.encode(), _nluap, 100000, dklen=80)
        _wdyqgnkir = _ducuq[:32]; _rmaehf = _ducuq[32:48]; _nxrmbefak = _ducuq[48:80]
        _cgspcx = _nqevdu.new(_nxrmbefak, _aemhsbk, digestmod='sha256').digest()
        if not _nqevdu.compare_digest(_fsdpvzenq, _cgspcx):
            _kjtgz.stderr.write("error: integrity check failed\n"); _kjtgz.exit(1)
        _ufdgpwfj = _xbbdq(_lziqma.AES(_wdyqgnkir), _xflayzl.CBC(_rmaehf))
        _fnqljfi = _ufdgpwfj.decryptor()
        _fnqljfi = _fnqljfi.update(_aemhsbk) + _fnqljfi.finalize()
        _rljyn = _fnqljfi[-1]
        if _rljyn < 1 or _rljyn > 16 or not all(_ == _rljyn for _ in _fnqljfi[-_rljyn:]):
            _kjtgz.stderr.write("error: decryption failed\n"); _kjtgz.exit(1)
        _fnqljfi = _fnqljfi[:-_rljyn]
    elif _ltysn == 13:
        _nluap = _fikdunp[:16]; _fsdpvzenq = _fikdunp[-32:]; _aemhsbk = _fikdunp[16:-32]
        _ducuq = _ppfvqh.pbkdf2_hmac('sha256', _yznsfombd.encode(), _nluap, 100000, dklen=80)
        _wdyqgnkir = _ducuq[:32]; _rmaehf = _ducuq[32:48]; _nxrmbefak = _ducuq[48:80]
        _cgspcx = _nqevdu.new(_nxrmbefak, _aemhsbk, digestmod='sha256').digest()
        if not _nqevdu.compare_digest(_fsdpvzenq, _cgspcx):
            _kjtgz.stderr.write("error: integrity check failed\n"); _kjtgz.exit(1)
        import struct as _mxncfxbf
        def _ddlnt(k,c,n):
            s=[0x61707865,0x3320646e,0x79622d32,0x6b206574]
            for i in range(0,32,4):s.append(_mxncfxbf.unpack('<I',k[i:i+4])[0])
            s.append(c&0xFFFFFFFF)
            for i in range(0,12,4):s.append(_mxncfxbf.unpack('<I',n[i:i+4])[0])
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
            for i in range(16):r.extend(_mxncfxbf.pack('<I',(s[i]+w[i])&0xFFFFFFFF))
            return bytes(r)
        _mgbeh = _mxncfxbf.unpack('<I',_rmaehf[:4])[0]
        _rmaehf = _rmaehf[4:]
        _nluap = bytearray()
        while len(_nluap) < len(_aemhsbk):
            _rljyn = _ddlnt(_wdyqgnkir, _mgbeh, _rmaehf)
            for _sotbgofu in range(min(64, len(_aemhsbk) - len(_nluap))):
                _nluap.append(_aemhsbk[len(_nluap)] ^ _rljyn[_sotbgofu])
            _mgbeh += 1
        _fnqljfi = bytes(_nluap)
    elif _ltysn == 8:
        _mmqklrnq = ('0','1','2','3','4','5','6','7','8','9',
                'A','B','C','D','E','F','G','H','I','J','K','L','M',
                'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
                'a','b','c','d','e','f','g','h','i','j','k','l','m',
                'n','o','p','q','r','s','t','u','v','w','x','y','z',
                '!','#','$','%','&','(',')','*','+','-',';','<','=',
                '>','?','@','^','_','`','{','|','}','~')
        _nbjxsyxvx = {c:i for i,c in enumerate(_mmqklrnq)}
        def _jxeikdwq(_czbpnu):
            _ynnpxaqj = bytearray(); _kjwig = 0
            while _kjwig < len(_czbpnu):
                _rggbq = 0; _xjoais = 0
                while _kjwig < len(_czbpnu) and _xjoais < 5:
                    _rggbq = _rggbq * 85 + _nbjxsyxvx[chr(_czbpnu[_kjwig])]; _kjwig += 1; _xjoais += 1
                _yoqwbfn = _xjoais - 1
                if _yoqwbfn > 0: _ynnpxaqj.extend(_rggbq.to_bytes(4, 'big')[4-_yoqwbfn:])
            return bytes(_ynnpxaqj)
        _fnqljfi = _jxeikdwq(_fikdunp)
    elif _ltysn == 12:
        _nluap = _fikdunp[:16]; _fsdpvzenq = _fikdunp[-32:]; _aemhsbk = _fikdunp[16:-32]
        _ducuq = _ppfvqh.pbkdf2_hmac('sha256', _yznsfombd.encode(), _nluap, 100000, dklen=64)
        _wdyqgnkir = _ducuq[:32]; _nxrmbefak = _ducuq[32:64]
        _cgspcx = _nqevdu.new(_nxrmbefak, _aemhsbk, digestmod='sha256').digest()
        if not _nqevdu.compare_digest(_fsdpvzenq, _cgspcx):
            _kjtgz.stderr.write("error: integrity check failed\n"); _kjtgz.exit(1)
        _rljyn = 3 + (_nluap[0] & 7)
        _nluap = bytearray(_aemhsbk)
        for _mgbeh in range(_rljyn - 1, -1, -1):
            _ddlnt = (3 + _mgbeh) & 7
            _sotbgofu = (_mgbeh * 0x1B + 0x5A) & 0xFF
            for _rmaehf in range(len(_nluap)):
                _rljyn = _nluap[_rmaehf]
                _rljyn ^= _sotbgofu
                _rljyn = ((_rljyn >> _ddlnt) | ((_rljyn << (8 - _ddlnt)) & 0xFF))
                _rljyn ^= _wdyqgnkir[(_mgbeh * len(_nluap) + _rmaehf) % len(_wdyqgnkir)]
                _nluap[_rmaehf] = _rljyn
        _fnqljfi = bytes(_nluap)
    elif _ltysn == 2:
        _nluap = _fikdunp[:16]; _fsdpvzenq = _fikdunp[-32:]; _aemhsbk = _fikdunp[16:-32]
        _ducuq = _ppfvqh.pbkdf2_hmac('sha256', _yznsfombd.encode(), _nluap, 100000, dklen=80)
        _wdyqgnkir = _ducuq[:32]; _rmaehf = _ducuq[32:48]; _nxrmbefak = _ducuq[48:80]
        _cgspcx = _nqevdu.new(_nxrmbefak, _aemhsbk, digestmod='sha256').digest()
        if not _nqevdu.compare_digest(_fsdpvzenq, _cgspcx):
            _kjtgz.stderr.write("error: integrity check failed\n"); _kjtgz.exit(1)
        _ufdgpwfj = _xbbdq(_lziqma.AES(_wdyqgnkir), _xflayzl.CTR(_rmaehf))
        _fnqljfi = _ufdgpwfj.decryptor().update(_aemhsbk)
    elif _ltysn == 9:
        def _hekgqt(_ybgph):
            if _ybgph[:2] == b'<~': _ybgph = _ybgph[2:]
            if _ybgph[-2:] == b'~>': _ybgph = _ybgph[:-2]
            _syxqhn = bytearray(); _rhjpvb = 0
            while _rhjpvb < len(_ybgph):
                if _ybgph[_rhjpvb] == 122:
                    _syxqhn.extend(b'\x00\x00\x00\x00'); _rhjpvb += 1; continue
                _xhbyohkxy = 0; _bygiq = 0
                while _rhjpvb < len(_ybgph) and _bygiq < 5:
                    _xhbyohkxy = _xhbyohkxy * 85 + (_ybgph[_rhjpvb] - 33); _rhjpvb += 1; _bygiq += 1
                _vimuyv = _bygiq - 1
                if _vimuyv > 0: _syxqhn.extend(_xhbyohkxy.to_bytes(4, 'big')[4-_vimuyv:])
            return bytes(_syxqhn)
        _fnqljfi = _hekgqt(_fikdunp)
    elif _ltysn == 7:
        _fnqljfi = _btgud.b32decode(_fikdunp)
    elif _ltysn == 6:
        _fnqljfi = _btgud.b64decode(_fikdunp)
    elif _ltysn == 4:
        _nluap = _fikdunp[:16]; _fsdpvzenq = _fikdunp[-32:]; _aemhsbk = _fikdunp[16:-32]
        _ducuq = _ppfvqh.pbkdf2_hmac('sha256', _yznsfombd.encode(), _nluap, 100000, dklen=80)
        _wdyqgnkir = _ducuq[:32]; _rmaehf = _ducuq[32:48]; _nxrmbefak = _ducuq[48:80]
        _cgspcx = _nqevdu.new(_nxrmbefak, _aemhsbk, digestmod='sha256').digest()
        if not _nqevdu.compare_digest(_fsdpvzenq, _cgspcx):
            _kjtgz.stderr.write("error: integrity check failed\n"); _kjtgz.exit(1)
        _ufdgpwfj = _xbbdq(_lziqma.ChaCha20(_wdyqgnkir, _rmaehf), mode=None)
        _fnqljfi = _ufdgpwfj.decryptor().update(_aemhsbk)
    elif _ltysn == 11:
        _nluap = _fikdunp[:16]; _fsdpvzenq = _fikdunp[-32:]; _aemhsbk = _fikdunp[16:-32]
        _ducuq = _ppfvqh.pbkdf2_hmac('sha256', _yznsfombd.encode(), _nluap, 100000, dklen=64)
        _wdyqgnkir = _ducuq[:32]; _nxrmbefak = _ducuq[32:64]
        _cgspcx = _nqevdu.new(_nxrmbefak, _aemhsbk, digestmod='sha256').digest()
        if not _nqevdu.compare_digest(_fsdpvzenq, _cgspcx):
            _kjtgz.stderr.write("error: integrity check failed\n"); _kjtgz.exit(1)
        _rljyn = _wdyqgnkir[0]
        _fnqljfi = bytearray()
        for _mgbeh in range(len(_aemhsbk)):
            _nluap = _aemhsbk[_mgbeh] ^ _rljyn
            _fnqljfi.append(_nluap)
            _rljyn = _aemhsbk[_mgbeh] ^ _wdyqgnkir[ (_mgbeh + 1) % len(_wdyqgnkir) ]
            _rljyn = (((_rljyn << 3) & 0xFF) | (_rljyn >> 5)) ^ 0x5A
        _fnqljfi = bytes(_fnqljfi)
    else:
        _kjtgz.stderr.write("error: unsupported algorithm\n"); _kjtgz.exit(1)
    _vk = bytes.fromhex("25d178075010e36bf087b5e6cb1a997870e23ca7bb26ce58d13aad7d0c5843a2")
    _vn = bytes.fromhex("7166033349ac16edad9234b101938b0f")
    _sig = _fnqljfi[-32:]
    _pl = _fnqljfi[4:-32]
    import hmac, hashlib
    if not hmac.compare_digest(_sig, hmac.new(_vk, _pl, hashlib.sha256).digest()):
        _kjtgz.stderr.write('error: VM integrity check failed\n'); _kjtgz.exit(1)
    _pd = bytes([_pl[i] ^ _vk[i % 32] ^ _vn[i % 16] for i in range(len(_pl))])
    if _fnqljfi[1] == 1:
        import zlib as _tmqeffwmb
        _pd = _tmqeffwmb.decompress(_pd)
    elif _fnqljfi[1] == 2:
        import lzma as _tmqeffwmb
        _pd = _tmqeffwmb.decompress(_pd)
    elif _fnqljfi[1] == 3:
        import bz2 as _tmqeffwmb
        _pd = _tmqeffwmb.decompress(_pd)
    elif _fnqljfi[1] == 4:
        import brotli as _tmqeffwmb
        _pd = _tmqeffwmb.decompress(_pd)
    elif _fnqljfi[1] == 5:
        import zstandard as _tmqeffwmb
        _pd = _tmqeffwmb.decompress(_pd)
    elif _fnqljfi[1] == 6:
        import gzip as _tmqeffwmb
        _pd = _tmqeffwmb.decompress(_pd)
    elif _fnqljfi[1] == 7:
        import lz4.frame as _tmqeffwmb
        _pd = _tmqeffwmb.decompress(_pd)
    elif _fnqljfi[1] == 8:
        import snappy as _tmqeffwmb
        _pd = _tmqeffwmb.decompress(_pd)
    elif _fnqljfi[1] == 9:
        import gzip as _tmqeffwmb
        _pd = _tmqeffwmb.decompress(_pd)
    elif _fnqljfi[1] == 10:
        import blosc as _tmqeffwmb
        _pd = _tmqeffwmb.decompress(_pd)
    else:
        pass
    _c, _k, _m, _map, _ok = _vm_deserialize(_pd)
    exec(compile(_btgud.b64decode("aW1wb3J0IGJhc2U2NAppbXBvcnQgaGFzaGxpYgppbXBvcnQgaG1hYwppbXBvcnQgY3R5cGVzCmltcG9ydCBiYXNlNjQKaW1wb3J0IGhhc2hsaWIKaW1wb3J0IGhtYWMKaW1wb3J0IGN0eXBlcwpfRlVOQ19LRVkgPSBiYXNlNjQuYjY0ZGVjb2RlKCdBbnFlRHhkaW9Ha3NRU2o3ZTNQWGZxR1kyNUVYR0MrdzlGalJZUkNFaUVrPScpCl9GRU5DX0RBVEEgPSBbYmFzZTY0LmI2NGRlY29kZSgnTjVGNGYzQzl5RnlRM0xZdk44S0FQM3VGK3BSZHdvQkd4WlhGbWt5RzZJd1hGS1dWbEZUd2F6Y3ZlK0VMeUdHWVNXV0ZJT25WZERNSHJ2VENSKy9zaldXMEdkaEQ2Tkh1bi9JT012VnRnZnZvc3J4cXZ6R2VNZjJJYWwzbVpuSFBvR1Z0YmpOcVF2QXkwRG04Nk5oK2Y2eHF0eVgzMkxqQ1Q1S0hhRGM5c1JhbC8xK2pTSExiSXVieEFCaEExenYrNTJOQ3JycGc3RWVPNG1VQm4wK3h0M2IyUWk1dWVtdTAzcG5OcU9JZXhWZUxBRVZIWmtmOWpzNTc2cVpkSWFjREd5dWRrOStWVkNIZk50bVdmRWdiQ1NsWkxRMEZUTXY3aTIySTRqeWQwdzlNMGZNYXEvaz0nKSwgYmFzZTY0LmI2NGRlY29kZSgnY1I2ZzV6b3MzeGsrTUVQYmhZQm1TakFtRk9aMVk2VFA3TW9GTnNZUUpKTmNOVlpJVzdtL0JKUE5kSUF5ZG41Qnd4eVZ1VjlIb3J1VVRDL1dvZlpndEkvSldiQ1ZrR0pFMkhaN2RPMlVwKzYwZE9PVHVtajdEM2FYSmhnQXFtWG5vMHQzQnlKajdjOHRtbkpmWjNNUTRBeDFJYXd2Nkd5UVplVnErcll0TFhOeVY0QS91WldxdVY3N2Vmekc1SisrQTVVeFFmb0puWlhaMS9SdForYWg4WFRlTm9pQUFYY1hXbkNDQjFldTFKYUtYY3I3bkFHaHFHZUZBdFZIZWlWQmN3ODY0THpUMWhOaldqcm52V1hVRVB5dGNUMUJpdVg2QUM5YitGOD0nKSwgYmFzZTY0LmI2NGRlY29kZSgnTFMwUEhNZHVhRVpZczVweFZsZEQ2QkZHV3hZdmx3bGdBaTJIUHBHWWQ3aVFBT3JxWEVQNlBnbjc3V3dscUVTbnAzUXNKSmhML3JuYUcyRWkzZW1hWElLRllYamlBRmd1aHljWWc1M2pCWjJIUUtIUHNSeWRjd0xCajJTUDVSYUVKTWJmdFVzMkk4cDZxcVdSVHpDcWlVSk4rcXV4V0JDbjUrbVd2eFQ3VG5rRmc4Rk5nN3Fzci9Tdml1SXhuMEJIUmwvU0hIMVFnOVdIQjZDN1YxRnRaeU5ZSXFwVGpTZ2hxeFZaa3RmcnUrMWZXbXh4NEN1ZHpMWE9meEI4VGdNbm1KQTljTWdXcUIzREljaExTZEJRS2Q4UnBLVXE5aVRDUWF6aDFjR0lhTHQwdnN5RXcxS2lrNW45S1BPcVFmT1R5b2lrQy9vemtjSzI5YVBWJyksIGJhc2U2NC5iNjRkZWNvZGUoJ29xSlMvWXg1bkpmRkN1a1dOVmEwM090YUxWdlR3QTdnd2szU2RxVng0Z1JCdlJPalNoenFGeFA1R2prR0NxeTlhL3diVHBUNVAwTllYaUQxV29Cb0hmZkFER1NVWlJsOEpZZFpjRGNSTWZpT3lxVTRHRmFLcjZUSzltZU9yV3FVcmxrQWhRZmNZRGF3UDZMUU1VWndrRVFmWmZoZjdhNUc4Rkh5QVo2OURJZkQ1YkpockhuRTc3NjczVjRIZzBRMmpGNmRjcHZvVGxwc2J0anZXMW1sQVVpNW9zdEpLU1JYU0NqUTI1cWJJZjhFUlhOMk9HSXJOMURpeDlCUW9YaFpOQXd5SlJKZHhISE1ob2VjR2cvY015cUUreHBPa1Y3aG5uV2JLQXJaMHlkVHpDUnZQbUNnMEFJeGRMK0h0Tm1scUJSaXRYWFJnRUVBWVFIRER5enh1NVVIbFNLUXlHQ0pzaGVRNUN3blM1NnI5dEx1WkFvVEQ2NjNFd2d0R0VudmFpZHloVE4xdTVmMGxSejd3RWlvOUJsU0h1QWVNT1MzQ2RzeU5jRVBPeEJxSFB0K1I5Yy9Xazl3YVZCODFIZHNzWWdxS1hGdXMxc1NyM3pNWjh0cEVFZ0RvNXNpSWVmYW12SkFYZzMvN0ZsTm9CcG0wWHd2NGpLcWxPeDVVY21sYTRLQnlqb2U4RGtOOXhpcHRETzVIYWRtTWVSZ1V4b0E4anV2VjA2bzErTEI3SmNCT0ZOY1B6T3F0c3JMUzdHUkVEQTF1MjdtWGNpTC9td3hwb1BRbWJ3MllienRHMDIxaFdFUXBwRUN4YTh6UHNxc0Zhd0R6M2NOaG4vL0tVZWpmV2hoczRBeHZDMjJZemIzendDL2FVSXRCQmhrQ2hYWGdDcXFjN1VTY2ZVS05aZ1lVRlZkRSthVUt3clBXcmk3dytuamRzaEVTSXo5MUU0YWZvb0RXWmNOTkpMcDMvb2hUdDFsTHVTc3JyTlRBY3EwRkVoeVlGRjV4TjJreGNLSzVwUm1rZGVqMmc1ZVIrN1E5NmQxeXpNaHZqRmdBK01LUGorUTdIekJjKzBVWVJjZlZ1RzBoOUxOclhNR2c1WTBkaWJTYXZoTXdkVmg5cWxLa252bmhZWnZ4ejFCcGNVYW03NTM1STVMM2swdWVibTlLK0R3SHEzTUs3TXRMa2p6Yit3aHhLS2pLdkF5dENxdllzUlRqSkV0RzY3bUFETU9nSGRyRDROVlkrUk9uWHpQQWR2U2krbGZpV3FLOHYyQ2ZFRmMrZUtuaXZnUjlPSFdsRUlscDVEbEg0Nm1aR2tRTTI4WklCMk85NnBGMnJ0UWl2dkZxQ3FtKzNRb01TdnFENXd0VnpONnlXRTlYTVlVcjQrUHFyNFVCOFJkQ29BMWc2ZGhramJWdzN6L2Fzb1FIZFdPOGltSEpoNzROcm82d3ZlVjVZaDQxOExQUFZNcFZxZHg5RDB1RDM1dTRMQlFZNnVqWGhXUFovaTZDZWRzaDZteWFoUWUra2RuY0ZZSWtHYitvNmtVa3FUMUpQWmFiMzc3NzN0YWp5K2J6bTVMQ1k1UDFKcVpTYkU5VVJGdG1HNjI5RGYyblVqZ0FGckFoRnBQNk5uUExyV0U3VkpJK2ZQMGJSckVDdERVbmpKSGxUVld5cUpOYzY1cW5KQ1VFOGhjNldHT2pMUmkwYzVBNHJ3Y2NoUVB4eEdEdklNL3owR3lUOWlIcy9ycnJGRnFmdDFXT0dsTjhaZmw5eEYvUy9MKzlFbDVIVC9kTkZ5QTNhS2tZQm9kZUVGdW9VSlF1U2szOVloK096V2V6STNQa3AvTTQ5dnduU2pPc1NHQWEwd0tEdG0xNXZpekR3VENDcWZ5ZkZ1NE1RUFp1Y1U0czJHa0tlbC93UDlvTGVIWGVpeTB1R21POXYvLzJkOW5SMmF0N0xyOGFoKzVheDJZV0Z1Y2hyVllabll0MXFqTG8yRWp5WWkvY1dZOGltR1hJd3pETUJRYUNXbndHYjlsb2taVlEwL21TVTZKdVk4RE5OaTBxUWNJMEV5MVZPY204V0VwUklHeEU1WHJMUnZrRDNwS09FVGNFUVpSY0FxT21TMGdEcEJ2R1lLWDc3R1NCOHkyTU5Gcm9Gd0k4MXR0YjYrd2I2QVFpQ3N5dVFCajZ1QnlldFBETTRYK3M0WDlidGUxcVV3UVRRRWdXbkVZcTIxd3NBb0xiR2c2Y2U3NmFWOWY1YXdOSnljZjRQencrZm9zOEJRMjlpenVXNVpzTlp3cm9OZzI5SUFhU1RvMDIxSTFwR3dMVnNkNzB3aW56NDN2R1lQb2RHOFpweEV6TUs3dklETW5ya0xDYVB6N0pGelM5NjNDOHRxdlZ1WTQwY1kwM1lINkJ4WlMwSlhGd3hLWkxZUGlXbG02YkRuMFVZazBQRXViMjRjUEhuNENJc2JmWjNNSlVTSzVwRE1EUVB4bStMVFg2bnFNQldoL2ZYL2pmeitIWFd3cG5id0dhR2ZrUUkwcHNLd2d0MmNJNDRwakV2K1B2THBnS2hBTzVzZ2JYa1NGbkhjcWpma3Bmb0Z1QlNvK2lGWnM5UnhRVEJQYVlqUzlCcHlhTVhMb1JqejFqbnBsV0gyeDNFSW5LTklGQkE9PScpXQpfRlVOQ19DQUNIRSA9IHt9CgpkZWYgX2V4ZWNfZW5jKGlkeCwga2V5LCBuYW1lLCBhcmdzLCBrd2FyZ3MpOgogICAgaWYgbmFtZSBpbiBfRlVOQ19DQUNIRToKICAgICAgICByZXR1cm4gX0ZVTkNfQ0FDSEVbbmFtZV0oKmFyZ3MsICoqa3dhcmdzKQogICAgcmF3ID0gX0ZFTkNfREFUQVtpZHhdCiAgICBub25jZSwgdGFnID0gKHJhd1s6MTZdLCByYXdbLTE2Ol0pCiAgICBjdCA9IHJhd1sxNjotMTZdCiAgICBhdXRoX2tleSA9IGhhc2hsaWIuc2hhMjU2KGInYXV0aHYxOicgKyBrZXkgKyBub25jZSkuZGlnZXN0KCkKICAgIGlmIG5vdCBobWFjLmNvbXBhcmVfZGlnZXN0KGhhc2hsaWIuc2hhMjU2KGF1dGhfa2V5ICsgY3QpLmRpZ2VzdCgpWzoxNl0sIHRhZyk6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdbZnVuY2VuY10gaW50ZWdyaXR5IGNoZWNrIGZhaWxlZCcpCiAgICBlbmNfa2V5ID0gaGFzaGxpYi5zaGEyNTYoYidlbmN2MTonICsga2V5ICsgbm9uY2UpLmRpZ2VzdCgpCiAgICBwbGFpbl9ieXRlcyA9IF94b3Jfc3RyZWFtKGVuY19rZXksIGN0KQogICAgcGxhaW5fc3RyID0gcGxhaW5fYnl0ZXMuZGVjb2RlKCd1dGYtOCcpCiAgICBucyA9IHt9CiAgICBleGVjKHBsYWluX3N0ciwgZ2xvYmFscygpLCBucykKICAgIGZ1bmMgPSBuc1snX2YnXQogICAgX0ZVTkNfQ0FDSEVbbmFtZV0gPSBmdW5jCiAgICByZXN1bHQgPSBmdW5jKCphcmdzLCAqKmt3YXJncykKICAgIHJldHVybiByZXN1bHQKCmFzeW5jIGRlZiBfZXhlY19lbmNfYXN5bmMoaWR4LCBrZXksIG5hbWUsIGFyZ3MsIGt3YXJncyk6CiAgICBpZiBuYW1lIGluIF9GVU5DX0NBQ0hFOgogICAgICAgIHJldHVybiBhd2FpdCBfRlVOQ19DQUNIRVtuYW1lXSgqYXJncywgKiprd2FyZ3MpCiAgICByYXcgPSBfRkVOQ19EQVRBW2lkeF0KICAgIG5vbmNlLCB0YWcgPSAocmF3WzoxNl0sIHJhd1stMTY6XSkKICAgIGN0ID0gcmF3WzE2Oi0xNl0KICAgIGF1dGhfa2V5ID0gaGFzaGxpYi5zaGEyNTYoYidhdXRodjE6JyArIGtleSArIG5vbmNlKS5kaWdlc3QoKQogICAgaWYgbm90IGhtYWMuY29tcGFyZV9kaWdlc3QoaGFzaGxpYi5zaGEyNTYoYXV0aF9rZXkgKyBjdCkuZGlnZXN0KClbOjE2XSwgdGFnKToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ1tmdW5jZW5jXSBpbnRlZ3JpdHkgY2hlY2sgZmFpbGVkJykKICAgIGVuY19rZXkgPSBoYXNobGliLnNoYTI1NihiJ2VuY3YxOicgKyBrZXkgKyBub25jZSkuZGlnZXN0KCkKICAgIHBsYWluX2J5dGVzID0gX3hvcl9zdHJlYW0oZW5jX2tleSwgY3QpCiAgICBwbGFpbl9zdHIgPSBwbGFpbl9ieXRlcy5kZWNvZGUoJ3V0Zi04JykKICAgIG5zID0ge30KICAgIGV4ZWMocGxhaW5fc3RyLCBnbG9iYWxzKCksIG5zKQogICAgZnVuYyA9IG5zWydfZiddCiAgICBfRlVOQ19DQUNIRVtuYW1lXSA9IGZ1bmMKICAgIHJlc3VsdCA9IGF3YWl0IGZ1bmMoKmFyZ3MsICoqa3dhcmdzKQogICAgcmV0dXJuIHJlc3VsdAoKZGVmIF94b3Jfc3RyZWFtKGtleSwgZGF0YSk6CiAgICByZXN1bHQgPSBieXRlYXJyYXkoKQogICAgY291bnRlciA9IDAKICAgIHdoaWxlIGxlbihyZXN1bHQpIDwgbGVuKGRhdGEpOgogICAgICAgIGtzID0gaGFzaGxpYi5zaGEyNTYoa2V5ICsgY291bnRlci50b19ieXRlcyg4LCAnYmlnJykpLmRpZ2VzdCgpCiAgICAgICAgY2h1bmsgPSBkYXRhW2xlbihyZXN1bHQpOmxlbihyZXN1bHQpICsgMzJdCiAgICAgICAgZm9yIGEsIGIgaW4gemlwKGNodW5rLCBrcyk6CiAgICAgICAgICAgIHJlc3VsdC5hcHBlbmQoYSBeIGIpCiAgICAgICAgY291bnRlciArPSAxCiAgICByZXR1cm4gYnl0ZXMocmVzdWx0KQoKZGVmIF9iKCphcmdzLCAqKmt3YXJncyk6CiAgICByZXR1cm4gX2V4ZWNfZW5jKDAsIF9GVU5DX0tFWSwgJ19iJywgYXJncywga3dhcmdzKQoKZGVmIF9lKCphcmdzLCAqKmt3YXJncyk6CiAgICByZXR1cm4gX2V4ZWNfZW5jKDEsIF9GVU5DX0tFWSwgJ19lJywgYXJncywga3dhcmdzKQoKZGVmIF9mKCphcmdzLCAqKmt3YXJncyk6CiAgICByZXR1cm4gX2V4ZWNfZW5jKDIsIF9GVU5DX0tFWSwgJ19mJywgYXJncywga3dhcmdzKQoKZGVmIF9nKCphcmdzLCAqKmt3YXJncyk6CiAgICByZXR1cm4gX2V4ZWNfZW5jKDMsIF9GVU5DX0tFWSwgJ19nJywgYXJncywga3dhcmdzKQ=="), '<exec>', 'exec'), globals())
    _vm_run(_c, _k, _m, globals(), locals(), _map, _ok)
if __name__ == '__main__':
    _sqcdoul()
