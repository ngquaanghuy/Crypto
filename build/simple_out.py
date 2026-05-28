#!/usr/bin/env python3
def _ksa(_eenjh):
    return _eenjh % 9285 + 1

import hashlib as _aemv, hmac as _bbnqyo, base64 as _uu, sys as _ho, zlib as _mjf
_eenjh = 52259
_oqmdph = """cW4Qib5um/56xRIWcNyycNhdiYtLdKrvHVzJD2xrOd12px/F8VXSYpivA6myjUdVP8DySIzpfEwE1HfN9FY//GseLdKQdTxmzpKNk9MGQRzj2isJO17119IoT649ff/CUCtEJbXnzdTUCAXqhSNXGXw3mU/8nSahx2MZaGg47jh3HHJMBst9H6jBnpyJVk4XGV9JigOM8JvDloiyPAJX+rMSdf6cPCOEHxfMcyMb/JI+x/Io7I1OA0ySfU3orYRxOEvV0u+RY3LNt8HiW/ckDkqdf3zz3LZRcs5PqPgPBz5dupQM62/1VRSihsseFPzUXgX+tetmK/r5Z6Q63R2PPqQSrIBwlbqejqkJZRVTZk1e4UoGVmIXkXmjQ25B/poOMY5c0adpwUl7vLTenTtYQDod3dnPO+B/Gay0YPYYbZY1qEXh+NfUnV+keQsIyzHHnY2oSdh1XvAWNlHl/0lxX6JCOqDMfWvSFEkOb1ufgR3HIAhgrSBnwMZC7yPImyTItlvT/ygt2osuGZ4h7NZA8FhIjANJb4khgfoowEb4+lcK5XvCi+u/R37wgHjq8LJslEyQmjK9T5sYGTTTOYdXLm9ZS3MT5BO2ALw1MRgFqG1pQeLQQLMuz9MQZ6NTzlD/BqD0v9qKyrvr3k43rTQlj1Q3BllYXPDYrbPu7VNp3LzoDeo0C6i1ewSBPvo842qB6qMT6xys7TieoIF2KV82zxhmSHfCFO63eWEP96fYh+o4UVzgu+RSsjNNeuTGrmwN+3JxdIhag/oxEos4SJRqSiD8xSYdlazZK+9R4I9/eUHgNKRJS9YhOwtVWu9cGumC3QJ6kkCC/cUH0XRnXLYnpI0bTZPl6PH+CSvdagnxpFuUrYqsbnt4JKQWjxLOz109IiyaGUj+RX93hu+gWNAurqDpiTkffnfr5BxpjEi2zQAN3JkEFQ7t+Qd9zenWIACagvFAX6yeMDUXKrKzjkIeLNiyxjbTSzoInFWddJLB74ZxmGOgPRnqBuyDuJu8MvsYHG1/fTltF/4w1CHfyZYniz3Z"""
_snnwz = 3
_qmnq = _ksa(_eenjh)

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

def _pznuk():
    if _ho.gettrace() is not None:
        _ho.stderr.write('error: debugger detected\n'); _ho.exit(1)
    _rdle = bytes.fromhex("33273a4d2c271a251f2b4b3a32113018332c0b3b364f0b243b0b0c133f4d380f274d093f3b1731304d3a072a0a0e2f4c1c111508382d2b0e4f171f3b05041a0b083b3b1524303f123f49334f3c253c4414242b0d0a15100a151c1411440f313e3e10350b0e124f07123c4a3f134e3b051e2e392a153e042910273f242b3b2525493532091148243c3f2e4e2b101f0944280c143838281f0e11270417051c3f1e0b1b2e36134f3a0e44113808284a1a1a0d1a052b134d0a1229364a38344438142f30352c38140c2e1525173927360a3f394d270d32374816483e4e393c1008344a1f244a09270c13321a2b2c07131644041e1637254928113728322f1b3116141a101f2e1e36144b3a0a4930302c481a390a293a3b3a041a10142f1413133c15354b07054e2c36351c1c483a33341c100815122e321349094d4e3b250c24102410273a0417393c0a2e1e284e31382e164b2c0e181c4815444b4d272b173f454c0e1f1c19040e3c481a0b3b2e31142835103813132a073e4a343b1f1c4a253632350a353b4e1a0f32123b3317454a2f101f131f27050d0d28312a1f1416194c2d49174d180e17142d4c083838493f1a1c1b0c31272d2a324d4e1630284e3f15170b2d4f4e360508493c1917083b0d0727130a0433101a281a39111c3c0b132b2814123e2844100f3e311c0b0b3818240e0f0c440d1a08102425332c083a3f274d12382b44073b483537092b3b352b4a1116350c160b390c330b33083310302c1b4a0d3b3c354a0d08153105134c2d4e28241f1e192e2d0a12343f2411340c04393345102f4f130c0a37102912162c1038150e332a07043c24131b321e312d1f444a151c444b1e0a4924091f1645143a2d2f0f043f0c442a454b08161b133a0d3e1936054c0a25193e07162905054f1935353b0d45082849370828164e152c45390b2e3e4d3f1227251f1805053c2d0529361933321f3c0c4f4f244d320d1615344c494a4a25444f4e1b4c4d303144162e364e0b25123931360c2c450e4a441c2d251805302e092e170e492444084f441145140a0e270e3b071548191f4b4405052b0a4915351a114f2b4d070e16353f3e09250a4f3e4a44141a1c09040f180c2d330b0e2d2f0d3f1804090a2c4e351e48101a0a0f0e321a2e44281e4b251c4c072e1f4a2f4a4a493f27330c0d193b49140c19311f191a4517492e1c04123a4f2c251a3e351b373e09173e3b104849271244274a1b254b454c332505383b043a363e320f0b173b3a30312c321b071b3a2b11310f07090d3b1204323a052a1a0f1e29240e292b3a0c3c30450e17111a3f4a24170d2a4b044f4d343c3c480e1013101f45484d250c10182e36334e070d49253b1c481619242b383f4404071f1b050b2b180a170e2f381b440f0d1349324a293a2e4c11243f181b3324103e131f2f2f")
    _rdle = bytes(_ ^ 125 for _ in _rdle).decode()
    _ho.breakpointhook = None
    for _qm in ('pydevd','pdb','ipdb','pdbpp','pydevconsole'):
        if _qm in _ho.modules:
            _ho.stderr.write('error: debugger detected\n'); _ho.exit(1)
    _kvjgpin = _uu.b64decode(_oqmdph)
    for _qn in ('__import__','compile','exec'):
        _qf = getattr(_ho.modules.get('builtins'), _qn, None)
        if _qf is not None:
            _qg = getattr(_qf, '__name__', '')
            if _qg != _qn:
                _ho.stderr.write('error: hook detected\n'); _ho.exit(1)
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher as _etxo, algorithms as _dkwohz, modes as _azbfuk
    except ImportError:
        _ho.stderr.write("error: cryptography not installed\n"); _ho.exit(1)

    if len(_ho.meta_path) > 5:
        _ho.stderr.write('error: import hook detected\n'); _ho.exit(1)
    if getattr(_ho, 'flags', None) and _ho.flags.no_user_site:
        _ho.stderr.write('error: sandbox detected\n'); _ho.exit(1)
    if _snnwz == 4:
        _nyfcfsx = _kvjgpin[:16]; _qnmcudk = _kvjgpin[-32:]; _ftuqmxb = _kvjgpin[16:-32]
        _gbj = _aemv.pbkdf2_hmac('sha256', _rdle.encode(), _nyfcfsx, 100000, dklen=80)
        _vvxkt = _gbj[:32]; _nawm = _gbj[32:48]; _dhqvupx = _gbj[48:80]
        _gmbkieu = _bbnqyo.new(_dhqvupx, _ftuqmxb, _aemv.sha256).digest()
        if not _bbnqyo.compare_digest(_qnmcudk, _gmbkieu):
            _ho.stderr.write("error: integrity check failed\n"); _ho.exit(1)
        _kv = _etxo(_dkwohz.ChaCha20(_vvxkt, _nawm), mode=None)
        _gsyff = _kv.decryptor().update(_ftuqmxb)
    elif _snnwz == 6:
        _gsyff = _uu.b64decode(_kvjgpin)
    elif _snnwz == 8:
        _prhed = ('0','1','2','3','4','5','6','7','8','9',
                'A','B','C','D','E','F','G','H','I','J','K','L','M',
                'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
                'a','b','c','d','e','f','g','h','i','j','k','l','m',
                'n','o','p','q','r','s','t','u','v','w','x','y','z',
                '!','#','$','%','&','(',')','*','+','-',';','<','=',
                '>','?','@','^','_','`','{','|','}','~')
        _nj = {c:i for i,c in enumerate(_prhed)}
        def _mqcq(_cfof):
            _kvxlrzk = bytearray(); _ggeh = 0
            while _ggeh < len(_cfof):
                _vqczk = 0; _kqbdvsn = 0
                while _ggeh < len(_cfof) and _kqbdvsn < 5:
                    _vqczk = _vqczk * 85 + _nj[chr(_cfof[_ggeh])]; _ggeh += 1; _kqbdvsn += 1
                _zbeql = _kqbdvsn - 1
                if _zbeql > 0: _kvxlrzk.extend(_vqczk.to_bytes(4, 'big')[4-_zbeql:])
            return bytes(_kvxlrzk)
        _gsyff = _mqcq(_kvjgpin)
    elif _snnwz == 2:
        _nyfcfsx = _kvjgpin[:16]; _qnmcudk = _kvjgpin[-32:]; _ftuqmxb = _kvjgpin[16:-32]
        _gbj = _aemv.pbkdf2_hmac('sha256', _rdle.encode(), _nyfcfsx, 100000, dklen=80)
        _vvxkt = _gbj[:32]; _nawm = _gbj[32:48]; _dhqvupx = _gbj[48:80]
        _gmbkieu = _bbnqyo.new(_dhqvupx, _ftuqmxb, _aemv.sha256).digest()
        if not _bbnqyo.compare_digest(_qnmcudk, _gmbkieu):
            _ho.stderr.write("error: integrity check failed\n"); _ho.exit(1)
        _kv = _etxo(_dkwohz.AES(_vvxkt), _azbfuk.CTR(_nawm))
        _gsyff = _kv.decryptor().update(_ftuqmxb)
    elif _snnwz == 1:
        _nyfcfsx = _kvjgpin[:16]; _qnmcudk = _kvjgpin[-32:]; _ftuqmxb = _kvjgpin[16:-32]
        _gbj = _aemv.pbkdf2_hmac('sha256', _rdle.encode(), _nyfcfsx, 100000, dklen=80)
        _vvxkt = _gbj[:32]; _nawm = _gbj[32:48]; _dhqvupx = _gbj[48:80]
        _gmbkieu = _bbnqyo.new(_dhqvupx, _ftuqmxb, _aemv.sha256).digest()
        if not _bbnqyo.compare_digest(_qnmcudk, _gmbkieu):
            _ho.stderr.write("error: integrity check failed\n"); _ho.exit(1)
        _kv = _etxo(_dkwohz.AES(_vvxkt), _azbfuk.CBC(_nawm))
        _gsyff = _kv.decryptor().update(_ftuqmxb) + _kv.finalize()
        _gsyff = _gsyff[-1]
        if _gsyff < 1 or _gsyff > 16 or not all(_ == _gsyff for _ in _gsyff[-_gsyff:]):
            _ho.stderr.write("error: decryption failed\n"); _ho.exit(1)
        _gsyff = _gsyff[:-_gsyff]
    elif _snnwz == 9:
        def _pyrqim(_oqflox):
            if _oqflox[:2] == b'<~': _oqflox = _oqflox[2:]
            if _oqflox[-2:] == b'~>': _oqflox = _oqflox[:-2]
            _pid = bytearray(); _agexarw = 0
            while _agexarw < len(_oqflox):
                if _oqflox[_agexarw] == 122:
                    _pid.extend(b'\x00\x00\x00\x00'); _agexarw += 1; continue
                _ubs = 0; _bhfua = 0
                while _agexarw < len(_oqflox) and _bhfua < 5:
                    _ubs = _ubs * 85 + (_oqflox[_agexarw] - 33); _agexarw += 1; _bhfua += 1
                _iyfzgrp = _bhfua - 1
                if _iyfzgrp > 0: _pid.extend(_ubs.to_bytes(4, 'big')[4-_iyfzgrp:])
            return bytes(_pid)
        _gsyff = _pyrqim(_kvjgpin)
    elif _snnwz == 3:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _hgjwf
        _nyfcfsx = _kvjgpin[:16]; _qnmcudk = _kvjgpin[-32:]; _gsyff = _kvjgpin[16:-32]
        _ftuqmxb = _gsyff[:-16]; _jsthgpk = _gsyff[-16:]
        _gbj = _aemv.pbkdf2_hmac('sha256', _rdle.encode(), _nyfcfsx, 100000, dklen=76)
        _vvxkt = _gbj[:32]; _nawm = _gbj[32:44]; _dhqvupx = _gbj[44:76]
        _gmbkieu = _bbnqyo.new(_dhqvupx, _gsyff, _aemv.sha256).digest()
        if not _bbnqyo.compare_digest(_qnmcudk, _gmbkieu):
            _ho.stderr.write("error: integrity check failed\n"); _ho.exit(1)
        _gsyff = _hgjwf(_vvxkt).decrypt(_nawm, _ftuqmxb + _jsthgpk, None)
    elif _snnwz == 7:
        _gsyff = _uu.b32decode(_kvjgpin)
    elif _snnwz == 0:
        _nyfcfsx = _kvjgpin[:16]; _qnmcudk = _kvjgpin[-32:]; _ftuqmxb = _kvjgpin[16:-32]
        _gbj = _aemv.pbkdf2_hmac('sha256', _rdle.encode(), _nyfcfsx, 100000, dklen=64)
        _vvxkt = _gbj[:32]; _dhqvupx = _gbj[32:64]
        _gmbkieu = _bbnqyo.new(_dhqvupx, _ftuqmxb, _aemv.sha256).digest()
        if not _bbnqyo.compare_digest(_qnmcudk, _gmbkieu):
            _ho.stderr.write("error: integrity check failed\n"); _ho.exit(1)
        _kv = _etxo(_dkwohz.AES(_vvxkt), _azbfuk.ECB())
        _gsyff = _kv.decryptor().update(_ftuqmxb) + _kv.finalize()
        _gsyff = _gsyff[-1]
        if _gsyff < 1 or _gsyff > 16 or not all(_ == _gsyff for _ in _gsyff[-_gsyff:]):
            _ho.stderr.write("error: decryption failed\n"); _ho.exit(1)
        _gsyff = _gsyff[:-_gsyff]
    elif _snnwz == 10:
        _gsyff = bytes.fromhex(_kvjgpin.decode('ascii'))
    elif _snnwz == 5:
        _nyfcfsx = _kvjgpin[:16]; _qnmcudk = _kvjgpin[-32:]; _ftuqmxb = _kvjgpin[16:-32]
        _gbj = _aemv.pbkdf2_hmac('sha256', _rdle.encode(), _nyfcfsx, 100000, dklen=64)
        _vvxkt = _gbj[:32]; _dhqvupx = _gbj[32:64]
        _gmbkieu = _bbnqyo.new(_dhqvupx, _ftuqmxb, _aemv.sha256).digest()
        if not _bbnqyo.compare_digest(_qnmcudk, _gmbkieu):
            _ho.stderr.write("error: integrity check failed\n"); _ho.exit(1)
        _gsyff = bytes(_ftuqmxb[i] ^ _vvxkt[i % 32] for i in range(len(_ftuqmxb)))
    else:
        _ho.stderr.write("error: unsupported algorithm\n"); _ho.exit(1)
    _gsyff, _c, _k, _m = _vm_deserialize(_gsyff[4:])
    exec(compile(_gsyff, '<vm>', 'exec'), globals())
    _vm_run(_c, _k, _m, globals(), locals())
if __name__ == '__main__':
    _pznuk()
