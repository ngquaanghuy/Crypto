#!/usr/bin/env python3
def _npddoxkk(_jypindj):
    return _jypindj % 342 + 1

import hashlib as _rypbhfei, hmac as _vptowsqmq, base64 as _cbgjnq, sys as _bnwfcpdr, zlib as _kzxujsjcj
_jypindj = 831623
_wzuncwqi = """z9+8/OpnB93BWnXTqi0qN34PJuzzlI4sQ656GhrrP4h/j+EkYmZU0VsktOS19XumO8CDvWVd96HfNcdxlPyYnzpAXDpl0jaspvvuUrSEDegBlzf4Sk+Nh5ftUmu3L5WfB00cBu9cQMGmmPkncEbRtf64QxMWHgLAHoXOr0uXYps3G23e8ZfLk+HRFdv5ZsHQztmz4DwpOw16Nx+T8zCfyMnmQ8XZl9CxM8qzHNgMfnvtVhH3n1pUALwwxjzMZa4jApAcsF+EG5FHFbBGGp6PeTyRNBYlw3MrXIvK7anXg6UeEUFaTZV9fnEsPkyj5LWwLo+o8xUAdVofK3mxQxNrn2qokcqVcH6SGSdzyTqGB14TL+H9r6Zvc64f0d9FZrXa3OpeJnccnwAjFO+jN6jlHcBW1s0ZlKcv7GcaHWrZ3qYlABN8Ql2vvGEIctcFzEGYCr4OyeHE9dGfdo+GEHeWlu6X6/2IdoK6AhTpB7h+qi44pxbVCTVu1mLU6olipJD8tiKizEd1TT229YJkeNGLAAaBWr0fseKKIw/4rvzFi77YRfOTbutRRHC5FkLSMyqutmKqZki4qd1IIhXy/iiOhKnGKificQTZ3EgI0kOctm/X1an7Z61Pmu6CqIxDoPIGc+Kow73UvcAil4mgWnW3MDuFvfGrSv8nlL7jZQ2AAAgooPL9+Il3SgoizM1knSIWWEMbc3RkRwvH8Ywc2qYLGQPcc1g43FGDDLcGzGd82IwPW9jHWslg/vaxMY10Ufpng8azXP+tmdcPomA24HqvB71XYy3AglcV48xqQ0SQqRDd6oiLIJhPvKvLLXfkchwap3YP8JDvINsyzmH9sDGU3PlADNSZiRzEACf9KhQB63rxZUq9lOvHFWEbPekg/b3+h8h6VXCAihV/vzxR6ZtZSqlCJBGx"""
_dangn = 3
_zekftmjqa = _npddoxkk(_jypindj)

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
    while _ip < _n:
        _cycle += 1
        _op, _rd, _rs1, _rs2, _imm, _ilen = _decode()
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


def _gwtotu():
    _lpaqi = bytes.fromhex("f3ecf5c9c8fb8ddff9c7858acdd984f8cbced5c8fcefecd088d3c5dfd2e585c885cfc4de8c8bffebcdefc9d4f7f3f9f2f0eaf0eadecaefedd9f4dcfcf8f3fbec88f1dce58ccafbf9c4dfefc5dcf7cbd9f9f1e8d2e8fff488e8d9dc848b8af1d4c8f4cdf88bcfcf8888ceecdbf3f4f7edf3f6e9f6e9e5daf4c8d0eb89c7eef9f3cbcbd2d7ffdcf3f4f4e5ded5fbcb8afbe8d9d9dff2cbc8fa85eaeeffdbfbf5c8fcd6eecd8f88e7e4fcdecddbd0db8ae7c9d3c98c8cfeccc5fbdbc7f8fad3f8c4f0e5cfeaf98ffbd0e4ed8fcbd0f5efc7fafbfe8eceecccfcf588cdc8ffd3d7d7fbc7c585fcd4dcefeafecff2e8dfe9fffed1cbcbf3e989d9dfdb88ced3cefb85d888f4f2f2fafaf28df58bd6d7f0ef8ecfe7d6f3d08dd28dc8fee5c7c4d1e8d3faee8cf8ebffd7e7c8e5cedb84d6cfdceddaceefce8fd3f48c8888d4ceef89c5ecced9e7ffd08989cfcf84fa8bf3f08ec8fbd28cf1def9c8defed08fe5e5d2f7d9d0c4d8eb8a84f7f3e789f1d4dcd18be4c5ef84d1ffebcb85cfdfef85dc89f5d68ff1edd0eac58ed5898ec5d6d8dcfcd08df9fcf0c5d9cd8f85f9d1c7fad2c8d7e7f5cc8b8af9ea8df1f2def6ebf78feb88e9dbc8d2f7c588d3f9e9f9e7cd8bdffedbe9d184cde7f484d38ec5defbf5ce8dd688ccd2f1fafaf9d48fdbcae5888588f9f2ccc9dcf5cd8ced8cdacfdcf1cbc4f5d1d7f484f7f8fed0d389c4fcfad7ded385dcf4d4d0e4fef8dbd3dafeceedf5cadaead8d8fad3f9f7c9efccfc898feaccdbe8f1d3f7d3cbd3e4cedecceac5f0d2d0e8cacec4f9f1f9f4dcf8f9d5c48dd1cbf9f8fbf6f9d0d3c8c789fcd3d3e98fc4d1fa898a8e8ece8ffb8a8c88d4f5effecbe4d0d0e9e7dbcdd08fd2f9f4def1d6d7f1d4eef1c78be9f88de9c98fdafafbf4d6caced6dbfbc789e5c588ebe5fbcf8febe5d0d4efcd8bd1cbe8f9fcd2ecea8afcf5e7faf3dcd584ebc7cef4f0d68efcdcdcf2c8fbf784d589c7eec7d1c8de8aece9cef6f1f7d6d4dbfeefd08fc7d0ffecd1fff08bf18af8f3e4ecd1d0fef084dac5cfccc5da8afa8ef1d1dbc7d5d28bf4eeceee8ceb8be9f2d98df1caf98efadff589c7d0858bd9f1cac9e8e7ccc8e885c88fd4ceded4fcf588cfd3e9d2fc8ae7c8e7d98feffcf7f8f284cdd7f8cdf4e8d3ffdbfec5898ed0d8d3f3e7ed85d888f4f5f489d9daccd2e8f585c4f8eef5fbf4f18ef0d4e9d4fcfcf6f4f8cb88f98888f9d4fcd8fbf2cdf1dee4d8d6f08dcbc4d78fdbf2f9d7d5d8ebd58df4edd1d4fe8ce4d3ec85dcd5ea8b8edbeaecd9e58dded9cbdfe4fac4f9f68ceaffef8fd984eceae48dead28cde8dedfbf3ecf6c8d68ef5e9edf3d28bdf8fdbd6c4faf7efcacb8ae4c7888aeef7ec8ac789f1f3faffdffad2d3e8d8c7f78acc8f89faf9d1f1c5f68df4d1c5e8f9d5d589eef8cef6d1fb8cd98589fbf0ffec")
    _lpaqi = bytes(_ ^ 189 for _ in _lpaqi).decode()
    _ahpxs = _cbgjnq.b64decode(_wzuncwqi)
    if _dangn == 6:
        _coicef = _cbgjnq.b64decode(_ahpxs)
    elif _dangn == 4:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _fpkcad, algorithms as _zfqjjwqhf, modes as _mpkxpyfd
        except ImportError:
            _bnwfcpdr.stderr.write("error: cryptography not installed\n"); _bnwfcpdr.exit(1)
        _iyjygrdi = _ahpxs[:16]; _ulscbpw = _ahpxs[-32:]; _lvrzmr = _ahpxs[16:-32]
        _xtgooa = _rypbhfei.pbkdf2_hmac('sha256', _lpaqi.encode(), _iyjygrdi, 100000, dklen=80)
        _wykwgdb = _xtgooa[:32]; _jojanvt = _xtgooa[32:48]; _rfzviosv = _xtgooa[48:80]
        _nbbbdc = _vptowsqmq.new(_rfzviosv, _lvrzmr, digestmod='sha256').digest()
        if not _vptowsqmq.compare_digest(_ulscbpw, _nbbbdc):
            _bnwfcpdr.stderr.write("error: integrity check failed\n"); _bnwfcpdr.exit(1)
        _bpxjsy = _fpkcad(_zfqjjwqhf.ChaCha20(_wykwgdb, _jojanvt), mode=None)
        _coicef = _bpxjsy.decryptor().update(_lvrzmr)
    elif _dangn == 9:
        def _cftmmruwg(_wabotkd):
            if _wabotkd[:2] == b'<~': _wabotkd = _wabotkd[2:]
            if _wabotkd[-2:] == b'~>': _wabotkd = _wabotkd[:-2]
            _uhfmf = bytearray(); _zpowombq = 0
            while _zpowombq < len(_wabotkd):
                if _wabotkd[_zpowombq] == 122:
                    _uhfmf.extend(b'\x00\x00\x00\x00'); _zpowombq += 1; continue
                _vfgozc = 0; _maxnpq = 0
                while _zpowombq < len(_wabotkd) and _maxnpq < 5:
                    _vfgozc = _vfgozc * 85 + (_wabotkd[_zpowombq] - 33); _zpowombq += 1; _maxnpq += 1
                _uewcmih = _maxnpq - 1
                if _uewcmih > 0: _uhfmf.extend(_vfgozc.to_bytes(4, 'big')[4-_uewcmih:])
            return bytes(_uhfmf)
        _coicef = _cftmmruwg(_ahpxs)
    elif _dangn == 12:
        _iyjygrdi = _ahpxs[:16]; _ulscbpw = _ahpxs[-32:]; _lvrzmr = _ahpxs[16:-32]
        _xtgooa = _rypbhfei.pbkdf2_hmac('sha256', _lpaqi.encode(), _iyjygrdi, 100000, dklen=64)
        _wykwgdb = _xtgooa[:32]; _rfzviosv = _xtgooa[32:64]
        _nbbbdc = _vptowsqmq.new(_rfzviosv, _lvrzmr, digestmod='sha256').digest()
        if not _vptowsqmq.compare_digest(_ulscbpw, _nbbbdc):
            _bnwfcpdr.stderr.write("error: integrity check failed\n"); _bnwfcpdr.exit(1)
        _jydkulyog = 3 + (_iyjygrdi[0] & 7)
        _iyjygrdi = bytearray(_lvrzmr)
        for _qwhep in range(_jydkulyog - 1, -1, -1):
            _npddoxkk = (3 + _qwhep) & 7
            _jypindj = (_qwhep * 0x1B + 0x5A) & 0xFF
            for _jojanvt in range(len(_iyjygrdi)):
                _jydkulyog = _iyjygrdi[_jojanvt]
                _jydkulyog ^= _jypindj
                _jydkulyog = ((_jydkulyog >> _npddoxkk) | ((_jydkulyog << (8 - _npddoxkk)) & 0xFF))
                _jydkulyog ^= _wykwgdb[(_qwhep * len(_iyjygrdi) + _jojanvt) % len(_wykwgdb)]
                _iyjygrdi[_jojanvt] = _jydkulyog
        _coicef = bytes(_iyjygrdi)
    elif _dangn == 8:
        _tcqvfsukl = ('0','1','2','3','4','5','6','7','8','9',
                'A','B','C','D','E','F','G','H','I','J','K','L','M',
                'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
                'a','b','c','d','e','f','g','h','i','j','k','l','m',
                'n','o','p','q','r','s','t','u','v','w','x','y','z',
                '!','#','$','%','&','(',')','*','+','-',';','<','=',
                '>','?','@','^','_','`','{','|','}','~')
        _vhvdp = {c:i for i,c in enumerate(_tcqvfsukl)}
        def _pgupwvwb(_nxgtou):
            _qlkxdfhq = bytearray(); _fyginqzt = 0
            while _fyginqzt < len(_nxgtou):
                _qrjns = 0; _crqvi = 0
                while _fyginqzt < len(_nxgtou) and _crqvi < 5:
                    _qrjns = _qrjns * 85 + _vhvdp[chr(_nxgtou[_fyginqzt])]; _fyginqzt += 1; _crqvi += 1
                _kyxxw = _crqvi - 1
                if _kyxxw > 0: _qlkxdfhq.extend(_qrjns.to_bytes(4, 'big')[4-_kyxxw:])
            return bytes(_qlkxdfhq)
        _coicef = _pgupwvwb(_ahpxs)
    elif _dangn == 11:
        _iyjygrdi = _ahpxs[:16]; _ulscbpw = _ahpxs[-32:]; _lvrzmr = _ahpxs[16:-32]
        _xtgooa = _rypbhfei.pbkdf2_hmac('sha256', _lpaqi.encode(), _iyjygrdi, 100000, dklen=64)
        _wykwgdb = _xtgooa[:32]; _rfzviosv = _xtgooa[32:64]
        _nbbbdc = _vptowsqmq.new(_rfzviosv, _lvrzmr, digestmod='sha256').digest()
        if not _vptowsqmq.compare_digest(_ulscbpw, _nbbbdc):
            _bnwfcpdr.stderr.write("error: integrity check failed\n"); _bnwfcpdr.exit(1)
        _jydkulyog = _wykwgdb[0]
        _coicef = bytearray()
        for _qwhep in range(len(_lvrzmr)):
            _iyjygrdi = _lvrzmr[_qwhep] ^ _jydkulyog
            _coicef.append(_iyjygrdi)
            _jydkulyog = _lvrzmr[_qwhep] ^ _wykwgdb[ (_qwhep + 1) % len(_wykwgdb) ]
            _jydkulyog = (((_jydkulyog << 3) & 0xFF) | (_jydkulyog >> 5)) ^ 0x5A
        _coicef = bytes(_coicef)
    elif _dangn == 5:
        _iyjygrdi = _ahpxs[:16]; _ulscbpw = _ahpxs[-32:]; _lvrzmr = _ahpxs[16:-32]
        _xtgooa = _rypbhfei.pbkdf2_hmac('sha256', _lpaqi.encode(), _iyjygrdi, 100000, dklen=64)
        _wykwgdb = _xtgooa[:32]; _rfzviosv = _xtgooa[32:64]
        _nbbbdc = _vptowsqmq.new(_rfzviosv, _lvrzmr, digestmod='sha256').digest()
        if not _vptowsqmq.compare_digest(_ulscbpw, _nbbbdc):
            _bnwfcpdr.stderr.write("error: integrity check failed\n"); _bnwfcpdr.exit(1)
        _coicef = bytes(_lvrzmr[i] ^ _wykwgdb[i % 32] for i in range(len(_lvrzmr)))
    elif _dangn == 0:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _fpkcad, algorithms as _zfqjjwqhf, modes as _mpkxpyfd
        except ImportError:
            _bnwfcpdr.stderr.write("error: cryptography not installed\n"); _bnwfcpdr.exit(1)
        _iyjygrdi = _ahpxs[:16]; _ulscbpw = _ahpxs[-32:]; _lvrzmr = _ahpxs[16:-32]
        _xtgooa = _rypbhfei.pbkdf2_hmac('sha256', _lpaqi.encode(), _iyjygrdi, 100000, dklen=64)
        _wykwgdb = _xtgooa[:32]; _rfzviosv = _xtgooa[32:64]
        _nbbbdc = _vptowsqmq.new(_rfzviosv, _lvrzmr, digestmod='sha256').digest()
        if not _vptowsqmq.compare_digest(_ulscbpw, _nbbbdc):
            _bnwfcpdr.stderr.write("error: integrity check failed\n"); _bnwfcpdr.exit(1)
        _bpxjsy = _fpkcad(_zfqjjwqhf.AES(_wykwgdb), _mpkxpyfd.ECB())
        _coicef = _bpxjsy.decryptor()
        _coicef = _coicef.update(_lvrzmr) + _coicef.finalize()
        _jydkulyog = _coicef[-1]
        if _jydkulyog < 1 or _jydkulyog > 16 or not all(_ == _jydkulyog for _ in _coicef[-_jydkulyog:]):
            _bnwfcpdr.stderr.write("error: decryption failed\n"); _bnwfcpdr.exit(1)
        _coicef = _coicef[:-_jydkulyog]
    elif _dangn == 7:
        _coicef = _cbgjnq.b32decode(_ahpxs)
    elif _dangn == 1:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _fpkcad, algorithms as _zfqjjwqhf, modes as _mpkxpyfd
        except ImportError:
            _bnwfcpdr.stderr.write("error: cryptography not installed\n"); _bnwfcpdr.exit(1)
        _iyjygrdi = _ahpxs[:16]; _ulscbpw = _ahpxs[-32:]; _lvrzmr = _ahpxs[16:-32]
        _xtgooa = _rypbhfei.pbkdf2_hmac('sha256', _lpaqi.encode(), _iyjygrdi, 100000, dklen=80)
        _wykwgdb = _xtgooa[:32]; _jojanvt = _xtgooa[32:48]; _rfzviosv = _xtgooa[48:80]
        _nbbbdc = _vptowsqmq.new(_rfzviosv, _lvrzmr, digestmod='sha256').digest()
        if not _vptowsqmq.compare_digest(_ulscbpw, _nbbbdc):
            _bnwfcpdr.stderr.write("error: integrity check failed\n"); _bnwfcpdr.exit(1)
        _bpxjsy = _fpkcad(_zfqjjwqhf.AES(_wykwgdb), _mpkxpyfd.CBC(_jojanvt))
        _coicef = _bpxjsy.decryptor()
        _coicef = _coicef.update(_lvrzmr) + _coicef.finalize()
        _jydkulyog = _coicef[-1]
        if _jydkulyog < 1 or _jydkulyog > 16 or not all(_ == _jydkulyog for _ in _coicef[-_jydkulyog:]):
            _bnwfcpdr.stderr.write("error: decryption failed\n"); _bnwfcpdr.exit(1)
        _coicef = _coicef[:-_jydkulyog]
    elif _dangn == 3:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _bjrem
        except ImportError:
            _bnwfcpdr.stderr.write("error: cryptography not installed\n"); _bnwfcpdr.exit(1)
        _iyjygrdi = _ahpxs[:16]; _ulscbpw = _ahpxs[-32:]; _coicef = _ahpxs[16:-32]
        _lvrzmr = _coicef[:-16]; _jydkulyog = _coicef[-16:]
        _xtgooa = _rypbhfei.pbkdf2_hmac('sha256', _lpaqi.encode(), _iyjygrdi, 100000, dklen=76)
        _wykwgdb = _xtgooa[:32]; _jojanvt = _xtgooa[32:44]; _rfzviosv = _xtgooa[44:76]
        _nbbbdc = _vptowsqmq.new(_rfzviosv, _coicef, digestmod='sha256').digest()
        if not _vptowsqmq.compare_digest(_ulscbpw, _nbbbdc):
            _bnwfcpdr.stderr.write("error: integrity check failed\n"); _bnwfcpdr.exit(1)
        _coicef = _bjrem(_wykwgdb).decrypt(_jojanvt, _lvrzmr + _jydkulyog, None)
    elif _dangn == 13:
        _iyjygrdi = _ahpxs[:16]; _ulscbpw = _ahpxs[-32:]; _lvrzmr = _ahpxs[16:-32]
        _xtgooa = _rypbhfei.pbkdf2_hmac('sha256', _lpaqi.encode(), _iyjygrdi, 100000, dklen=80)
        _wykwgdb = _xtgooa[:32]; _jojanvt = _xtgooa[32:48]; _rfzviosv = _xtgooa[48:80]
        _nbbbdc = _vptowsqmq.new(_rfzviosv, _lvrzmr, digestmod='sha256').digest()
        if not _vptowsqmq.compare_digest(_ulscbpw, _nbbbdc):
            _bnwfcpdr.stderr.write("error: integrity check failed\n"); _bnwfcpdr.exit(1)
        import struct as _zekftmjqa
        def _npddoxkk(k,c,n):
            s=[0x61707865,0x3320646e,0x79622d32,0x6b206574]
            for i in range(0,32,4):s.append(_zekftmjqa.unpack('<I',k[i:i+4])[0])
            s.append(c&0xFFFFFFFF)
            for i in range(0,12,4):s.append(_zekftmjqa.unpack('<I',n[i:i+4])[0])
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
            for i in range(16):r.extend(_zekftmjqa.pack('<I',(s[i]+w[i])&0xFFFFFFFF))
            return bytes(r)
        _qwhep = _zekftmjqa.unpack('<I',_jojanvt[:4])[0]
        _jojanvt = _jojanvt[4:]
        _iyjygrdi = bytearray()
        while len(_iyjygrdi) < len(_lvrzmr):
            _jydkulyog = _npddoxkk(_wykwgdb, _qwhep, _jojanvt)
            for _jypindj in range(min(64, len(_lvrzmr) - len(_iyjygrdi))):
                _iyjygrdi.append(_lvrzmr[len(_iyjygrdi)] ^ _jydkulyog[_jypindj])
            _qwhep += 1
        _coicef = bytes(_iyjygrdi)
    elif _dangn == 10:
        _coicef = bytes.fromhex(_ahpxs.decode('ascii'))
    elif _dangn == 2:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _fpkcad, algorithms as _zfqjjwqhf, modes as _mpkxpyfd
        except ImportError:
            _bnwfcpdr.stderr.write("error: cryptography not installed\n"); _bnwfcpdr.exit(1)
        _iyjygrdi = _ahpxs[:16]; _ulscbpw = _ahpxs[-32:]; _lvrzmr = _ahpxs[16:-32]
        _xtgooa = _rypbhfei.pbkdf2_hmac('sha256', _lpaqi.encode(), _iyjygrdi, 100000, dklen=80)
        _wykwgdb = _xtgooa[:32]; _jojanvt = _xtgooa[32:48]; _rfzviosv = _xtgooa[48:80]
        _nbbbdc = _vptowsqmq.new(_rfzviosv, _lvrzmr, digestmod='sha256').digest()
        if not _vptowsqmq.compare_digest(_ulscbpw, _nbbbdc):
            _bnwfcpdr.stderr.write("error: integrity check failed\n"); _bnwfcpdr.exit(1)
        _bpxjsy = _fpkcad(_zfqjjwqhf.AES(_wykwgdb), _mpkxpyfd.CTR(_jojanvt))
        _coicef = _bpxjsy.decryptor().update(_lvrzmr)
    else:
        _bnwfcpdr.stderr.write("error: unsupported algorithm\n"); _bnwfcpdr.exit(1)
    _vk = bytes.fromhex("03e8a5dfbc6b36732f7deffb7e2219466a579c5ca9fbbf389d65877f23dbe47e")
    _vn = bytes.fromhex("bd118ab89b835ad4315c33cf144d338d")
    _sig = _coicef[-32:]
    _pl = _coicef[4:-32]
    import hmac, hashlib
    if not hmac.compare_digest(_sig, hmac.new(_vk, _pl, hashlib.sha256).digest()):
        _bnwfcpdr.stderr.write('error: VM integrity check failed\n'); _bnwfcpdr.exit(1)
    _pd = bytes([_pl[i] ^ _vk[i % 32] ^ _vn[i % 16] for i in range(len(_pl))])
    if _coicef[1] == 1:
        import zlib as _kzxujsjcj
        _pd = _kzxujsjcj.decompress(_pd)
    elif _coicef[1] == 2:
        import lzma as _kzxujsjcj
        _pd = _kzxujsjcj.decompress(_pd)
    elif _coicef[1] == 3:
        import bz2 as _kzxujsjcj
        _pd = _kzxujsjcj.decompress(_pd)
    elif _coicef[1] == 4:
        import brotli as _kzxujsjcj
        _pd = _kzxujsjcj.decompress(_pd)
    elif _coicef[1] == 5:
        import zstandard as _kzxujsjcj
        _pd = _kzxujsjcj.decompress(_pd)
    elif _coicef[1] == 6:
        import gzip as _kzxujsjcj
        _pd = _kzxujsjcj.decompress(_pd)
    elif _coicef[1] == 7:
        import lz4.frame as _kzxujsjcj
        _pd = _kzxujsjcj.decompress(_pd)
    elif _coicef[1] == 8:
        import snappy as _kzxujsjcj
        _pd = _kzxujsjcj.decompress(_pd)
    elif _coicef[1] == 9:
        import gzip as _kzxujsjcj
        _pd = _kzxujsjcj.decompress(_pd)
    elif _coicef[1] == 10:
        import blosc as _kzxujsjcj
        _pd = _kzxujsjcj.decompress(_pd)
    else:
        pass
    _c, _k, _m, _map, _ok, _ht, _pf = _vm_deserialize(_pd)
    exec(compile(_cbgjnq.b64decode("ZGVmIGFkZChhLCBiKToKICAgIHJldHVybiBhICsgYgoKZGVmIHN1YnRyYWN0KGEsIGIpOgogICAgcmV0dXJuIGEgLSBiCgpkZWYgbXVsdGlwbHkoYSwgYik6CiAgICByZXR1cm4gYSAqIGIKCmRlZiBkaXZpZGUoYSwgYik6CiAgICBpZiBiID09IDA6CiAgICAgICAgcmV0dXJuICdOb3QgZGl2aXNpYmxlIGJ5IHplcm8hJwogICAgcmV0dXJuIGEgLyBi"), '<exec>', 'exec'), globals())
    _vm_run(_c, _k, _m, globals(), locals(), _map, _ok, _ht, _pf)
if __name__ == '__main__':
    _gwtotu()
