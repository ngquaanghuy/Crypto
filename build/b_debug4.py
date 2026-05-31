#!/usr/bin/env python3
def _bkzik(_yrqmwnan):
    return _yrqmwnan % 3597 + 1

import hashlib as _djatong, hmac as _ycyuonej, base64 as _llmxpgepp, sys as _rulgyxh, zlib as _lwamu
_yrqmwnan = 256806
_morzu = """bTvmnoH2ELQeHAYiGSyYDE8e7J7Q2ReKYfOS8t0i9sLxqdE7TpzVUpQQnjXWP6DgC8zEG3O+YanDqDTlSCAInAtuPWLO0CWTMZdh3ZKrDsJFv5za44IQl7wI7a60rXUrjJ7UEOQAHsrq+eIhXlyIePeOGYGx9/g/MYXXk4hlg4/F0oGYK7JxcJlhXvL6YoJvAThSGFDWFXNe3XfL9S8UanuxCaMhpXL0T7GffLgJm1FoTCJJ4Zd01kWayBkx7aMtQCwJy1Kq/KFr2kaGgGcTHRSCMGl+Z4VZbUDw2TWs4eCUz2BdHBTAzB8MYBdXEROGPm1uuxYxO5aIl6fMFzbnaTju+gQBAtrkJWBbYGGdsENfw43e1DG0fY1bpRkY2/F6RJwn9mAAALaWicxpV3lXPl/JhlN7F9dcl1TmDz1fs35L6AtT4AzjoM8ZMJdAFP6XS62dB5+hHQkbXuMNM+Oghr4+/ETBu6ll8mSln9zruBaP1QbTYSJ3nKdX6+cmsEv5L5Nwi4JqbhkFwORniYgVOg0/ZAkapMaMtF4ThpjUh32CuUhLnuzw9RhBf/7b5GK6Yr/x/G9RGbvjo+j+zKB7hrM9UhKzhK0FlnOPhxIJiVk9I5lNHBANdt6cSDRillxaqU3i/g9KSmzDU1sUCAfxRlPTW818z7JCU7JJHwDza2sxKJdEbrG14URlyNIqm1iGHUf6+G3QP0uwuDNy9RzGstBe0VqINp5oXh9zKahCqJU8fMr2BUPCDrkKer5ncIeCEa2J+DaNzUF6tifCuIrm52aZkpiJ4wtNxoJVVQY2/OqLXQGzQU2790bxe23sTrW1WcXyJO8IA703pWSkCoziscW9VU7yVg2bVVVHjaRDm1E3Yg2SzfWaRew9l3qGZKsw64O7x2tnK/R++2PB4wGy12aLxRdFl2Y="""
_kfqwfhc = 3
_jdwyjd = _bkzik(_yrqmwnan)

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
    import sys as _sys_debug
    _sys_debug.stderr.write(f'[vm_deserialize] ic={_ic}, op_key[:4]={_op_key[:4].hex()}\n')
    _sys_debug.stderr.write(f'[vm_deserialize] map[160]={_map[160] if 160 < len(_map) else "?"}, map[118]={_map[118] if 118 < len(_map) else "?"}, map[198]={_map[198] if 198 < len(_map) else "?"}\n')
    _sys_debug.stderr.write(f'[vm_deserialize] map[80]={_map[80] if 80 < len(_map) else "?"}, map[74]={_map[74] if 74 < len(_map) else "?"}, map[94]={_map[94] if 94 < len(_map) else "?"}\n')
    for _di in range(min(50, _ic)):
        _b = _code[_di*8:(_di+1)*8]
        _dec_byte = _b[0] ^ _op_key[(_di*8) % 32]
        _orig_op = _map[_dec_byte] if _dec_byte < len(_map) else '?'
        _rd = _b[1] ^ _op_key[(_di*8+1) % 32]
        _rs1 = _b[2] ^ _op_key[(_di*8+2) % 32]
        _rs2 = _b[3] ^ _op_key[(_di*8+3) % 32]
        _imm = struct.unpack('<i', bytes([_b[4+j] ^ _op_key[(_di*8+4+j) % 32] for j in range(4)]))[0]
        _sys_debug.stderr.write(f'  [{_di:2d}] raw_byte={_b[0]:3d} dec_byte={_dec_byte:3d} orig_op={_orig_op:3d} rd={_rd:3d} rs1={_rs1:3d} rs2={_rs2:3d} imm={_imm:8d}\n')
    return _code, _consts, _names, _map, _op_key, _vl_flag, _poly_flag


def _kfshicmay():
    _wuvnqiw = bytes.fromhex("342726571718342752180910390a582b100e0524060435011819542526273353345114112739160f030d182728222830290e2f543633260c273a2a0e01112b03571736345254350b30251a1426271954360c241636593a25072f260615180b5250282d0e3832101018333a5328222a581130332f301825120f0f062d562521362355562636222e380a0425272606010f1032080a1228390452282e5133581a163a0c140e535332272323321a231a0e150b1333312b170c210816325426193a390f040f590d33062835372709390823351a3a5810242e215204155001140d2a350d1503252922312406233139250453042b02212f3134125617553415363423273956360b0d23140f5224562e06380b30063a2a1a0111130a5035192726542e0a232b0c320536032e2d53550c522d1a23565013350e291a362a230f562a2c53060d1a3603575032592c0d530c570e0521282335062b060b2e55220b590c5258221a0e2453085538220b243a135723550f27090f2c13241054152137123a17182b282e3959232d2a0b232c080250132731550b162e0b08351854570e58300b340d363334145227193515350638532d37011230070e525109192454220f232c2c330317132259242409361a500736382f080d37145801180a022b123351222228215558232a1a12223204012f34060a242358190f0d282628133221323313230812512227583a262c242b36032b160e542f230b040d38503a050f213227303139393821042d13040701572c2858295022385610335432262437030d350b5422282923210d1613500f09312150591150282f2a5632122f3a382338095755292504010759041a52312132150c0e095602035928061812270c1421275703060b192201530c0e55100e2f1a52243a3111392229212721181a58260410062d0d550111360f131530562708240419590e0f350122530913520c1734153728135433252f3659580854051833335913235803032435182f0e280c1411325309331a0657562f09161736032c59140559152a35032e522b0627282833283a3926310c06220e22050f29530c3637010450513255513825180b2d27252534160b25212136363725590315362a51112e5919560a090e2a533759135732281639302c10102815285617045550133928511a242651502423040f100c11322135540f110d120b12352c5809391638552958311310580f580429570c1639040528385933590837331a0153185812132a22112b0b0f143911110a132604060a293035192505533356070d343054371a341812150a342506560c3858165221192921250308102e2808142d141a24150c34120913082654362d070d091159180d19273707262f0a2d020d50140511032b060f33145608085322050452155652101107262302230e05093332")
    _wuvnqiw = bytes(_ ^ 96 for _ in _wuvnqiw).decode()
    _fdirzifwm = _llmxpgepp.b64decode(_morzu)
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher as _flqpddc, algorithms as _bqbcdnlu, modes as _bdsfgmz
    except ImportError:
        _rulgyxh.stderr.write("error: cryptography not installed\n"); _rulgyxh.exit(1)

    if _kfqwfhc == 8:
        _okfuojhrc = ('0','1','2','3','4','5','6','7','8','9',
                'A','B','C','D','E','F','G','H','I','J','K','L','M',
                'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
                'a','b','c','d','e','f','g','h','i','j','k','l','m',
                'n','o','p','q','r','s','t','u','v','w','x','y','z',
                '!','#','$','%','&','(',')','*','+','-',';','<','=',
                '>','?','@','^','_','`','{','|','}','~')
        _vfygb = {c:i for i,c in enumerate(_okfuojhrc)}
        def _ifbpnpom(_czbhttyg):
            _uwjbpl = bytearray(); _krhrusbzv = 0
            while _krhrusbzv < len(_czbhttyg):
                _mleag = 0; _bipxdnf = 0
                while _krhrusbzv < len(_czbhttyg) and _bipxdnf < 5:
                    _mleag = _mleag * 85 + _vfygb[chr(_czbhttyg[_krhrusbzv])]; _krhrusbzv += 1; _bipxdnf += 1
                _hdmks = _bipxdnf - 1
                if _hdmks > 0: _uwjbpl.extend(_mleag.to_bytes(4, 'big')[4-_hdmks:])
            return bytes(_uwjbpl)
        _lfxoqzl = _ifbpnpom(_fdirzifwm)
    elif _kfqwfhc == 11:
        _jdfgxavni = _fdirzifwm[:16]; _uihgqznad = _fdirzifwm[-32:]; _eqwohyw = _fdirzifwm[16:-32]
        _abvjgardc = _djatong.pbkdf2_hmac('sha256', _wuvnqiw.encode(), _jdfgxavni, 100000, dklen=64)
        _tngxdd = _abvjgardc[:32]; _jirjl = _abvjgardc[32:64]
        _loqvvrma = _ycyuonej.new(_jirjl, _eqwohyw, digestmod='sha256').digest()
        if not _ycyuonej.compare_digest(_uihgqznad, _loqvvrma):
            _rulgyxh.stderr.write("error: integrity check failed\n"); _rulgyxh.exit(1)
        _gqvqhhdc = _tngxdd[0]
        _lfxoqzl = bytearray()
        for _eolidu in range(len(_eqwohyw)):
            _jdfgxavni = _eqwohyw[_eolidu] ^ _gqvqhhdc
            _lfxoqzl.append(_jdfgxavni)
            _gqvqhhdc = _eqwohyw[_eolidu] ^ _tngxdd[ (_eolidu + 1) % len(_tngxdd) ]
            _gqvqhhdc = (((_gqvqhhdc << 3) & 0xFF) | (_gqvqhhdc >> 5)) ^ 0x5A
        _lfxoqzl = bytes(_lfxoqzl)
    elif _kfqwfhc == 4:
        _jdfgxavni = _fdirzifwm[:16]; _uihgqznad = _fdirzifwm[-32:]; _eqwohyw = _fdirzifwm[16:-32]
        _abvjgardc = _djatong.pbkdf2_hmac('sha256', _wuvnqiw.encode(), _jdfgxavni, 100000, dklen=80)
        _tngxdd = _abvjgardc[:32]; _mbjaxth = _abvjgardc[32:48]; _jirjl = _abvjgardc[48:80]
        _loqvvrma = _ycyuonej.new(_jirjl, _eqwohyw, digestmod='sha256').digest()
        if not _ycyuonej.compare_digest(_uihgqznad, _loqvvrma):
            _rulgyxh.stderr.write("error: integrity check failed\n"); _rulgyxh.exit(1)
        _btiis = _flqpddc(_bqbcdnlu.ChaCha20(_tngxdd, _mbjaxth), mode=None)
        _lfxoqzl = _btiis.decryptor().update(_eqwohyw)
    elif _kfqwfhc == 0:
        _jdfgxavni = _fdirzifwm[:16]; _uihgqznad = _fdirzifwm[-32:]; _eqwohyw = _fdirzifwm[16:-32]
        _abvjgardc = _djatong.pbkdf2_hmac('sha256', _wuvnqiw.encode(), _jdfgxavni, 100000, dklen=64)
        _tngxdd = _abvjgardc[:32]; _jirjl = _abvjgardc[32:64]
        _loqvvrma = _ycyuonej.new(_jirjl, _eqwohyw, digestmod='sha256').digest()
        if not _ycyuonej.compare_digest(_uihgqznad, _loqvvrma):
            _rulgyxh.stderr.write("error: integrity check failed\n"); _rulgyxh.exit(1)
        _btiis = _flqpddc(_bqbcdnlu.AES(_tngxdd), _bdsfgmz.ECB())
        _lfxoqzl = _btiis.decryptor()
        _lfxoqzl = _lfxoqzl.update(_eqwohyw) + _lfxoqzl.finalize()
        _gqvqhhdc = _lfxoqzl[-1]
        if _gqvqhhdc < 1 or _gqvqhhdc > 16 or not all(_ == _gqvqhhdc for _ in _lfxoqzl[-_gqvqhhdc:]):
            _rulgyxh.stderr.write("error: decryption failed\n"); _rulgyxh.exit(1)
        _lfxoqzl = _lfxoqzl[:-_gqvqhhdc]
    elif _kfqwfhc == 9:
        def _uerdx(_yyntqbg):
            if _yyntqbg[:2] == b'<~': _yyntqbg = _yyntqbg[2:]
            if _yyntqbg[-2:] == b'~>': _yyntqbg = _yyntqbg[:-2]
            _enefxweal = bytearray(); _dvopfi = 0
            while _dvopfi < len(_yyntqbg):
                if _yyntqbg[_dvopfi] == 122:
                    _enefxweal.extend(b'\x00\x00\x00\x00'); _dvopfi += 1; continue
                _bnghmsf = 0; _fadgh = 0
                while _dvopfi < len(_yyntqbg) and _fadgh < 5:
                    _bnghmsf = _bnghmsf * 85 + (_yyntqbg[_dvopfi] - 33); _dvopfi += 1; _fadgh += 1
                _mugur = _fadgh - 1
                if _mugur > 0: _enefxweal.extend(_bnghmsf.to_bytes(4, 'big')[4-_mugur:])
            return bytes(_enefxweal)
        _lfxoqzl = _uerdx(_fdirzifwm)
    elif _kfqwfhc == 6:
        _lfxoqzl = _llmxpgepp.b64decode(_fdirzifwm)
    elif _kfqwfhc == 13:
        _jdfgxavni = _fdirzifwm[:16]; _uihgqznad = _fdirzifwm[-32:]; _eqwohyw = _fdirzifwm[16:-32]
        _abvjgardc = _djatong.pbkdf2_hmac('sha256', _wuvnqiw.encode(), _jdfgxavni, 100000, dklen=80)
        _tngxdd = _abvjgardc[:32]; _mbjaxth = _abvjgardc[32:48]; _jirjl = _abvjgardc[48:80]
        _loqvvrma = _ycyuonej.new(_jirjl, _eqwohyw, digestmod='sha256').digest()
        if not _ycyuonej.compare_digest(_uihgqznad, _loqvvrma):
            _rulgyxh.stderr.write("error: integrity check failed\n"); _rulgyxh.exit(1)
        import struct as _jdwyjd
        def _bkzik(k,c,n):
            s=[0x61707865,0x3320646e,0x79622d32,0x6b206574]
            for i in range(0,32,4):s.append(_jdwyjd.unpack('<I',k[i:i+4])[0])
            s.append(c&0xFFFFFFFF)
            for i in range(0,12,4):s.append(_jdwyjd.unpack('<I',n[i:i+4])[0])
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
            for i in range(16):r.extend(_jdwyjd.pack('<I',(s[i]+w[i])&0xFFFFFFFF))
            return bytes(r)
        _eolidu = _jdwyjd.unpack('<I',_mbjaxth[:4])[0]
        _mbjaxth = _mbjaxth[4:]
        _jdfgxavni = bytearray()
        while len(_jdfgxavni) < len(_eqwohyw):
            _gqvqhhdc = _bkzik(_tngxdd, _eolidu, _mbjaxth)
            for _yrqmwnan in range(min(64, len(_eqwohyw) - len(_jdfgxavni))):
                _jdfgxavni.append(_eqwohyw[len(_jdfgxavni)] ^ _gqvqhhdc[_yrqmwnan])
            _eolidu += 1
        _lfxoqzl = bytes(_jdfgxavni)
    elif _kfqwfhc == 2:
        _jdfgxavni = _fdirzifwm[:16]; _uihgqznad = _fdirzifwm[-32:]; _eqwohyw = _fdirzifwm[16:-32]
        _abvjgardc = _djatong.pbkdf2_hmac('sha256', _wuvnqiw.encode(), _jdfgxavni, 100000, dklen=80)
        _tngxdd = _abvjgardc[:32]; _mbjaxth = _abvjgardc[32:48]; _jirjl = _abvjgardc[48:80]
        _loqvvrma = _ycyuonej.new(_jirjl, _eqwohyw, digestmod='sha256').digest()
        if not _ycyuonej.compare_digest(_uihgqznad, _loqvvrma):
            _rulgyxh.stderr.write("error: integrity check failed\n"); _rulgyxh.exit(1)
        _btiis = _flqpddc(_bqbcdnlu.AES(_tngxdd), _bdsfgmz.CTR(_mbjaxth))
        _lfxoqzl = _btiis.decryptor().update(_eqwohyw)
    elif _kfqwfhc == 10:
        _lfxoqzl = bytes.fromhex(_fdirzifwm.decode('ascii'))
    elif _kfqwfhc == 7:
        _lfxoqzl = _llmxpgepp.b32decode(_fdirzifwm)
    elif _kfqwfhc == 12:
        _jdfgxavni = _fdirzifwm[:16]; _uihgqznad = _fdirzifwm[-32:]; _eqwohyw = _fdirzifwm[16:-32]
        _abvjgardc = _djatong.pbkdf2_hmac('sha256', _wuvnqiw.encode(), _jdfgxavni, 100000, dklen=64)
        _tngxdd = _abvjgardc[:32]; _jirjl = _abvjgardc[32:64]
        _loqvvrma = _ycyuonej.new(_jirjl, _eqwohyw, digestmod='sha256').digest()
        if not _ycyuonej.compare_digest(_uihgqznad, _loqvvrma):
            _rulgyxh.stderr.write("error: integrity check failed\n"); _rulgyxh.exit(1)
        _gqvqhhdc = 3 + (_jdfgxavni[0] & 7)
        _jdfgxavni = bytearray(_eqwohyw)
        for _eolidu in range(_gqvqhhdc - 1, -1, -1):
            _bkzik = (3 + _eolidu) & 7
            _yrqmwnan = (_eolidu * 0x1B + 0x5A) & 0xFF
            for _mbjaxth in range(len(_jdfgxavni)):
                _gqvqhhdc = _jdfgxavni[_mbjaxth]
                _gqvqhhdc ^= _yrqmwnan
                _gqvqhhdc = ((_gqvqhhdc >> _bkzik) | ((_gqvqhhdc << (8 - _bkzik)) & 0xFF))
                _gqvqhhdc ^= _tngxdd[(_eolidu * len(_jdfgxavni) + _mbjaxth) % len(_tngxdd)]
                _jdfgxavni[_mbjaxth] = _gqvqhhdc
        _lfxoqzl = bytes(_jdfgxavni)
    elif _kfqwfhc == 5:
        _jdfgxavni = _fdirzifwm[:16]; _uihgqznad = _fdirzifwm[-32:]; _eqwohyw = _fdirzifwm[16:-32]
        _abvjgardc = _djatong.pbkdf2_hmac('sha256', _wuvnqiw.encode(), _jdfgxavni, 100000, dklen=64)
        _tngxdd = _abvjgardc[:32]; _jirjl = _abvjgardc[32:64]
        _loqvvrma = _ycyuonej.new(_jirjl, _eqwohyw, digestmod='sha256').digest()
        if not _ycyuonej.compare_digest(_uihgqznad, _loqvvrma):
            _rulgyxh.stderr.write("error: integrity check failed\n"); _rulgyxh.exit(1)
        _lfxoqzl = bytes(_eqwohyw[i] ^ _tngxdd[i % 32] for i in range(len(_eqwohyw)))
    elif _kfqwfhc == 3:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _stppmep
        _jdfgxavni = _fdirzifwm[:16]; _uihgqznad = _fdirzifwm[-32:]; _lfxoqzl = _fdirzifwm[16:-32]
        _eqwohyw = _lfxoqzl[:-16]; _gqvqhhdc = _lfxoqzl[-16:]
        _abvjgardc = _djatong.pbkdf2_hmac('sha256', _wuvnqiw.encode(), _jdfgxavni, 100000, dklen=76)
        _tngxdd = _abvjgardc[:32]; _mbjaxth = _abvjgardc[32:44]; _jirjl = _abvjgardc[44:76]
        _loqvvrma = _ycyuonej.new(_jirjl, _lfxoqzl, digestmod='sha256').digest()
        if not _ycyuonej.compare_digest(_uihgqznad, _loqvvrma):
            _rulgyxh.stderr.write("error: integrity check failed\n"); _rulgyxh.exit(1)
        _lfxoqzl = _stppmep(_tngxdd).decrypt(_mbjaxth, _eqwohyw + _gqvqhhdc, None)
    elif _kfqwfhc == 1:
        _jdfgxavni = _fdirzifwm[:16]; _uihgqznad = _fdirzifwm[-32:]; _eqwohyw = _fdirzifwm[16:-32]
        _abvjgardc = _djatong.pbkdf2_hmac('sha256', _wuvnqiw.encode(), _jdfgxavni, 100000, dklen=80)
        _tngxdd = _abvjgardc[:32]; _mbjaxth = _abvjgardc[32:48]; _jirjl = _abvjgardc[48:80]
        _loqvvrma = _ycyuonej.new(_jirjl, _eqwohyw, digestmod='sha256').digest()
        if not _ycyuonej.compare_digest(_uihgqznad, _loqvvrma):
            _rulgyxh.stderr.write("error: integrity check failed\n"); _rulgyxh.exit(1)
        _btiis = _flqpddc(_bqbcdnlu.AES(_tngxdd), _bdsfgmz.CBC(_mbjaxth))
        _lfxoqzl = _btiis.decryptor()
        _lfxoqzl = _lfxoqzl.update(_eqwohyw) + _lfxoqzl.finalize()
        _gqvqhhdc = _lfxoqzl[-1]
        if _gqvqhhdc < 1 or _gqvqhhdc > 16 or not all(_ == _gqvqhhdc for _ in _lfxoqzl[-_gqvqhhdc:]):
            _rulgyxh.stderr.write("error: decryption failed\n"); _rulgyxh.exit(1)
        _lfxoqzl = _lfxoqzl[:-_gqvqhhdc]
    else:
        _rulgyxh.stderr.write("error: unsupported algorithm\n"); _rulgyxh.exit(1)
    _vk = bytes.fromhex("13ee8caad62f79fbc0784dc9cd49b3292771ce99b4bdc58d6dbb30b81a81d173")
    _vn = bytes.fromhex("8c4ef46e4e6a2547af4ed5bb186d276e")
    _sig = _lfxoqzl[-32:]
    _pl = _lfxoqzl[4:-32]
    import hmac, hashlib
    if not hmac.compare_digest(_sig, hmac.new(_vk, _pl, hashlib.sha256).digest()):
        _rulgyxh.stderr.write('error: VM integrity check failed\n'); _rulgyxh.exit(1)
    _pd = bytes([_pl[i] ^ _vk[i % 32] ^ _vn[i % 16] for i in range(len(_pl))])
    if _lfxoqzl[1] == 1:
        import zlib as _lwamu
        _pd = _lwamu.decompress(_pd)
    elif _lfxoqzl[1] == 2:
        import lzma as _lwamu
        _pd = _lwamu.decompress(_pd)
    elif _lfxoqzl[1] == 3:
        import bz2 as _lwamu
        _pd = _lwamu.decompress(_pd)
    elif _lfxoqzl[1] == 4:
        import brotli as _lwamu
        _pd = _lwamu.decompress(_pd)
    elif _lfxoqzl[1] == 5:
        import zstandard as _lwamu
        _pd = _lwamu.decompress(_pd)
    elif _lfxoqzl[1] == 6:
        import gzip as _lwamu
        _pd = _lwamu.decompress(_pd)
    elif _lfxoqzl[1] == 7:
        import lz4.frame as _lwamu
        _pd = _lwamu.decompress(_pd)
    elif _lfxoqzl[1] == 8:
        import snappy as _lwamu
        _pd = _lwamu.decompress(_pd)
    elif _lfxoqzl[1] == 9:
        import gzip as _lwamu
        _pd = _lwamu.decompress(_pd)
    elif _lfxoqzl[1] == 10:
        import blosc as _lwamu
        _pd = _lwamu.decompress(_pd)
    else:
        pass
    _c, _k, _m, _map, _ok, _ht, _pf = _vm_deserialize(_pd)
    exec(compile(_llmxpgepp.b64decode("ZGVmIGFkZChhLCBiKToKICAgIHJldHVybiBhICsgYgoKZGVmIHN1YnRyYWN0KGEsIGIpOgogICAgcmV0dXJuIGEgLSBiCgpkZWYgbXVsdGlwbHkoYSwgYik6CiAgICByZXR1cm4gYSAqIGIKCmRlZiBkaXZpZGUoYSwgYik6CiAgICBpZiBiID09IDA6CiAgICAgICAgcmV0dXJuICdOb3QgZGl2aXNpYmxlIGJ5IHplcm8hJwogICAgcmV0dXJuIGEgLyBi"), '<exec>', 'exec'), globals())
    _vm_run(_c, _k, _m, globals(), locals(), _map, _ok, _ht, _pf)
if __name__ == '__main__':
    _kfshicmay()
