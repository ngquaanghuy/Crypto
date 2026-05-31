#!/usr/bin/env python3
def _yqjqern(_kuszhur):
    return _kuszhur % 6406 + 1

import hashlib as _pvqqq, hmac as _myfghs, base64 as _qlflnf, sys as _iwgnkevir, zlib as _zilryda
_kuszhur = 426661
_ehslatbn = """FNd6KP/3twYAu/CWZdYb4k4Uo/ARKEHQ9wFE+kkpDe3+BDPsJo2eLlRhiZcsjtuDL4sCgw9YHKDFtnThA8UnpTAI0sYq3rg5n4WncBs8R7fQBmnFLbwEKgAxGXi5aBrJ4LOpjEbXxZUrlvLXCDD3kVi4+B2P7skpjTvEb7qF0bqDOiProXcUrIhk/KDFlhu+hcOi+BghmchralKg6uU6zogK0ZxTdnWvvM7ZeGNwGQIGuRGwmcafyDCsC9lyp+5dutJedFOyer2SL7qVUOmM3JFRl4CGku/DzLcgHxZWQkCQBTaU2/2XTHrt6BeDhDoKGb4TVk0srxKHkLmrAd/4e8PaER/1EwvOULTK8ELpMZD99pgoEsrAmPIDS7yonTiCwBo536h63Bm2nHXbCAEh7YusFLGcGO9v3esYGedxXZLYrX+7KPXqyEJIV3umBoSO5Q7xV/wzQcaH/bfXlggNVfhQiZtPOKLGEAUIdJr/YH9Et3mG7Um/WCoQ6l5pu7gjDZqtmV2WIzqp9jo39O7Ylb/Bpe1SvW75Oto2+0nUjvimm96+FqZECakK7QqCcr/vn2sfHiZ7NIUjJO4g0Cw5KEx7La6X4IgoDwWK7pNuTLtx0srCkH1F2T9XwDRN9HYqonboBx3EuZlfp2rNNxYNfkiVjQOM3NYR0zTAFb019A/2G0/HcbTDMuBPBb1e4WBeqElwX5CbF3aNm+K5PLioApjjnywo6qA78RsGvH5FF0iySZk9WhoJ+qeGvSAToMLlgSd4TQAGj0J0o8P3Y/uTvPzaGLzxv3W/sHFDOZCHVJRq9ZKsWAoVh5k3haOGUGhVZUiZKngyFxxQSinlJ52Xi+VXQeg83oPOjQfgJ4Ja4sRcmPs8G7SXhVEIQeiQmtWTjUAHiySCkeXVmdAxHMgGLG+YCjpH"""
_obfylbg = 3
_pwimzsij = _yqjqern(_kuszhur)

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
        _decode = None
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


def _ttbowrol():
    if _iwgnkevir.gettrace() is not None:
        _iwgnkevir.stderr.write('error: debugger detected\n'); _iwgnkevir.exit(1)
    _okuwdkym = bytes.fromhex("aebfb9f7ae8b9bfbb7fa9980bdf881849afb979eaab99a888e878bbb888282fdfcbb958e868ca68a809788b780a280879c8c87f88bb9fe8e9e9b9caeab82979f89fb89ff89fda0bf8bbabdb8a28d8a8afef99aae98bbf786a2f9a5bbb59a9da9fa95a799ae87bb98aefd8cac8b83a89aac8c999df99ffca69da28c81868a83acbcfbfe85a99a8095a5a48ba0a7a58abba38aa4a1988c99a88589fe9b95abf9f7a0feb7858eaafaaa9581feab96ae9d848cfda4be8ebfbdf8aea78ab69b87f88596aa8dfcac99fa8088aaaa879e81a0f799a5979983a7a385969e97fc8bfdb7acad8c85f6fffbbcb58a83998d8a9887fb858898a798b78abda7828c87b69a8c9784acffa18489f99d829a97faab9b82838da79c9c859ffc8b87a6f7a6fc9ff89d9bf686968b88ae8caba7a0a399f79f8296ab9abc8a95899797958387be8bb783ba8abca58bbabd80adfcb8f7bd88aeffa38ca28588faacababaea2b5808083829a9c899c8c9da59f9efa849682a0a7a983a3f8a5bcf6f9fdab898c81fd95fe83878abaac86fdaa9e8a89a08589fc9d8b9f9daefab8b8aa9efafea38c8a9faca7f98383a289fcb781f7bb9784a1b8a1a89e95ff9efb8ca6ac8bae888a8a8a9b8af988f9ffb8aabba395a685899a95f89b809d96a89d8e8c8aa6859e96f784fd96a8fca7f8f688bcbefd959bbcf8968aba82bba39e8bbc85b5bb81a587828ebf8587fc80f996aa8183a7969b8281fb8a9a83fcfc969d87ada8adffbcb78dfef9a7a89ca7fb9af689a99b8dacb9a5809f84fe958eb697acbefcfc96f9fcac89b59cbf8abc9dbabeba869e89bea1baa282a3fdaba89c8082ffa580ada08ea8848895a180bfb9f985f9fffdb587a8fbfa809afd9bacb6a0a5f8f98e8bfa8e9ebe999ebb88b8f685889bb6a2a08d83fea9fc89bfaeacfeaa8b89b6aea8a5bd979985f9aaf68bf7bcfaa5ad9d968596f8b8f786a4859afe88a78986a0a8befeb781ff9cadb989b5a0a28a818eaabea584b79ba6aca1f686b888acaaa5848c858197bafb8ab6aa899899a0849ebfb68982a89bb589bd97fcb5faff888aa280819c8afca288f695bc8cb9bf8bbfbe8889808cfffbbcb58282f68596f6f7a9a38d99fa8ebd8a86a2fba2bdff8d97ffa6bdbcacf8a8adfb88989aba848e8cf68bf6acbe9dbcaba6ad9bfcb6bf8eb7b7fcbdbd8a958185889ffcab8dbe9dbe87bd98b7f88ea9828c86b7fbf8f9fda5b7a1979ca0fbb68afea68180bc9cbcbc8189fcacaca6a5a0bea398faa980b7a3fda79f85a7fbbdb8fd989a899980a3aaab85a395bdabfabdbea39ba6a9a38affaeaa9ff786bb8ba68d85a2ba86b89a9db9fffaf6b5a1fdf880a78d80aafc828ef7bebe89fc99aea0a09c80b7bc84fea9a5ff9c9d98fa9e99aa87b79da48ca2ad9baa9bf79f878180818b8eae8bfb988e84bab5bdbba6b7")
    _okuwdkym = bytes(_ ^ 207 for _ in _okuwdkym).decode()
    _iwgnkevir.breakpointhook = None
    for _qm in ('pydevd','pdb','ipdb','pdbpp','pydevconsole'):
        if _qm in _iwgnkevir.modules:
            _iwgnkevir.stderr.write('error: debugger detected\n'); _iwgnkevir.exit(1)
    _rmbubh = _qlflnf.b64decode(_ehslatbn)
    for _qn in ('__import__','compile','exec'):
        _qf = getattr(_iwgnkevir.modules.get('builtins'), _qn, None)
        if _qf is not None:
            _qg = getattr(_qf, '__name__', '')
            if _qg != _qn:
                _iwgnkevir.stderr.write('error: hook detected\n'); _iwgnkevir.exit(1)
    if len(_iwgnkevir.meta_path) > 5:
        _iwgnkevir.stderr.write('error: import hook detected\n'); _iwgnkevir.exit(1)
    if getattr(_iwgnkevir, 'flags', None) and _iwgnkevir.flags.no_user_site:
        _iwgnkevir.stderr.write('error: sandbox detected\n'); _iwgnkevir.exit(1)
    import os
    if any(x in str(_iwgnkevir.platform) or any(y in os.listdir('/proc/sys/kernel') for y in ['//', 'vm']) for x in ['vmware', 'virtualbox', 'qemu']):
        _iwgnkevir.stderr.write('error: virtual machine detected\n'); _iwgnkevir.exit(1)
    if _obfylbg == 2:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _wosywyxvh, algorithms as _acpvxim, modes as _ruhowet
        except ImportError:
            _iwgnkevir.stderr.write("error: cryptography not installed\n"); _iwgnkevir.exit(1)
        _wjdxrenba = _rmbubh[:16]; _oxiwz = _rmbubh[-32:]; _enksld = _rmbubh[16:-32]
        _pcsnt = _pvqqq.pbkdf2_hmac('sha256', _okuwdkym.encode(), _wjdxrenba, 100000, dklen=80)
        _ynejte = _pcsnt[:32]; _zrdadkp = _pcsnt[32:48]; _catjqsr = _pcsnt[48:80]
        _rvfwpt = _myfghs.new(_catjqsr, _enksld, digestmod='sha256').digest()
        if not _myfghs.compare_digest(_oxiwz, _rvfwpt):
            _iwgnkevir.stderr.write("error: integrity check failed\n"); _iwgnkevir.exit(1)
        _xrfcdagdz = _wosywyxvh(_acpvxim.AES(_ynejte), _ruhowet.CTR(_zrdadkp))
        _jzdtou = _xrfcdagdz.decryptor().update(_enksld)
    elif _obfylbg == 6:
        _jzdtou = _qlflnf.b64decode(_rmbubh)
    elif _obfylbg == 0:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _wosywyxvh, algorithms as _acpvxim, modes as _ruhowet
        except ImportError:
            _iwgnkevir.stderr.write("error: cryptography not installed\n"); _iwgnkevir.exit(1)
        _wjdxrenba = _rmbubh[:16]; _oxiwz = _rmbubh[-32:]; _enksld = _rmbubh[16:-32]
        _pcsnt = _pvqqq.pbkdf2_hmac('sha256', _okuwdkym.encode(), _wjdxrenba, 100000, dklen=64)
        _ynejte = _pcsnt[:32]; _catjqsr = _pcsnt[32:64]
        _rvfwpt = _myfghs.new(_catjqsr, _enksld, digestmod='sha256').digest()
        if not _myfghs.compare_digest(_oxiwz, _rvfwpt):
            _iwgnkevir.stderr.write("error: integrity check failed\n"); _iwgnkevir.exit(1)
        _xrfcdagdz = _wosywyxvh(_acpvxim.AES(_ynejte), _ruhowet.ECB())
        _jzdtou = _xrfcdagdz.decryptor()
        _jzdtou = _jzdtou.update(_enksld) + _jzdtou.finalize()
        _qphjiaxbx = _jzdtou[-1]
        if _qphjiaxbx < 1 or _qphjiaxbx > 16 or not all(_ == _qphjiaxbx for _ in _jzdtou[-_qphjiaxbx:]):
            _iwgnkevir.stderr.write("error: decryption failed\n"); _iwgnkevir.exit(1)
        _jzdtou = _jzdtou[:-_qphjiaxbx]
    elif _obfylbg == 3:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _xmwrm
        except ImportError:
            _iwgnkevir.stderr.write("error: cryptography not installed\n"); _iwgnkevir.exit(1)
        _wjdxrenba = _rmbubh[:16]; _oxiwz = _rmbubh[-32:]; _jzdtou = _rmbubh[16:-32]
        _enksld = _jzdtou[:-16]; _qphjiaxbx = _jzdtou[-16:]
        _pcsnt = _pvqqq.pbkdf2_hmac('sha256', _okuwdkym.encode(), _wjdxrenba, 100000, dklen=76)
        _ynejte = _pcsnt[:32]; _zrdadkp = _pcsnt[32:44]; _catjqsr = _pcsnt[44:76]
        _rvfwpt = _myfghs.new(_catjqsr, _jzdtou, digestmod='sha256').digest()
        if not _myfghs.compare_digest(_oxiwz, _rvfwpt):
            _iwgnkevir.stderr.write("error: integrity check failed\n"); _iwgnkevir.exit(1)
        _jzdtou = _xmwrm(_ynejte).decrypt(_zrdadkp, _enksld + _qphjiaxbx, None)
    elif _obfylbg == 11:
        _wjdxrenba = _rmbubh[:16]; _oxiwz = _rmbubh[-32:]; _enksld = _rmbubh[16:-32]
        _pcsnt = _pvqqq.pbkdf2_hmac('sha256', _okuwdkym.encode(), _wjdxrenba, 100000, dklen=64)
        _ynejte = _pcsnt[:32]; _catjqsr = _pcsnt[32:64]
        _rvfwpt = _myfghs.new(_catjqsr, _enksld, digestmod='sha256').digest()
        if not _myfghs.compare_digest(_oxiwz, _rvfwpt):
            _iwgnkevir.stderr.write("error: integrity check failed\n"); _iwgnkevir.exit(1)
        _qphjiaxbx = _ynejte[0]
        _jzdtou = bytearray()
        for _rpmfhktzi in range(len(_enksld)):
            _wjdxrenba = _enksld[_rpmfhktzi] ^ _qphjiaxbx
            _jzdtou.append(_wjdxrenba)
            _qphjiaxbx = _enksld[_rpmfhktzi] ^ _ynejte[ (_rpmfhktzi + 1) % len(_ynejte) ]
            _qphjiaxbx = (((_qphjiaxbx << 3) & 0xFF) | (_qphjiaxbx >> 5)) ^ 0x5A
        _jzdtou = bytes(_jzdtou)
    elif _obfylbg == 12:
        _wjdxrenba = _rmbubh[:16]; _oxiwz = _rmbubh[-32:]; _enksld = _rmbubh[16:-32]
        _pcsnt = _pvqqq.pbkdf2_hmac('sha256', _okuwdkym.encode(), _wjdxrenba, 100000, dklen=64)
        _ynejte = _pcsnt[:32]; _catjqsr = _pcsnt[32:64]
        _rvfwpt = _myfghs.new(_catjqsr, _enksld, digestmod='sha256').digest()
        if not _myfghs.compare_digest(_oxiwz, _rvfwpt):
            _iwgnkevir.stderr.write("error: integrity check failed\n"); _iwgnkevir.exit(1)
        _qphjiaxbx = 3 + (_wjdxrenba[0] & 7)
        _wjdxrenba = bytearray(_enksld)
        for _rpmfhktzi in range(_qphjiaxbx - 1, -1, -1):
            _yqjqern = (3 + _rpmfhktzi) & 7
            _kuszhur = (_rpmfhktzi * 0x1B + 0x5A) & 0xFF
            for _zrdadkp in range(len(_wjdxrenba)):
                _qphjiaxbx = _wjdxrenba[_zrdadkp]
                _qphjiaxbx ^= _kuszhur
                _qphjiaxbx = ((_qphjiaxbx >> _yqjqern) | ((_qphjiaxbx << (8 - _yqjqern)) & 0xFF))
                _qphjiaxbx ^= _ynejte[(_rpmfhktzi * len(_wjdxrenba) + _zrdadkp) % len(_ynejte)]
                _wjdxrenba[_zrdadkp] = _qphjiaxbx
        _jzdtou = bytes(_wjdxrenba)
    elif _obfylbg == 1:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _wosywyxvh, algorithms as _acpvxim, modes as _ruhowet
        except ImportError:
            _iwgnkevir.stderr.write("error: cryptography not installed\n"); _iwgnkevir.exit(1)
        _wjdxrenba = _rmbubh[:16]; _oxiwz = _rmbubh[-32:]; _enksld = _rmbubh[16:-32]
        _pcsnt = _pvqqq.pbkdf2_hmac('sha256', _okuwdkym.encode(), _wjdxrenba, 100000, dklen=80)
        _ynejte = _pcsnt[:32]; _zrdadkp = _pcsnt[32:48]; _catjqsr = _pcsnt[48:80]
        _rvfwpt = _myfghs.new(_catjqsr, _enksld, digestmod='sha256').digest()
        if not _myfghs.compare_digest(_oxiwz, _rvfwpt):
            _iwgnkevir.stderr.write("error: integrity check failed\n"); _iwgnkevir.exit(1)
        _xrfcdagdz = _wosywyxvh(_acpvxim.AES(_ynejte), _ruhowet.CBC(_zrdadkp))
        _jzdtou = _xrfcdagdz.decryptor()
        _jzdtou = _jzdtou.update(_enksld) + _jzdtou.finalize()
        _qphjiaxbx = _jzdtou[-1]
        if _qphjiaxbx < 1 or _qphjiaxbx > 16 or not all(_ == _qphjiaxbx for _ in _jzdtou[-_qphjiaxbx:]):
            _iwgnkevir.stderr.write("error: decryption failed\n"); _iwgnkevir.exit(1)
        _jzdtou = _jzdtou[:-_qphjiaxbx]
    elif _obfylbg == 13:
        _wjdxrenba = _rmbubh[:16]; _oxiwz = _rmbubh[-32:]; _enksld = _rmbubh[16:-32]
        _pcsnt = _pvqqq.pbkdf2_hmac('sha256', _okuwdkym.encode(), _wjdxrenba, 100000, dklen=80)
        _ynejte = _pcsnt[:32]; _zrdadkp = _pcsnt[32:48]; _catjqsr = _pcsnt[48:80]
        _rvfwpt = _myfghs.new(_catjqsr, _enksld, digestmod='sha256').digest()
        if not _myfghs.compare_digest(_oxiwz, _rvfwpt):
            _iwgnkevir.stderr.write("error: integrity check failed\n"); _iwgnkevir.exit(1)
        import struct as _pwimzsij
        def _yqjqern(k,c,n):
            s=[0x61707865,0x3320646e,0x79622d32,0x6b206574]
            for i in range(0,32,4):s.append(_pwimzsij.unpack('<I',k[i:i+4])[0])
            s.append(c&0xFFFFFFFF)
            for i in range(0,12,4):s.append(_pwimzsij.unpack('<I',n[i:i+4])[0])
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
            for i in range(16):r.extend(_pwimzsij.pack('<I',(s[i]+w[i])&0xFFFFFFFF))
            return bytes(r)
        _rpmfhktzi = _pwimzsij.unpack('<I',_zrdadkp[:4])[0]
        _zrdadkp = _zrdadkp[4:]
        _wjdxrenba = bytearray()
        while len(_wjdxrenba) < len(_enksld):
            _qphjiaxbx = _yqjqern(_ynejte, _rpmfhktzi, _zrdadkp)
            for _kuszhur in range(min(64, len(_enksld) - len(_wjdxrenba))):
                _wjdxrenba.append(_enksld[len(_wjdxrenba)] ^ _qphjiaxbx[_kuszhur])
            _rpmfhktzi += 1
        _jzdtou = bytes(_wjdxrenba)
    elif _obfylbg == 5:
        _wjdxrenba = _rmbubh[:16]; _oxiwz = _rmbubh[-32:]; _enksld = _rmbubh[16:-32]
        _pcsnt = _pvqqq.pbkdf2_hmac('sha256', _okuwdkym.encode(), _wjdxrenba, 100000, dklen=64)
        _ynejte = _pcsnt[:32]; _catjqsr = _pcsnt[32:64]
        _rvfwpt = _myfghs.new(_catjqsr, _enksld, digestmod='sha256').digest()
        if not _myfghs.compare_digest(_oxiwz, _rvfwpt):
            _iwgnkevir.stderr.write("error: integrity check failed\n"); _iwgnkevir.exit(1)
        _jzdtou = bytes(_enksld[i] ^ _ynejte[i % 32] for i in range(len(_enksld)))
    elif _obfylbg == 10:
        _jzdtou = bytes.fromhex(_rmbubh.decode('ascii'))
    elif _obfylbg == 4:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _wosywyxvh, algorithms as _acpvxim, modes as _ruhowet
        except ImportError:
            _iwgnkevir.stderr.write("error: cryptography not installed\n"); _iwgnkevir.exit(1)
        _wjdxrenba = _rmbubh[:16]; _oxiwz = _rmbubh[-32:]; _enksld = _rmbubh[16:-32]
        _pcsnt = _pvqqq.pbkdf2_hmac('sha256', _okuwdkym.encode(), _wjdxrenba, 100000, dklen=80)
        _ynejte = _pcsnt[:32]; _zrdadkp = _pcsnt[32:48]; _catjqsr = _pcsnt[48:80]
        _rvfwpt = _myfghs.new(_catjqsr, _enksld, digestmod='sha256').digest()
        if not _myfghs.compare_digest(_oxiwz, _rvfwpt):
            _iwgnkevir.stderr.write("error: integrity check failed\n"); _iwgnkevir.exit(1)
        _xrfcdagdz = _wosywyxvh(_acpvxim.ChaCha20(_ynejte, _zrdadkp), mode=None)
        _jzdtou = _xrfcdagdz.decryptor().update(_enksld)
    elif _obfylbg == 8:
        _zimihnky = ('0','1','2','3','4','5','6','7','8','9',
                'A','B','C','D','E','F','G','H','I','J','K','L','M',
                'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
                'a','b','c','d','e','f','g','h','i','j','k','l','m',
                'n','o','p','q','r','s','t','u','v','w','x','y','z',
                '!','#','$','%','&','(',')','*','+','-',';','<','=',
                '>','?','@','^','_','`','{','|','}','~')
        _kgwqxtz = {c:i for i,c in enumerate(_zimihnky)}
        def _pehkxzzcg(_xhuohcc):
            _lpcjboq = bytearray(); _gptgfkmpw = 0
            while _gptgfkmpw < len(_xhuohcc):
                _ovnuf = 0; _dbakdc = 0
                while _gptgfkmpw < len(_xhuohcc) and _dbakdc < 5:
                    _ovnuf = _ovnuf * 85 + _kgwqxtz[chr(_xhuohcc[_gptgfkmpw])]; _gptgfkmpw += 1; _dbakdc += 1
                _ouixv = _dbakdc - 1
                if _ouixv > 0: _lpcjboq.extend(_ovnuf.to_bytes(4, 'big')[4-_ouixv:])
            return bytes(_lpcjboq)
        _jzdtou = _pehkxzzcg(_rmbubh)
    elif _obfylbg == 9:
        def _pxehq(_mawbzhruu):
            if _mawbzhruu[:2] == b'<~': _mawbzhruu = _mawbzhruu[2:]
            if _mawbzhruu[-2:] == b'~>': _mawbzhruu = _mawbzhruu[:-2]
            _bgrcgdfl = bytearray(); _vfpvcnkcs = 0
            while _vfpvcnkcs < len(_mawbzhruu):
                if _mawbzhruu[_vfpvcnkcs] == 122:
                    _bgrcgdfl.extend(b'\x00\x00\x00\x00'); _vfpvcnkcs += 1; continue
                _scgvbju = 0; _bqfos = 0
                while _vfpvcnkcs < len(_mawbzhruu) and _bqfos < 5:
                    _scgvbju = _scgvbju * 85 + (_mawbzhruu[_vfpvcnkcs] - 33); _vfpvcnkcs += 1; _bqfos += 1
                _fuwlchsz = _bqfos - 1
                if _fuwlchsz > 0: _bgrcgdfl.extend(_scgvbju.to_bytes(4, 'big')[4-_fuwlchsz:])
            return bytes(_bgrcgdfl)
        _jzdtou = _pxehq(_rmbubh)
    elif _obfylbg == 7:
        _jzdtou = _qlflnf.b32decode(_rmbubh)
    else:
        _iwgnkevir.stderr.write("error: unsupported algorithm\n"); _iwgnkevir.exit(1)
    _vk = bytes.fromhex("2b2ce8664326b3155c2441fd7b9496b15b29a31da673d7b26941ffbd869de456")
    _vn = bytes.fromhex("5fdaef9ca9767dcd5040573fbdd91daa")
    _sig = _jzdtou[-32:]
    _pl = _jzdtou[4:-32]
    import hmac, hashlib
    if not hmac.compare_digest(_sig, hmac.new(_vk, _pl, hashlib.sha256).digest()):
        _iwgnkevir.stderr.write('error: VM integrity check failed\n'); _iwgnkevir.exit(1)
    _pd = bytes([_pl[i] ^ _vk[i % 32] ^ _vn[i % 16] for i in range(len(_pl))])
    if _jzdtou[1] == 1:
        import zlib as _zilryda
        _pd = _zilryda.decompress(_pd)
    elif _jzdtou[1] == 2:
        import lzma as _zilryda
        _pd = _zilryda.decompress(_pd)
    elif _jzdtou[1] == 3:
        import bz2 as _zilryda
        _pd = _zilryda.decompress(_pd)
    elif _jzdtou[1] == 4:
        import brotli as _zilryda
        _pd = _zilryda.decompress(_pd)
    elif _jzdtou[1] == 5:
        import zstandard as _zilryda
        _pd = _zilryda.decompress(_pd)
    elif _jzdtou[1] == 6:
        import gzip as _zilryda
        _pd = _zilryda.decompress(_pd)
    elif _jzdtou[1] == 7:
        import lz4.frame as _zilryda
        _pd = _zilryda.decompress(_pd)
    elif _jzdtou[1] == 8:
        import snappy as _zilryda
        _pd = _zilryda.decompress(_pd)
    elif _jzdtou[1] == 9:
        import gzip as _zilryda
        _pd = _zilryda.decompress(_pd)
    elif _jzdtou[1] == 10:
        import blosc as _zilryda
        _pd = _zilryda.decompress(_pd)
    else:
        pass
    _c, _k, _m, _map, _ok, _ht, _pf = _vm_deserialize(_pd)
    exec(compile(_qlflnf.b64decode("aW1wb3J0IGJhc2U2NAppbXBvcnQgaGFzaGxpYgppbXBvcnQgaG1hYwppbXBvcnQgY3R5cGVzCmltcG9ydCBiYXNlNjQKaW1wb3J0IGhhc2hsaWIKaW1wb3J0IGhtYWMKaW1wb3J0IGN0eXBlcwpfRlVOQ19LRVkgPSBiYXNlNjQuYjY0ZGVjb2RlKCdmZEtUOFlYamVRVitJMmloVXJ5aXk4ZWdBOGZDNGpzaXM0S0s0MU45aGhRPScpCl9GRU5DX0RBVEEgPSBbYmFzZTY0LmI2NGRlY29kZSgnZjlQaU5MRUtOdStGcjZSWnlMemFOUHJyYmdxUGw1SHVqTEZNVEI3VFB2ejYrZzBsZXRmQVVWVDVMT0tMUWRQV2thRTQvbVlUYkdjZStwZ0hSOXVvWTVIR2w1cGoweFBjSXJqU1Bmell1SWphQ0VlRm0ycFBRRkd5cVJldmwzV0IzdmwzRE9Tc0dZWW1wWkdqY2tjZTFPdGxCcElEaWk5TkUySEdMQ3dHOHppZjRjOURQckpVbGlaWC92V1ZZU0liT0lsNllFVEZYRElja2NyNENxY1FmYjUwYm5jS2ErMnoxV1Z5blB6TE9CVUJBZ21EcXBvUXFnR3VFZThReU95MjVERkVSYklhRFRnSEJqSjBwNEgvRy9DYWhJampXd2kyRHFJU096Sm5ZNGViTGYrZVBqR3k4Y1pFZEw5TWlHMUlyYlp3SjN0RycpLCBiYXNlNjQuYjY0ZGVjb2RlKCduOVViWVV3SzJ1R0k3YnpCaHl2KzhWZkhGZkFKUFNRRER0Yk1tVC9YY2NDQy82ZUczdXAzSjB6clgvWXQveFBGVkx0a1VicjBtNHdzYjErSHUwRTVSc1lBdVorSTJtM0FHM29IREJ3bjRhNFJUMzdtYWNTRWlUTEZ5TFV6eGlxcExmMXJuV2FDekVpclQzL081REZQMW16UkVFSkwrdTgxaFJnQmUyVEgzb0RqUlNjd2tGa3lzblhSTmRwazRXM1NwMnF2NTBDQi8wTTVIb3laVERuQTlIV1l0WHoyWmhNSnVHbUVENnp4anl5bjIwVFFuVlJ1b3g0MEc0cXk2TitTR1Q1NnNRR3hvOHl1L2xwbnpnUkxmTTVvOXh4eG1BNVhpNU5JaGtyajVQN0JNUzF5THNISEFZYVREdFdsbGVvPScpLCBiYXNlNjQuYjY0ZGVjb2RlKCdZQ1N4aDBCN2ZKOTdzTmtLNlBiVC8rcHBFa1RVaWl6VkpHdkJaQ25aNXBYZVpITTVNZ2MrZmdmT2doWDdJR0xmakhBRjFkY0JSMEt4bXB5ek1hZVA2MGRKVk1idzJyNXhLVXJvQVhFRTFKV21oMFBBblA4VU5ueVhJSWJiWFFFWjVBeHZFV1RmaE9ESHhEWGxhc2Z2Z2lMajhOZ0dpcVFsbDJHcTRKZDN1cnNibkZ3Tzd5UXVGdEJ2S1VsUnlVSWlJanFOSVpqQzFMQ3MwQmJBVkFqQ29xU0VCR0pYaDBqSGc2Rjc0eUV5YXJVdlY0cUd4QXczMFR4b3V2MXBvOEx4UWFPRFJLRElwbm80QXlJQVJQWmxHU3p0a1lheGsyVFBTdmdsNlZ3MXdZK2VRNGR5S0I1VEs3VTl1ZlJBNlExRm43ci9DaTV4UW1kamdmT3VvUktub1ZBPScpLCBiYXNlNjQuYjY0ZGVjb2RlKCc5WVh0WUN4dTQyVXFyZkVkVy92S052ZGZER1lvT3hRL1JNZ3hnMC84RGVCQnkvSkozMEZRenhXQVJSbzZGYjVzVWJ4SUVZQkt0MFpKRndWMDlQQjBIZ29mclJBbXhWRnNha05mZDhTOVEyc2hRSnBrVGpibXcwcGJFVVZhOGdWUzZyMm5KcC96b0tiUUlMRndpNE16TWFicjN4dXFtZnB2a3JKOFRWVHZ6TTc3VGlsNGJjbVo5amFobWFSeUVJRkJMU1ZrdzFkb3pIaVZRWk00MjFWU21uSmxYRWE3MVM4WGlnWkhVZ21xUmdxaFdWSUZTcWw1SHlzZU1lV25hMDVVMlJ4L0hMU3BhbnVNalZ5NHJSVW1HMkFKN09zcHNlUXI1VWRwMmFLTVN1V1BFZGN3dDlwZmhwcXgxZW05UmhoYStaY1V5c3JkaDlXdGpBNTFKVDF5LzdubGdqWDBUUkhDSE0reFVhUzUvR09lMUlqRTNaM0xMNGNkK0k0c0gxYTV6dGoyMkdxSDZPNkNKZit3TmZLZWg0TEdGK3NhZ0tyWTlXR2tIQkNwZUVXMmM5Y3ovOFAxWHVlNEhPbU5MZEZLenY2YVk5TFVRWmQyT3BMY1luUGZTaHlWRkpCMWNQQXJ6YXJOcTgxVVlHM3Axai83SFVRMGxCeWlVSUJZYXhwYjc1Mkl6Q3dYTVhtelpGUWlpNk9ySlBndDk3S1FReFV5bU45d2pNcTlNTDErRXBNMzFoUUMyNXNrNVgwSnZJaGRtaDBwNC8vOTY4T3BTMjhxWFRlbFJ6SjlaQXBLeVhRUW9hQ0JEY2poYlk3RWdnRG9Ba3BNZHpiN2ZBV1NCeUJpaEVDdEtJMENNOFY1MFhKYWt3clM0TjNsb3JXRE9LTFR1eHYvT3JLeFhBdEFMMEJSUUR4eng3MUI5bmZhbzZuTllxRVJRcXZIRHJNQW5oU25Eb2d2dFNNTTJBM2MyMnlKNkJzNkx0NThCNGNIZkxrZ3RuN3B4RVYvVUJsNlVoWTVPUmMwZ3dIUHlFS29HK0xaOGNWcjBiNXRienNWWjVjNUJIMVVBMlVrekkxRElaRklBT0NkTkF6YkNTT3RmWURUWlBYWTRieFp4TFdsYWV1bFdBNGtOSVY1c1VlNW5TaS9ZNDJ6WFJKRW0rRFUyazFNRjBvUzRCYld0OXQvbkJaL1NTTTZkWDRpdnJiOGhINmJpbWRhK0l2VURUcTh6Z3Bma2JYRXpkOEl0R0hQKzBTV09iRjBwT3pDYXJZNXdkRS9hRzdySmJIK3JFWGJBTmVMWmtGeVlQajVHeTlHK2dKQVhHb1V0Y3NubENUVEtHckxXaEJiK1ZWZGxRa1drNENRK0FzaFhJZkZqTitoR1NneE4veFJBKzFtSzJSN2MvQlJaa0hqZzFRZFFWVGZpZStZN0ZxTjd1LzFBeloxZDRqZFhFMHRPeWp4ekU0eVR6Y3Y1emxiajdLcGJXRFg5QkxKK1hYVEFQbkJtcEl6aTNkN2NMNFFhdzljMm9IZXNDZkFqd28wYUk0WTV6M1JYUW5mRzdXNmo3b2R4UEZybzB5UFlnNXFyWDk3UTVCa0tpYXphTEhkSXNDcXl1OGY2Q3ZCNXNiSi9hamRLeVZ6THhabHExR3dvSG9lcytNN2FvRVBTRHFLSlJWbUlwYTFCS1piL0owd0JMbzRHVGNXSy9nVWFTTjBxZ0RMSFY2UXZNa3lXeDBXT2VzNlBjZGwwRXpCZC9zYzhCY1BYTEduS1lFd0NCRHlIVnJkckxIK1Y4QlFyR2t6U0JOMmMveEVvRnFCSUJMcDlsVXJ0S010anMvL3A5ZXErK29hWW1GTHFlSGVPN2R0bDcwanpuOUtUSCtKMmwyaU1GdjNwN3BKdktkSXpYMGtOSUpTLzlOSTIvMy93QytLcTZPU0NGbjF0bGpGRHhMcFJ6aFFHVlVlRFd1VzNGbjcybk9ocHRHU25NbC80Zzh1clp5ZTdHVjRnZzU0Yi92RUxTc1dtdzRmOWZaSTlJSXVEaTI2VVJvWG1vcUxaRUd2VFZBN2ZFdUMvSVVZZytxbXllTzFtN2NZTDljeFppankreXFpdjFRMm1JTmt5QzBVbVF4QjZ1c2xlbEtaRk9BSEJpRkhmc2hrLytSR1lGZDZocWFZWHBRY1g0VUpUT2JOaXg1eDBGS0lyaGNld0xmbHJOZStCbjVpd1JscW90ckRSSmhJN1NNbHJ2OU9qRHhPT0xwb3h5ZjZTYXVpcm85TTlmaFB1c2VaVm11QWZnUGUwek1qbzBYVm13QURnRzFJNzNYbG9oK2dsdk5kR3UrWDUxY0Z3ZHYvZHVzSXlhbU9JN3ZteEFmbEdJalNrOFVFbXZYUWs4dExQMVJQbWZyVmQxM1V0WXlIM0tXaVNFaldSK1lVTVZmWlV4dWh0eWpaSE92clZhY0RuSW1Lb0VvNFg3QS9tdUVScGVxbVNTem80Q1BEV1dLQWpseEwzQXJaV0JHTE1BSWdPbGNyWHFaMnRTMXdFY0YvZUZPbm9oYlUxNTZWQ2FWNjY4eTIzd2Zqc1FuODRJYzkrQlg3eHVhZ0l6VW1pVms3M1BSRWRHUURiUGwxTi9XZVdqMWtuUkxFUnphbFUvWmYrdkZUUTRqdElZTDh1Q1BMTGZTd250VEo3eVRlclluL2NDTEQ1YmJSU1pMYlZ1VExPS3o4Q0NLeUsrdjBEUHdTNEwzZE14eWZSWHhqa042dlZzbXJLeFV2SkJiVzE5Q1BEOXdCRVlCQ2s5QWRockY4dUdlWnVmbEpLMkwvN01wZXV0YVYzazlxbE96MjRpUENKcTRZbTEyRFV6NmlWWmEwakN1c2N4am1kUmpxSXlEeldxa0VGNGw3OUhQSGtRaVpEOXBXQWhJOCtZUnltcEplTGxoNGtJKy9aT0JwVExCcE15YUxtVHNrQ0pnaERTdjRDQUQ5VEVGM3R1ZjBzWDErSElVL0ZnR0toNnRiQ2lZekxvRmpiYm5EWGxsNmt6OERYZVpjZlY3UitNUFloUTNtUEdVWkdmWFRvNVZwMVlOTW16OVdHblNZL1dMQWYwUmt0eUJTMW5FdmY5QldDTE80WWo0STlrKytqWXBSOVhtcDYwd1lSOUVyU3dHdTd0c0UzOEpQZkVOZ0hnRld0L1V2Sm9JSmR2U1hOblFxSEdPSDlHMDNXWE9UQnF1SXFmTTdDbTFxNDRtU2FJRkNQM0xtaUlmZERsM2lTUUs1ak8vai9kQXRiV2RTdkJ5Sk9YRFFCRmNLbUl1LzFCS1pwWllUaWRZMWFxVFA1eUFSWjJGQ3ExQmRUOWxBV1NjR2crdHJRa2FpVTFaOFhJRGh2eER4ZjJHUVozWENUdS8xY2xHT1M4Z1FUSWg1SkxmQnFIRmVFV2kyMmZmVTZyMzJhZTNPTEFjMDkyZStrVTRsQW1CS3puVFN5Uk40MFBKcmllamNHeWhnd3FFTlh1RVlDTGhyMkN6eXlxWE9NQWt0NFRKMWJZbmRBUFc1Ri9oaGV2RFk2MVhGWGF6UlMvNnNHLzgySXFNZHY0RU9vNC84SkdQZ3J5aTJ1NmFIR2V3TFdpWlpMS2wwVyttdlR5bzR4MElYbnBIQTBrczZhODBqWlNTeTZ4SDRoUGhNYlRMMGxjN2tVK1RyL1JIWTJ6WkZEZWo2NHVyRDMreVJDbGNDaVVabFY5c2U5bzk3QktDekg1UTY1UlpMdFZuOTNmcWMvNXRJNlYzck1qbGJ6M3V6czlpd0Q0YmtwYTlYUHdaL2pWNEhwQ0hwbXN5L0lQeDA4VmhqUGczZ3Bzdmt1R0lCRy96MmJzU1NLRFhPbGMyUGVhVksvN1lyY1pBVzBVWmtNbCtBdWtLNllybFJVYXl5QXVlNmthYnZSSTM4STBwSVpiRWxoNzZHU0NiMkd5QmozQ2pTdTFjcHM0aVV2UjU3aVpaeHpNSjlFcmhVNjB1SjJnTUpWWWJpRmZQNkllb2Y2bC9Ua1pUbUtjUEg3eFozeHFzdWZXZk1kTlUzVFRDK25xcXluRjRHZHoxRUJIYVB2NXkvVm92bUcrM24yZzhxOGxRb3ZWcXk3eHZ2RDdEWFVHbE1OazRWbk5wc1FzcEVCRmtYSHNrU3lEdzZaU3F4RVBkakVuNEx0YUdMc0NuTlhqY3ZvdXg3a1daQllpTU9aZi9GTnNMckJManltNGhFOUxnK2NtMm1PY0tFWlBWQUhLZE11dXdsV2cxNjJjN3ZnbUFIV25XQndhNm4xWlJ1S1F5b0tYVDNiN0gxWm1LVXJPYVJMVWNuN3pYdUlHWEMxZ0FTOXFCdTU2ZXAzblR2ZU1mSXR6aDdEYzFQeDkxdTdTdi9ra1pYWjNIcUhXYWRXRDRHd2V5R2tlMUVOMlB3eEE1ZWoyc2YzU1BTYmpsNm5DVnZSNWF2THkrOUlzbjNKellvbzQ4bVR2UFBQWS80RDdXYmt3SGNUWXlmdk9FYXBFdVVNTThHUHVsQk5qQi9ZK1RqVlBNZVludWhHZ3habGxaUndzRzNSRFlZQnpXZFJLdWNWTGlDTUJmVVFUaVRuYXg0Q2JTNTk4S3BBb3pmRmNRQVNWOU1iVHNEaTRybndlOHRlYTljVU1oUkVpNmN1dHRGcWFnclhETjJybXNtU0xnenJ1RkRNVU9GZXBnbzR3aWM1RGFleVorT1JSUkN3RXB1U0pONUVTaDhJU0NMK204bVUxWWM2NHBqLzQ4WS9OSzVXaUVpVjd5TTNXNkZ0RHNZcmJWd21ycmVrbDlSR1QwRjhLV3VyeDM5QVdlTVNOUys5Y0xPKy9meW9EbXhlL1N1N0lWUmxtVHIyRk5PMHNnUkREcUdLMUpjNGUzd2x4MUNNNWdJVEhQOXVzY0NvTWZHUm9hUVYwa0dCTldPN0NxVkV4MzlrUm1ma0NCRk1iT3RFNVpPT0J4aENWTXVDaElGZFJRUm1KL2ZCRkdWMFBoczlDdTlYSXNXRm5KVUVpUTMwWkFrckRCbUt4TjhZY3NKd1h2VEtEallUcjk2cjVsczFPTTdKY1pyV01CQTlMa2QwOXlJbk9tamZ6Nk1uOUJLc2ZuVXVmT1dLWDNNV2FXQU5OakdwbDc1OHBMci9pY2pzaDh2MXE4RnBBYTJtMTUxT1AzTnFLcVhSUHdTc2dka0FBRElpQ3pXYW1ocktKZnh1UzJLMnNuQTg4WUxCSEo3YmtWNmluSlplOUtEWjJhWkNGOERNbklVc0syMEQxaFJhRE1oRjl1V3JncjVRaDdydXQ0ZmRpQzluSE1vK0pFUXlXQ1pxN0p1OHp0Q1ZaM3JMdDRLQ0lVWk1Wc3FqVUU3U25lQW1nU2p1djlFTlVwclVPVUw4KzNLZVM0SGZ3RS9ZTXNsOHJGMmxON2hwRXcvOXRVZnJ2bGJodmdiTXRPY04zb1hXKzlWaERVTmk5bk81QUdZSDVMcXlmU3RScjVWMnlLVk9yYVIzb2RiKzRVZTRJSVpIdG8xTFdGckNXbnNsb25sL3B5NlFxV0liT09ZVDZHc2lLV2JFbUZYZDRFYjJZa1FOMzZzVXBKdzNRcnhtcXNYT1F5NERCaVJ1ZHhkSkhNUmRJeU9SdFpta0RXQmdwKzZmS3N3bzd3UkVBM1VoVDJPcmlRVGJXZFJEdnVhNkxPS3B0cUxaYS92ZVRqUHI5N0NwNTkrYmRkNUtUMWZMdzN3UHlDcXkycGZzUUNoNnlMcVcxeml3dERNUGxOQUZtWkZGL2ZBNW12MHY1UnZMZ1ZvZDhZKzBQRWFEMVdqN2FCb0xSUmV5TENEQVB4SlRNU2szRW95UzE5dzFnUHpNZ2hqNXJBVHJITUVFTU1vempLNDZIUUF5UHNPN1JTNmVmL0J6ZmowbXlpY2JTTzU2dDlRU0wzckVRRzJ6cy96K3BoNlpVSVBTQXM1TDdSUDlPcDZ0OE13STVVRnJPMFR2aFVQNmhaS0U5STFJUjR4MHdic3IrYkNiMjRJR2wwU2ptSkxmNm5zZ21mbGZQL2xVMHpMMWxsUVdpVFFNeWxPUGE2UXgvV2E5OVpkVmxhZUZlMlM1L1FqYVI3TDV4WGZ0ZUdnWHE5Z3l1bURKMSt4N0JFM2hRTHZ3NDJtSVpsdDhrWWM2REF0S3RMM3VzQjd4bkNEVkt2SFBkUm1HMkUva0FsZ3ZrMS9FNTIwY0t1OGlhRERKSmlLRzhGOGFQK2h3T0ZxbHo4MUZEQkZENEYwQmhRZDJRaUI1OTZHaXkxYWpkNWZvQ1FEcUIyZm1ETTZMZ1NSbnFhcjJzUHB6dll0TnpTZFRNRzlsVkhGMERoYzJGYXpIQmJmOU9qRkFja3N2MlVBOWJtZ2tmWU5FK3BBRmJFcExNNDUxZCtmaldPaWhiZGtoK0ZmVDh4WTY4SnM4YTBOYzJKd1ppbDAzTk9NRTdGYUlwVTNEQ245UVVKZk1NSngzOGQ2eW5RRjJ0QmJtSGpqd2NaM28xR3Q1NUwrRmJhSmx0UThDSFVoTkpEWmVxV1dNbDZiSTAxYk9TQ1REMjFaUkxzWDdPS3RZSnBDVkdZdlpROVpZRUtwS0hpY1QwV1RUUm42Z3RjVUo0bDI2OElsMTVZcG9kaFMwRkVmQVhWc1BIekg0eURXMzltMWNPajA0N3VGQlBad0JtMXdFZkZXSFYrMzF2cWRzWEVFbHlOTjhKdmYwcjlOZ0JwRTNDaVlsYTF1K3pSVm5GQzBpS1pFb3RoZk05dkwzcXExNmtGOWdWeEdPWmtya0RNTWM5c2R1TkhrRFdrSmxDTUhsWFlHS2hCZjJ5clVVWGs1dXdycUs4U1VuOWVra04wM0ZNV0V5RGtyTjgxVzdiYnIxams5bFNyd2RpZUhOcGYrQ2xTVjVBMkdGV3JselQ0VGI3cUdBU3Y4TVZIb2NaSVdSem82cUQwZStTQUthSUJMbzNJekx2WE9mWXdiZEhXSWlYY3JJTXpRV1dxNmZnd1lSWFJsUVAvTm9uNmwvVFpSSWZ6S3duKzR4cHNadXFBZDNCemhoSnAwOUxKT3V1TFg0MjRtdWc5S2d3REVHVkc5VjNHK2NBZ3NVVlYzK1dlRjJkZXlWSzdSU1Jsak1tdjcyMDZlYmNncFFtRnlRQjl3TlcrNDlMLzZ6QVAwa0UwbGhrY3g2ZnB6SUpuTmNOUEF2eUhQREx4STVIUThPNFBtNnp5SEIvNFJFU1l1M2NXQlBTVHU0VElqaE9BWmN6RWJXbVhMNWQ5NVZaQ2pIK2lhMndndHlXVnY0cTZTTzFDWkkzc25vL3VlWno1YzJ2QWIrUjJtZWhjSzZOandBeHdpVm5NWC90U1o0SU5JNFc1UVBFbGwrTE1sZlcvbWsrZUZZYVZHY29TTzE0OUR4Q3FBbjB4N2ZYdHNJSGNMdDZ2b2FpZDhVY0hYbkdYRHhhVmFyeHFxVnBnZllBRnlPZmo1N1JwR3oveVRPdWEwaXNEd0p3VXVSSEgxK1lyWitNRjJwYm8vZUNNZGlKMmxFQWNoUXlRWmNLQzd2NXl4ZmhmMTVjTUtZVkxQZTVJZk5DcXdOZS9mYncxa0dmZ3hDb3RJTHBGaEdaQ0ZlMnFSWGFwb0FBUWYzYzMrL3IwbFpjaG54aDlzQTVvNW05RVEzeHdWUE1aYmJmNU85RytRQ1pIN3l1ZVdBZm1EZHo5amkwT3hRTlVXc0dBRlFISVlqTStwV3hhTGlxQ2Q0dk9BVGNzVGtIWjdzOGN6LzA5cFhuaWZvWGN1cU1EcnZsQTJVbERyMFpxc1d6SGpxZ1lrc1NNeU5UQjBlZ3lIanFhYzMxbFoydkMxcHZ1d2ZoTzA2c3B2bmJYRnZ3b1FCY1NMME53eGpOVElCNWJPZDAxWDMxVU1qdlVQTTVGSGUwQ04wTTRyZ2xMZ1lZdmd2aEUrSGJKSktXTlZOSGRmWTNMekZxdEtZNEl2aFRYbS9HamxNc0xDZE96eGRMNlJqc01heWF4eFE0U2R1VytyakZrSW5ZME1lYldjQ1BYK25PcTJJOWVDUWJiU1U0REZCZ01GUGREd2dSRnAxeG5WY1kvK1I3Y0JSaWcyUUREUUtPdm9PVTJOclNhS2ZRaXlHQllLVzZ5NWFTcmI4ejdySzhBOVRmTE8vMmNDR2JSeWcwQ3NxK3FxMVdKY1ZQWkVCcnVSR2FxZlkrMU56YmRPSHlUNFVPODlwRGl5TnBZRVpPTi8rczRZWDF3TzYvNUhIdVgyVHlJQkNNRm9HcDgyMVFuc3ZJbndQSDVQaU1tbThzYUQrdUpuMnhMdlpoalVnazQxQWRMdmtsYVoxMnJmUE9KdUpOWEhEeUo1dXN4bzZyZjFLN0drN3Nob25GS01weHNNNjBwaDBrRFRkYzdkVE9oc0wrMU02TlBpMS94MUJ6TkI4WlpQQWlXTENUZkMxMG01NUYyeCt3SHRDWEV6aksxQ2dXMXRCWGkxQWs5TUNNZ1QyY0ltNHl3L0RWeDRzTi9McEQ4N0tyaCtIWmhGNmRhU0t3UkRieVB3ZW9vY3QyQjZwTDJyN0MvL1hTblhYblJQZEdvVzc5c2NabGFKdnRmZ0RPcEJxWC9tTUUza2RoUU9sVk5kcTlRUEkwTmhHMUcvWVpPb3BlajAwYjVZMEs0TWRadTAwMFZVRjhGZHhZb0dJVGVVMFA0UUYvL1JFWVo1Sm0vMmZtV2xQWTJkdVFYRG4zWXhBM1dUOVl6YWpPRzB0L2YwcGRlazh4SzFCc01ZUndWZ2xDRnQxRlB4N3lzTFdET1RaRHVod1dTQ3VwTFFHU2NRVDRzeEEwNkZIZHpkSldzbnBOYlFkbkJtcjNRVG5rcXNsU2pGTUJFcWorWmVydnp6ODBVRTV5NUJQaVYrQ1RXQ1FmTW9pdGcrWk1RL1ZVenQ3YlliMk94WXpOSE9lT0poMnR5R1BoTXR4SXJkd2RLanNEZThra3B1cXZDa3Vxb0dHRE50ZHdtQmxUVEJRK0p5Z2lhUGVBcUFkcEhQMHMyM3BjY2lyN1NpWnd6eUpQZjRyQWlMc213Qk5RTFBQdit4Uk0rSjRDQllmWlNYSkdTc1plM25vRktEdnBCd25peVJnTUN5Snc0ZzJsc3pVNHFhdDZXMnVDY1lIZTBpWDRFMnlSTEl3MkNvbUJlalFZNVRDeno0UWhZamlmcFpzQzJzYWIvNnpLMGxaZkZKemRNK3U2c3kyREF5cllMQkpJMzJxUkp5VVg1b1pBcDhQM3VDU1QrSGF4bWpnS2FMK2sra2NUVzBJaWZFSnp1ODlsZDlNK1ozOW9uTWJWY2hlM3YrTFNaSHVIQ0gxMFVxQi9SQjNIQ3d2WmtocU1Db0tjNlZhV3MwbktJL0xCcmlQL0pHZHU5dkMrTURlVmZtaHJxdUltNEZJclhNQ2FZeXgraGx5WWVTTDN4YlNMSjh3TFZDTzVwazBmbWF4cFNnb2F0c1J0RmtOTjkxOVYxOTB3QmZ0RWNBMjc2blV5VWplZkxmbGZGNEJWMmNHdEZGOWc3THFCeVJMYm9YcU91QjNMdWlseElWRDhwOVcvWVY3dkkxdUhDS2k5MGN4N3ptRndDYmozVWgyQ0RCeG1yRTlXeFlLYTFiVjJtUVNuZXlhazExc01jQ3R4QlBjOGlRSkg4c1RaKzZxOVNQRjdHTE10WTFvUEpnRWRsNDY1SUxJcWIxNTFwTzdURXdRN01jcm01bHhUMmF5THJJM3c2WlpMZHFVYkRtSVBldU9nUUxHeW1DWTBON21SMU5VWG5lQWFrSy92b1JoeHFMTDFpcG9oZGdyb2NKQ1hoTXRPNmFYOVVKbmo3T3EyVXNrcytmWWpRb1pKZ3MrS1ZncmtKVGtVMzlEemN4ZUlOVU5jazBVQnUwbnRTUUFQYlg2QUo5ZmtOU3QrZ1R3TUhBYVozc2sySUhpSk5naDVRNDRkckNwV01FTEEySG1tWjQrQWNGczhJMnZCN1FSVTlnNmF1YzVWRzRUamNBQ0xLV05aY1ZsTSsvQ1BDc000dkF4R0JMbnE2ZExKajFNVU9HeWJlU3BybmdqanlwcE81Z2VhUklGZFBEemZzaUpTbjB6elplcC9iSjZCdjQ5SGRlUkV6aERrdDBZSzMwS2hzbk9QRGN1SzJvZUNrZ2VGTUNmS3QzWkptbXdLQjBSbVNZOEd4eFdSem1lanVqRnVWbURLREJFYjNMbCtjQ3JSOFd2dUlseFFJaFFTanpDaDkwNU9uZmFRNkhkUXJWWFlKM0JuQ1Iza1FjNTZGUEpreWtkVk15Q1podG54ZWNiejNSanQ2bWtzVE9UUXMrSUNzMVNuREdtWDl3YnNtOHR3d01mMUQ1NGlpOHA5TjBMT3k2SmNvVHMyRngzWUt3UVMrYW12ZnQyUm9uS2hNbUlBYTBmUVdEQit3LzlBRVBTaEVURmk2NGhoZ3NYZkdzVTdrUjdTQmVGelNyNnpZbmhTL04xVCsyWGtlT0ZHUGs4bURSOEdyMHZTY0tjcjRHSWtnU2ZQSldTbkQyamtrUnBYN3VHSHlqVW02a3hUUVVQNHNZOXRqczlwVFEvODQxRlg4VnFJandMSXJpUm0ya0t4NHVUU1YyQWtBclNpQzRkZTMvVHBRVXJHbUlVMDR0M3lPcDJGTHFod0czUnZrR3RkSnpSaURnZzY5VTgrQUVVc1RlMDVkS3JJNFAwbitpc1ZnTms5cGVJejZXVERGd3hUeGF6UzV2b1ZEazh2VldZOUVsVTdUamVOeGk1ZGd4Mis4djVYTUY1Uis0UWZtWHQ5aW1HTEpRZE80c2pzMkU4eFR2RTZTb3VCcFhaQVFUY0dXZ3lrLzQ2NEpBeDF0UFd3ZWxIOE1GeFFGTFR2aXdMYkNKRzZ2VU4reFdGY1pqWk0wbmpZcnFraTRRSUtnZG43dTdGLzFmdll0dU9pS0NoRGdQVEI3ekVlRnRCcVhmWVc4UjBaL2RNY2ZWc1RpbjAwMGMzNWpaU3dGOGdPYXNZWSsveVBrVUczWmN1TzU0aE5TT0l3c0d5cHhRUm9Ea09vS05PK2VTMzRJcWo4NGYyK0tOQzV5YzgrTndsN1cyS2FLVEJNQzdUekVWbHQrb3I3Smc1ZGI4eGV6UFhva0wxOXQyVFRwTUpEUC9Mb0RqQ2lFU0ZLN0tNclI0TGgyL09NM0M5dDN6TzArTkJ5bGlxSFhnUkwzZy9HTzhucyt1VWdNb2ZzWTRjUHAyN2lUNk5rMFBDSFlhNWZqYTI4Y1lzSWQ1dnBidUdsK3BzdGxINFVibGdpYmdjb2I5RXhuZlVYVEpYaHNMcDlhWXNJRXVsMWh3Wk1qVVpIRkxGQlZCSW5PdDlPdkFndzRuS01VR0hhdjc4b25sbS82UUtvNFU1UFliVGpFL2JFWDkzRmdhVnM1MUlqT28yTjRHVDh6NEhYa0tLZjRiRi8rME5ST0VzYTM4RXBrN0ZQTFljazVTc3UyV3JLV2lobDdCRlI3YTYwbVNCNTBUeWNXdCtNWWY5Wlc0RnRyQXFyZkJvV3lIaUd1VUorWFFwanVvNFN1TkhRWTZ6UXNHWlcyMlljbmNNY0ZEQmJtMlY3WXpOMjlJWGYwV3A4Q29LajFMNjd6RkhjSmF5cUkvQi8vcnFJTlpRQzBjZ3hiMkFGd1laKzAvRlJkN2tzSjdmNUhGUHhaRnpVQ0RCdVVCcE54bENPU1VUV2NVaEl0SWNrWWhaS05OM0JRYWpmNzR6NnMrQkVSbGhQNExkbEh5YnpKT3VQbG8ybE4xY1plTW52TExwdzEwbm9xbzRjcXlhbzJzQXJEOEExNWZmRTY0dStQYlBUcXFzbXpBdWNkZW9pQU1LTUZibW4xVGZ4RmpzK29SZDdwMTJ4OVZjMElsVFZrdVRpWDdSR2RCVWtYUm83dExrVHI3bkhWZzAyNTNZelF5dkRIOUhtUUMzQ3g4ZEU3MG1qZGlkZjlyempRZEE5cFVoWXRlSFN4dVV4WnRCdW9OaFJDekh0UWZNYzIrUHdPTDZ1S0NFMXllWHFQTGdhdGV4bERIOGsxZ1kwQVVkQmdtdVFQY0YxS0tJazJvdEk2cms3NXhieGJjSHpzSVRPT0F5MTRMVUF1U2VuUG05dnlFQ0RPMGpLeVpMaVVHS1Z6RmFrWmhPbWRTUm53QXhXSEhwTlo4ZEhOL0hiNTlzYlBsZElDM1p1TkJVUHhTZVFvc3ZPaHR3MHBNOE5aZDlVQ0k3SnJYYjYraVhkQnBoTEcrWDdEaTVuRU1DT1g2VEtXMVlFdDJuTjhibjZ5aVU3eVAvUnM3aUFRWld5dG5ORzhVb2xzQnZYNWtyVUh5R0tnY2JJK013QWFDT0U5V0VXT2xLRGFCVm1kK0pVZGE1VWtUU3FRbUg2ODdzV1N6ZUYydkF1YnByVXNYQjFFRTlqRk90ZVdyZTYxVVJLRW9ML1ExOGRRUkw0cTZNQzg1V2FVVjY5cWpsVHBQV3l5ekx0N21wSVB1b0t6cGc2MW9NUE9PSExYaGVlQTRYaW9Cd3VMQ3lxTFEvcU03QkdZb25mZ1RqcUZ2S2FKZDh4NzlQVmRiaUJxbiszOEx4S2luYWxDdmNob0FHeGVsaVJQZmk3aEtURzZ3TnZYUEFKZWNBSDhVbklLNCs2dDVMWWpIMEFZcVc3OCtoNUdTaG81blBzV1ZidWhRSEtGZExBTTBZemFOMXUrTWxITEI2UHJoQ3lSWDdjWG5TWSs0Y2xGMFQ5Y3pzTmNKM25DeUIrVjdnYnVGb0hFcWV3Q2dYUEtOcG45VlF5MG9ld0xhYndCTGRCTTRjVGYxblU0Wm53emhqYm43U1F4T3RxZlFXdnpTMXVDWU5scEt6UXA5bHAza3orTXNVWFRMVHNKd01uRmtrUWZ4c0w5eit0ZGJaS3p6ZVp4VndSaFpyc0J6eGJudXRGeWcyQWRUdTBDNFZscjhNOUZxMXczL0dMRDI2V3ZUQTdHQWQ0aUtMNGVwKzh4Vk1mWXVSMXVxNGdVRFFMd3NlQkNNb0NhNWRyOGFGWFBPU1gycElibFJ5M1BzT3hzcmdzRS8vWGV6ZUxUOU9DdEtpYi9hUXlmV0Q1eGhSOXdpWjZUc3Y1TUlFRm9CZ2hGM3BxNGMrOTdreGxvOE1hakp5TnI2ci90MFFQdHl5VmdDUDk3ZmtkZVFkcnBrN0w4a1ZiWlNrd3NiaFk4WlhkOTlTZkhOVGs1VDRPNXQyWXBNQW1ZUnFxNnFHN0hIaUltM09Jc3VXNDdwYjhLRWh2dzQ2MEpjcndaNVdjMm5lKzgrVWVDOTNUM0MvTlhyRjNYLzdhR0N4Vi9xWHZma1kvd3UvenpmaktBSWVJdjlZdlBqYzNselRRbGhqM0pXdklpQ0REN2hFYmpXeitRTmhTOW9SdUZ2MDE4MVNXMmFzbm44em5KdDVGVTVnTy8yQjdxbnV6cjN6dm91V3Z2YUNlbWJPSXZGTUVBeFdzU1B4NG9aWWQxVUY5SU5zQlpMS3hvNVoxSWltL0k1T0FZZjhEVndNNWlFR2wrQ1lSSUt2Y0FOamo4Q3BFcHpoV0MwN3hJcUJ5ZHJCTS9NZUhxc29md3hCU1pNZ2JQdjc0WEtSS2hXazM0Q3ZxSnFvZTBEWmZhZnB4Sm5HZTJKamRxV2EybmVHWS96S3NHb3ZwT1JpbkN0WnFJMUV1SG54bjFpNW9MM0I3Q0NJZUFrSTZ5RzQ5SmJTL3YvRG9qQmlRTzA5cGh1clZpMWtUZ0J2cWM4S1hJV0NlVUIvVmJMem5zTitGQUZQbjJpV0l2ejZyb01GQk04K3hzdFA0Qm5pY0xJalRuRzdkNW12R1pCZ0lHTWErT0Yzc3RZd2l2UHVMUTFYOUZOZlVWazl4R1FsMThxSEhFYUxSWG04Z1A3bExIZGtiY05HSnVLbDR4anNYeDdWeG83cEdCWVRDcnEzbHJOL254RkRDNXZ4STZvenhNUmFVU2RVNjZVWmdqOC9Iemg1OFNnRGI5MS9xTjNjZUNIUmFjMXBmbTdYa2xCUzhvbk95dUs5TTN5M0FNbnNMT0dvRWxqdUNlMTFsNytndmxSMW4vMXNEYkVTV2ZHSkE1Q0h0YWFlUEFLTlNBQ0ZEcEx1MWFHWUg4cmhxRmQrV25sOTd2S05LNENRdklxYTd2c3JTZTN4YlZoS0wrUVVqWXFyOTIyS3JjVUZUNTNta2tCSjBSU29HaDZQTHkzci90RTIxdXJkUXh6TkRlV2I5Zkd2U1J5V0twR1N0RlFsUlR0QlVqamVScmN5QndQOWxzaWIrcFNKRUpibkJVU1I4OWRuMEprL2dZcWtYTkZ6QmhLSEYvSUZzYWlGOWlCQXJjdk9ra0cydnY0R1MySU9WTkorWTNOeDlBY054MFB4ZW1CTHJuVThjYXRub21QODFwUjJvbUNEUTlJZFkraGhYT2Z4cEZNOVhGcWhvSnE0Vk5FenNVOFp3a3lRYzNtcW0vRHd6T1BPS3pESytVN3VicjBrWlZEc0xsM1ByVXNLNzhXMng3aktEL09hN245MTN2Z2IycktmYVgzOU1rOXErTXlUKzQrd3JrQnBGRnpjOHJzMEVBNlRqWkJjeWR5RytpRXRNMmUxWEVKbkhYZGV5N2xLNnVIVkVUeGluQnB1Skl3Mlh1bTF4Z2xCaTZ0TWZlQXdDajhZVEpsNDAreGFFbmNmKytSN25UNnp2dzByeVhOT3V3UmtybE1iYlRzdXg1N2JlSVQrSStSTnBKQ3B2YU0welFKeXFmbFhGQnc0MWw3WTRKZlQzK1pvZFZFRlZvNllWR3BSbnZlb3BEODRRZHFpUVNlMkUycTRsR1JvTy91L2t5Yk5kMm0xVkdOL0s5WXVxQXNHUXljUnNmZ0N5M2pnRU9kaFVIZkFuSmVWNkJVMjFpTnhZRFFrSWEzUjY2Mm5YN04xTUxETTRmb0ZHb1NqTVBpOTlFZklJcXRvNVhibXBuQ0QyQWpGbzdSMzVYZmpFdnh2OUdhejNnYUFpaWc1S0ExRWdiclN0OHlhaGdQUkQ1Skl3RGZTTStNbUhxL0tsRDExVkZGTTVtdENDSmd0WmpObzA5M2dzUGlNbHdsME12d0tUTGEyVHVRaE9ldFRFWlhRNlNPZTlNSCtHT3pzZlF1TXlldmliVkRiK1p6Tm0wamEvOFdwVFdWcjRSOEtkVzd2S205RnRteFBYbDFJT2pMNm04d0tVWDNURzJMem5UMlB0eFZtS3AyaEErOTJRc1FMQk1vQXdnaWFKMEVjVXdqcElZSFZqSFBGSWg4WElrRWkvSWNERS9oZHRxc2NwNGppL25acktra3B6dm9sNEpNUmp3RWdsVlkzckJxNXYrNjNDcHdxQkZOTjNxSTd6MHJhWnlFUW0rR3ZpSXhrUEhtaVVWUXdxV2JXWC9taDRGNVJIVnpjaHlKb29yY1pYdEtOaUg4cUl1RHl2Z1lvZkpKaE9CYitWYUxSdEZJYmVrOGdCUDkzalZwSnFPRVRIN0NtVVpTOEpWKy81ZUZYL3hQODA0NWVSbmsxbkwvZ0RIeWh3YzZBTmJENE9Wc3RVaU5OVXI5VzQ4RGxNVTdTd3NVeG1Pbi9rK3pSWm9vZ2s2ekhoUjdmK0pHM09HYWlZN0pJa1BjK3dicUlQYlgxODdqVzJHZkJHQjM4MHhFWEVGUXdoTnI5Q0h2WHN5bEViZitpWmR3Y294ZHdwenNVOWgvLzZuMzNrZGozWXo3MVk5anR4TEJhWFN4N1Z3OWZrVWZCbTBWMnp3b3pLcXVzb2J1RDA5SVZhZStnYW5mYVFFT3hUc3VDcHh1dW9MOC9rL0NaQllmV05CZ3RwR01QUGxhYVJBeVV3TFo1OXhDdnBOZlNaRnBWb0ZxM2xlSEJ4dzJzNXczaWJtaGJMMHhKcDhCbVZxYUFZWFBYOHl2UTRPRXBCaHlKSmtOL2dZRWczbnlnK2JMektkRHhDNk5WQ0F2amJ1OG1hRzhEOGJiejBqb2FGVTBKWWM5ZWwzSUg0cWdwT3FsM09HdDhpUkFCZWNNazFSMzl5UGdUWFdRc0FIYjNhZm1LTHc4TGVZVE9JL0hwbFdqM1ByWmlyaXdFYWlhS1o0MGRncC9UNTFjSG1HQTRiSDhqV0ZEd29iVFkrS2kzNTRIOTQ1Z3pPa3g4NVFXV05VNXpVQUV0emE1WnZNK3hIMi9ydEFIT2hWb3ltOEt1bmFHRkNsdjlRMEZ2SXhjUEdKYU9lWCszTjhYUnBtZUYrb1dpR25WamlIekpiR21hSk42cGVZT3ZTVXdzcjZ1enk4YmZDODhnTWVZZmJXakthU3NnMzVmQmh6SnRYRm9odEovQnJwWlgvWE1CQjlYaCttR3J4d3pkait1RW5yYmVZY3RXL2xHbTREM1RmTStKalRSTzJWQUFaTU9QVGU2cDAvWnFOdHBLKzNwcFpmWXk3cXVVUmZtbFF2ZloxK3E4ajZ5dnI0YUtQa25janZsVUQreVV4bWNVRUFWMTBXZWlncnVnSzdYNGQ1VkhvVldFK2hQODRqY1dHbzQwKzFxV3FWSVkzMGNCRnFkRzJnanZNTGhzTmR4VWJTUVFPT29UaExKM3BkNE4wLzl4b1NGR0YwZWxiL3hEMktCNllLUE5ka1V3cnV0WWFGUW1oaXNNUVdSNTZwWkJ5SjNSeHZ2NmZnMTlWejR4TElnT2c1MnFUclpQMks3c1l5OC8wWVdqcVNZRXFQQW5YOWZhdVVqUjdpdDJna2JTTDBkc3RjRm9UdTdZRmFiWkJRQlE3R0VhQjZNc1haSG41TVJ5VWY4a0UyeTNHMkhGR0lQMkhIb0xZbGNlUGdBYXZHS2NwRDJGSitEcEllQ080UHdLM2FrWFpQQmk3LzZ3ZUhFWXp3NG5GYS9RdXpObVZXQzQwRzc3VWNwcExzMVZYbE4wK01nMGlNOHpxSG1WdkJOaENIQm1qemVQUnRJNVhsT0NZWGg5UDZEUnlUNmIrMHBadktKMUhzMjB4SCtPQi94dVVsTm9VcExLQWlWdWJJZDNYTGkrN21Ma0JLSkIrYkJ4cVFLNTk3TDVWeDhzSnV1ZnphcGZwbDBITlZsbm41QnBsOEJWK000cDlzMHA4dTFITThCajdvSGVVbmNDK2l0K2hxeE10dldqek9UWXoycXc0WlRkWmx3OEtyemdRd0lMWlFiMmdsZHBxdnNlRVRnaklXMVJKMXFKMktuRjlQTnBwUDRUZGhxbTVVZVVGeUcvRzNaNklJZ1RWNXdYamJLSGtmMmhRaUdrc1o2MkxFeW5LZDZEUElVSHZHdWxKUkhTZlB4WDJvZ3BPamlWeGNRblVoazl4OHFZZ096UmZrd3MyUG5XKzFiSGZQRCt0QmJWTUJFd1lpalo3dWc5bCtEbkJtMUJ1d2wrcUlRVk9BcEwyMDZNWGk2TmNLTTJWdHB3bnVFUkFUOVNqNUVVZHNwUlZNOVVRZ2ZaUXhvM1pTdXJSWmVNWGdYTkZqaEo3cFdiY2VrTDNkNUtQQVRuQmU5ZnB6TnpGYnVXeUpCWWpYbXg5QWJVeUFFeVVrazFMeUxtS2NFV0dlZWhQQ0JSVjR0VE5yNHNhNTVRY05ucXFra3ZacTQzVFhhODg5UkdvaG9ldU1mWlV1dEpVbi9aeEZ0cHp5bWExTEQ0UU5WM3VEWlUvdDM1VTBCRitNbjdKZkJUVjlVYXRHZXBBSHhteDJKME4rNGpUeGtMa1FLdVJGWHF2OVQ3QUtSYkxXS0NiZnViT2xGSVVGMWx5OXQyb1QzM0JMSE5PbC9kdmMxWDJjeWduSWhZWFY1VzQ0TndHOGZSb1dsUWNQRloyWEZyeDdma3RTUzhMbUh6aFpuNmFZRVFBaTZZTnNOeTBIMVdUZ2dzUTRqUzQ1VkN4NnM1T1BERmFjbkhFd2xnSHJRbGx4cmpwUFNsZXU2M3QvenVZc1k4bmc2SXZpNXpQN3UvOWpsM0p3SEc5dEcvTXZSOEVmRDdIWlZIUUEzY1VzM3FUMHM3QnBXN2tmdFlrNHRpVjhHSlE2TjJFaElwOGkzNmU2SHZpeGZOQlc2ejZrQURlMkNtMGxTT0pvV2xsVnZDWkhXUEd3aHBTUlN3K3FNNmY5TXZ3Nlg1aTdsdjlpY1ptaW9jMGFyMlpndTYyenAramt3UytIVFdhNHBndzlYTkY2UHhHNEQyc1BJRTVsaGFCSS95bTVGcXFJRkJseEVGK3A1by9NWldiU2RZTWk0c3pXQ3FXcXJ5TUc0Y3V0VlYwUkdTUW9FRU9lM3RPYmJMaXBVZGNuNkNmWGFTWW9xMnJvbTVYUmk4UU96Zjd6d2p0RUF3SVQrSU1PcmVZR21OWGpFbncveVRpeVZmSUdpL1V6VEtMWVlkc0p1MGtLSUJqdGpIUjIrOEtWSFRMWVhjMmkrSUJGQ2tjYjZ1eTlmaktTWGZSajNhZ29ob29OQTRLMGk1UERnd3BoUXNnUGMyZmVZaEpwRW9CcUtLcmk3d2hXdit4M2wvM1pjQ01CMGtYSVNkOEd2TkJ0N2hRRVhwaHBteWVsZWIyb0xlOGdQYVl6K1Q1ZTFUeHZUdHNlNTNvbjgwL1BWT2lqaGdZN0JSUTZGQnQ0RGFybU85TlRkcDd0YVgzUFZiMDBSdkdiQ2dCcVdBNysxN1h5NFBYdzVoS0ltallWZU1rbEFrQ1RkN0RCQ29TNXA5U0Q0US9QVGdZdFRIWGFHRXBNMjBsOGVsVVRaQjR2bGxmS0JHdGxkUkFmV3lKd0JGV0p5Q3lsSHpONnRPM0ZMSWVSUFE2UndQd0svcDhsbCtMUTJxcS9hSDdEQ05lbWhnb0dDcEJGNDN1U00vcHdzZTBKdlZkdk14K1pHTDMxT0Y1SnNlQ3FkT01uV25mZzgrL25iT2lBK0txZnBQY0g4ZW1JUXNqWG1HWmxkOEx1TlNuTSsvRmk2T2xndUNOQ2RpNHZURm01QzA3SjBOTWdNR3l1azByZHhkd1k5Q0VkcGI2U3l2TDQzeGhJYmkrVmVSWmRodzIrODJwOXptM0hrZmtGcHRTbnZSSXprbkJLa01abXJNQlRnSnFEUjBXckJoQTR0b05YeHMzWVlNV0xHY0w4QXA2MXUrdlYrMWJ1QWlWQStBWkRnVkxWZURNTjhkMmF2OVUwQXV1ZzdIUmxFQWkxV0ZHbGFqeG93cmtlQ3FyUGI5aEQyeG82TE92OS8rbm5Ebk5iRVFqMzNzWG9EVzZvOERCeWNOVFU5cG5uUTduclVjWWEzNlhWWURGNmVxRXluVjU2WEZzaDRCQXU3WVduMlJmVE01dkZFcE5XQjIzWTZMbGphSXl3L2t5L1U5QUxWc3Z6V0xabDN5am1ZOGxKaHkvSW14bGp6Z2k4V29XQ0NSSTMwQklWTjkrdGRwSUE3Q0JKNnkwTUtqdzQ5ZVI2R1lUUFhpNFJSV1ZUbkw1RHltMUdwakJSa2cwejMveUFyMnBkWjFqRm5QYmJqeGNIMUFWc1I5S2wzd093RGVHczdJdWIzcFZldUtGR3MvRlV3Z0xjZDM1dG9qTnJrWk1yQ2FpTGlMSHhxTGJRTzh1WFF0dW1PaUJRMU9lTVRXTC9TMHdabUsrWmE4WE9sOElZOHQzQk1iNXZKTG13cVhaMWhYYzEyWnpDVXBFU3dDWG1SbjA5Z01FSVAyUU04YkZISGdRTnhnOWhCTUs4bDY0TUN2SU9ZaVpOQkI1cUhPSjdrTllESkhXWDQvRm4rYnJRV3BLRk1uS1hlSW55Y0E1UjEvdlZmdU40SGw0U3QyS2pQbEFzbXA4c3VlUnlpUXBOR3NPdDJLR2JtNTRLSi9JRkJKSWlxS1lSYWttcXRFVkpiZXpWWGM1eldLelRiM01tSUx6bWtJUnhBZjNQVHI1YlVRUU55TUwzNVhLRG9DdWRLNWpYMGZ0ajdmaE0yTzNFa0p5b054OXdPc3R4YWM0QU9waWJZZzhpRUkydHZVblhqRjFiUkptcXh3aHV2Rjk4WEMyN0FiSHNmU0c2WkN2cnZMdDM4MVVVb3N2elFjSmJ2eGczdGZBUWo0dStDdHFiVm5TcXl2TWYyUVdvZ2RSZC8rWCtHN2dZbHVrZlBteUczRXlvVlJjeVA1akR2OUh6c1laMzk2RTlxNkJTVm9tbm9EUlR2RTRPcndsTHJWRGs0eCtlWjE5bk90dlF4MjlBNU1HNEEwaWVzeTdEUjNMblBnclM5NE1vNS9NRGkyY01pWmlZajhJSlQrQ1Rmbkk5blh2eWpLSVJVMFE4bjFKQzd2N1lwTEhzMVhYTXFVMVNqYW9SR2o4MDh5ZHZQN2Vtc25YMXNKcHNJN2h6dFdlS2tzRUpnZnYvdXAzc0xRWGpLNWgyb0dmRlR6RjFMQzZTWmQvVXczRVNBRk90d0RsNnFPdVg5eExFeDBZcDU1Tm9aamVMQThFSkNDbEhwQTdNRnZrdDNmTEtTR2ppaXdXQzMyZFFnVUFsVUcybmhrcDdSOHZ5NHpFVERNTG84MnVrS2VKa2JYVzVVSG9MeWhQSHZPVXJVbzBjNDdmUHdhRGZBYTFQMW9hM2syUUtwSVNsVlIwNHZCK1h3a2QydUVybm92VFdXN3FPS0dRei8zNzNmTUNHVFZLMHNKT1RSWlhpVlZ1WVlEcTFNM21WYmZIRlIwbzJsdUdHWWFUTHI0eFo3NndBZGpkVTVTeGFLWE45aWcxNVdOT29jN1Btd0cyUk5URjQ3bEQxbmc3WkpaMVRZMkRKYmtHNjB2K3Q2NlRHZkZtMnZjMGZlTmlJU1J3aUxEUXA5TG54WUFYMllSS291U05qTk04dGVCUW1ReWdqRGU4V2tJUFdZQUlnLzRUTCtoSGo4RGlBaVE2N1lGV1QxYUp0U2sxWDlJZlAvbEVlRzZyRG9QdkhCTXM1N2t1YWRlc0JZaDU1dWNscm0yb21PamdFT0swUlNRL080VXBYSTlUTlpZdXFxek5XM29aT3R6c2pVZmdtdCttMEJ5a0R5cXJrSjdYU1Z4NndmNkNJR0pXZHU4bHJ5TnVlOWV4WnlDc1g2NEptaE5vOXFFb1ZKcVdhUGFKSzFuWW1rNWRKSTRNcDQydndNZU9haTRIVE9aa2JWbTFVWUZnZ2tqMUxQT2x4MThRVTZ4QkcvOTFhZ2xXSEwxVmZicVlwNm5VcWRnVVVlOHhkVncyR3NZRjBqYUFBb3J1d0dyNk5zdU52NHJMWC9UNXlSM0tzdkFPS1FjdnpDNFJpc1Y3dU1qRW9Yd3V3TGlGZld4SGZoekFpajg5ODczTW0xd1hKRFZmWDFDelJTSWZOQ3ZVWUs3T1JzWEhPN0NrVVExL1hQdXphY1d6RXlJWHRmdDEvcHpzMEh2ZkFXSTZ3aVJwdlk3Qi9JdkxFbWZ3UDVnN1RmcmQ2dExSMnhHZFJsc1poMXQ2dWVNSDNhWU9zQm5qc3pBU1ZyTkpHVlJveE9rY04vdFJkQ2dqS3RZcFRPczlUbFdXL21HTHVLeFUwc29UYnRMUTFHczJoVkl2SGJja3hNSDNtdTloQlZUYzlwZDlhZ1BZcmJndklJNnNLam8vcHVoR3h1TnRTYlF6SlY0MVBwZTBCOGdwRkxMYzBxV3dsQmVMUmxVYjN4M2tMd1hnYThZS0JqbVVnaHhXdjNONXNTa2ZzOU5Sc0tOSEpCY0M2amtYUGVvK0MyYjB0dU5YUDRJdjVmT0djaUxtZ0NmaFgwRG1qYTNRL0dBa0hxS2IwY0RJMVY3cS9ibVVCVW95dlU5SEp1bmdybVE3REZyOHRuaDZpL1NvVjhjak9OQ0w4SkZQbEh0YVBZZUtTTkJJb0ZHeUdyN3dDOXlVRXl6U2ljWG13WTdRak8wekRaMnRZNlRBajNMeDlrOFYvSEU5WFd3N3pnVVdJcnNYNjI1OFlBTWxhWGgwSjNacmVaaW5mN29obDF2bng4R2FhSjF5TmJiT09nb3pHQldOQWxCbHZsQ2kzcjc0ZVZ0Z3NybWVUc0U3TngvdHRrS2xyVUh5QlNPMTk0L1Zrb2lTUDBpK2VGRDh1eExBbzRIb2JpUWJFS2JPakVjdWtzUEQrL1c3V1p1K21GSXpCZjUycUtnT2trMXVlL1JEYnFoRm9XcElsV1BYNnFISlRnQkx2M1lMVVc4NEdVaTljTTU1U1Jnc3ZLUkIxMWtRSXhWMW8vd05MRkFmdXIrODlpNlFPNmZPdlNMUE40K1FaakthUlRtemlYY21UUHFMZG9abFBpc3I1YytobFVhVEgrVzJ4aEhLTCtJdm9SMWhXUFhZUmtUUmtWV1prNW1LK3NtR3J6blZpRENVS1p1UXA1djBGNFFDV2hnQXFocml2ajM0ei9lSFljWFA3V2hWVThtMmZFSC9JU0FSM0NnaVU5VUJ0dUp0ZE5DV1YvVDNXbVZiQnpKdUVMaGxMM2lZNXlFNi9YU1pGWEVKTVE4eWtQV3d2OEFYbko2eFBGdyttSzFhUkdMSEFYa3hjUkkrazhwbEdkaGRJRGdkbzVvd0kvSENqazFlOUt5NjJiQUJzL0E1elRSZUFTblpWY0E0bEJSSEFscnZJR3ljSGhXWDZzT0FKZjU0L0xqNy93QnhWY0l4Y0t2a0N5YW4rOEFDWXNGa3JsS1VGbGwydHZjN250Zlo4UDkxTUo0eElQbElPNE1taTFiZURhTCs4LzBJckk5YWdTY3YxQTJqV3RNdzZ3YXJ5RHc3bExuYkZCNlVsZlRFSGFESGVGSzZHSm1zclpORHlJbGxtZWFVOGFOTXU1NlhHTSt5UzFlMUVPcjdTSkd5S3FsNnB1ZTdwRFpzbnZRaGR5aUthN1QxWklsQkY1VWRJRmlXTHR2L2VUUFpuY1dXZlZISC90R1YwT1JNZU51WnBvUXZuVUVNM1JFMUlyZytHVVcwMzdWa3RFdTltS3JGK3E0SnNwdHgwM2NUSFhqUW9OMWJXRHpSbjBZQ1ZYWDhiWGFmd1VzMVFPODhZVW1DYTA1ZG84b1g5ZzdvTS8wYkVZcU1FajZkUmRhK1gzQnp2YjFoa3ZuVmpQdUFyL2ZwRnJZbWF1eDk1cXR6bGpWTERGczFDUHdRcG92Ym1UTFVVR0xBNU9FVGk0NXVzaTRuMDZhcURwR1YzL3Y0ZlhMeUpNR084WDVxY2xkUjlqekFwRjU5MU1la3VoditvSHk5aDdDUnRFOWtVTUlnV1JxYjM1NEdSM3gvN1BsZ0lQUHhlWEx4SFdIdlVSdjZIMzNGSXJuVVpyOTUzbWZuc1NpcUtIVzlFTmJ5SWJ0NVJRc3dSa2JTLzJXUDlrQnBCcWhjT3JIVVRuSFczYkw2R3RVVUg2SGlGeWtnS3B6b2V2MXJhTWRlUkwzL3Q1VGNWSEs2a0tGc3NKelYvOGxOcExmc3lDd092a2UwVmZhNnhJNVl1V0pvcFBZY29lbFJiVEU5eHJvbEhCZW90azEyYnpGb1lrazNKMUl4bU5JMXZiZUhJM1VBWm9YTWxXMzA3U0FGdTdLelUxUXJvR2R2dkpGMWlkZlBYNWVyODg4RXRiZUp3VUEwN2hySkZTb3NqUXUyZlVOT09DMWJUS0k1Y1JXSjlmT3Y4MUhlTEFXbFZjbVNVZXJMd3RoKzA0Z3dHMkR5SWpoU3UwWkdkWlBaMFRvZEhBZGVveVNjV2hyL293TDhqUHYzVXc4VE9YS2x0WDcrT2lUeG9jVHBuNzdyd2xIL1ZIYWZ2TmZVbWJINjVuYnBFNkR3SWlPOUlMeXI3bVJHcnJDV2VIN21sYmxyb2c5a3RJOVFaOGZqaGg1TGpqeEszUUJnanVoc0lnT0czMTVDclNIYnY3MlRWdHlmVjg1ZGVjb2Zsb3ZDR0ZDYmF3bm9vRUZYc1RSZ2FncFpEOGVTKyttWjl0R3pOUkFTbklPWnAyVkFWOXMzT1k0cjBEbjhQbXhSbHlqQ3lWOXRtUi9BVFF2M0JNYW5pMnhlbVFRc21rK0E3WUZCVFVUd1drSzNsV09IamsxcC85WGQvVmxtNjJrQkszVHBaUGM1ZFk0R2U1Z2lkQTF2amRqSHhxN0M1VS9vcTNNQkZSOFJ2WkJYT1NaWlZuQ293U3NpbGNNZWtlZzArSDBEUXFLcU1uMVJkNExCVFQ4aWZXT25uMTRiTHFabjBydHcvQTJVN1dkZExkSUNZOThNck9ETitRclJTUFJDQngzRTh2czQ3YW1kOTFMSkdVbkcreDVKbDM3dVZVZEpBQzM5K0U4YTBCU3o4VzRLQTNjOTlsQ2NvM3c0cTZSeHZ4WGdndFhLUk9COGlXeDBYREh0bWZibDI2MFNlQmZVWUFya09ETjU1VnRSeWFlbEIwMHJTTDlCVWZpMG9rbFpLSjhCUlRCbEN2QzBNeWtWYW8xTG5ERVJJaVNyQUJDTFBLTUsvVFp1Y3dWS1ZUK1hocHBTMmpacVVETlQxMWhKaXZZYmxhSWxid0xXWE02NmZnQit0MDYxUmpvZDg5OVI3Y1dCV0QyM0hEcG5rbnpQblJ5bUpqOEhCdXMyRkZkWHhJM0NyQUtwQWFHcGRkcnBvZXB5cFIxY2tCODZUdytUVHVDb2ZiRUg5M0ZyYi9RQ09BVHBCNlBPempQZFZJSGpEdk43b2hxNDJBNWdDbktuOUM2dTdyL2ZCNkVIZUhPUkN1NHhVRlRVYVFGUXpabW8rN1pTMmlyWUdsRkNYVmZzWFVQWkpZQnlieCt2NXNKMksrUW41THFmR1cwVmw2WnpUN01nVkNMVGlqQ0Zsdm1ZVU5DUlNOZUhkVnFCQWpGVkk1Vm5TRkRwYlRvZUdGT1RURzhDV2lsY1ErNVowWW45QXpHSW9oNXF4OWNVS25tcVNpMU5wT2pLV0FESmw2VzEwRDZOeG1IYStHZE5xWFcvVzJ0VjNjUXNPVVJla2FCdUVhOE9pZDcrUjNkNUJmYWJEYWxJQXlxNzZMYmlSTHpDVHF2aER5TUl4YUUzWGNsdzNESlAxbHh1VmgvSUs4OHRjN0lSK3hROVdHektOdFV2bHdoMTZHdlJqRit4NzI4ZXNvYW5ZcWhhNTZ6SENDdUdZRUdIdkhHdmdJT1RFclpBc2d5dzhxVC9henFScVdFVytncTc4a3Y0VkRJTUh4Z09YbVZUQk1lR1JndVdPaDdKS1V4ZnUybS9EbktRbG96K3l2OVhYQUNrTk90dVRBKzhhcEtXVWVoL3pFQjFhYUg1a0VXcXMvM0xHSFh4NU1PRWMxWEdLcVB0VVhDdWRQMEdSaytBalpVTDMrMjNRRXZMY1FCdmdGSXFCS0lwWDUvZHhPNzBDOUNVWjNEZkNwTjZSckhCTTlJMVBnOWhHMG52Vy94THZhM1hxdzlvSXRYY3UrNW1mL2N0OWtiWUNqVnRnSWozSGhoK3FMUyswSSs0bXliVVVWYmhDT0Z6eVVsSHJ6YThMT1QxRExBeTFyWDFvU25WbnFRUmlrenZaSHBvTlFRL2tKSTRJc09SVTlUUFNoNHlIQnY4bCtEbWY3QW9DYmFoa0I3a3FsM3RFK1ZwZUVKeFo0MmlYdEorRzVDK0hidFM1blE3MnNrZjR2TWI0UW9mcng4OC9XcmY4NndpSE9wdWpmbUxrNHhOYlM2RVVjMHdtelI5cjg1b296TXRUU3dLa1BDWlhjM1NGSGJrK1BMQVd6VkIrTmRvcXpZVGlLQWRBSnY2UFl3c25HbnBWWC84VThZUGNNKzkwYUIxTlg0YllDTkZCZEZMakRSaUswOGltc1dGYjk4QVV5M29zelRTakNITDdLL2lJZHVvd0pyenFuTEdhblVxQ3BUaDQ1clFITm9FYXp2OUlKWG43NDIxMlRXLzlPM3IySzc0Qm1kS3Z3bVVoa3NHeFVkL1VsVjNEcDd5ZHIvWEE4MVJhRDFFMm9Lb0dzUlAvNkZVMExvczE4aXBtdjllcStlMHdQR1I0Y2xwL09tK240ZjZ1ZEFubEVmZHduY2IrVlZCV25pNnprZ2h4NGE4SEZHL21jb1BKdmYxeEZYMVZ5MmNXem1vWTNxcXRyUlZiZG9EMEVyRmhac3RqeUFRbjFKLzRBMzAzRGFNTklvRVNHZmh4SThVb2duSStZNXhlRDhKYjBOa3VVWWw0d3lsbENzd2duOW9mZ0pPcmtDbWVRL09QSzZzUjczSjhhU1RxMisxUWszTzhUamJuMXpEaUkvU25ISEZyc29lVVJyQ1orTUJqd2F0Rzk3OXlIWTZDYlN1S25NYmRRaHRIT21KWS9McU9URllMTTBzUFM0K1hiOU5JTERqbCtIb0dtRU1iSThOREsxTGw0ME94djNoRUpuRUhOVWpGNjVzRzg4ZUZpY1FSeE5sWlJrUExFZnI5SWhsZnZiU3ZHeHJOQllmZms5ZS8rcXFnL1AxaS8yaEF5dU1EUFF0Wkp5WkZEa0tPL2ZrNVRuNGVjcXMyMjhxNDJzU3BrNE9ySHlQeXhjYTEwNi9zWFJmQzZiaXBvbnJiaUg2MVcza0F4bnNkWEpUYzN2YStzU211VytZaURZdW9FWWdPdlI3RStUOWp0VzB1YXh0Nk5jVlU2cDdaSUFTdEQrNkZ4Y2xwc3UvOHJTQ283TlVHclI3aVhMdklsUUN6UW9tVWFJOStMQXU5TVdLREp4OFY4Y1pjUW1JcWNsc2hGUXU5ZXlNV00yOUI0Mi9oZWVnRTVXU09OVmNKQWx5U1hRYzdCZks0YisvZzNOMDBaVnZjdTFJRkwwd3NvT0VyY0xEY2pDNEp6OTAvdWp0UVYxUUlQZDRFenZJYVFrcklFeDYyVWNMdDFPREl1cGY1Yk1VU0tyK2hZWDZoaGdEaVlNK1ovTG1Semo4amJ1NTdBK1MyL0grcnlRM1V2c0dsTnVmSGNsVVFPbjhjTGVQL2VpcVJmcU4yL1RuaW93QkpVdVpVTTRZajRiUTJUWXpvdlhLL0x1UE9GYk9BM1JNRFZYTG5jYXFxREUzeTQvbkI4dHhMWC9FeC9sR2JCcnE2NkNCbGQ2cWErMUE0c2M2MHRDTitwZ1krSXpWZTF4NUQ3L1huUWlDcGhlLzJlWm8wa2t1clJiM1pUeUdpeTRvVkxUa3JMK3pZLzJ4WmdoRkJMaytkRlFHRnJNcWN0bHNQVkw5VnhPblhtc3VXQXpJM0FqUys2Q3BsYVlYRUdxRnhwK2dCVHI0aXR4emtoT0YxbURCeldRQWxlalRzSnZJVkNwaUhadkVNcXQyVjFLdHk3cFJVdlVHdG5CZkl2NmMzUkQwWE5XYzNWVHlDbGt3ZHh3cDEwQ0tBWTJ1aXlHVm1ocmw4ZW5rVjNzOUcvVEFwNVhidnZlV3h3SGNOV3NBQVV4dGw3RlBzUFBvRzNLT1d4L3ZNMERVdzlaZFJCK0pIZmhsRE9rZWszQ0syMitDa2x1TzlXR1pxRGtnZ0dJZ2VxMXJTbDdhYXg2MHV6dDhzbVpCK1NtZnIxR012RzJDUDBKSVg5eFIyT1FuT3JBVUtlOWREb3ZMSVVsaWVKQmxoSjVldGpZUmlseXltSTN6ZEZlZVFNQUtnamhwTkhNYnQxR1UzQWJWSHEreVFyaTlIVG1jL1NObjB6UjdqTmRLdzN0ZXlJbzUyWmxheEt6MGJwdE9EZHFHODMwVzJKYXR5bDl1RHgzY3g5dmMrMGxyK1JUSjdzaVVTTXd4NlM0N0h5ZGdXTlVyYnkydGpyN21uaTNZdmpiOUREeHpWMUNxRVYvaGdiRFVVWGRrQVpHOVBERGxDT0hPNmdrMk5uRWkyZFBWRzROc05WVUQwQ1hIMGVDV01SQkpHcVYreWpQTzZ2VWlaYzJJZ1ZOY3FhSEUvTTI3TW53R0MwelJicEJVVDIycXBNdlFYcnRjd1VTckdybFloa28vckZ4Uno5ZHdtTXEwbXVON2RjbmwremdCcHYxTm9DRTVRdXhUaFZ3dHNuTldUa3ZOVkp4RnNiZ3hJeHVmL24wV29MVHlQRlU4UmxKaEdyRDd2NWV3dHlFQVdwb1J1YnBmRzBhSlRWTW1oSy9raVhoTjAwZFpYMGtjd1dlZnJDZXNSbTA5cTA1S0ZqNlpROXR0UStlQTZWb0hhY3htMUhTakxmbVYxKzNzditlN1NXV1UzVDB3T0MrbHcxT0pBVUlVaHdzVEVzNnBhMXNtdUNHSnlYRHZpZTVJVmFCTzBxamo0MHhZSjhadWFXbC9zTVpaMXRZSDhpN29OQ1VYQ0cySFJHWUtpcHd1QTl4ck1xak5PR21LK2V6aUV2WGs0Z1RCU0VrYkhIVUh0Zzk4dW43ZzI5cFpyZUxuZEtER1hKYzRYSzU5TWZaMTNEdGVzcmFxYndLM0pGYUdjeStWYzhlaElXeitISnRvamMxZDNCdFpqN1hBOWFnTUxpSGJKSGJaR1NKOXBpMTJYcEVSb3RadXJrMUFja0VucFYrR3dSRzlBZ3UxYzduSlBUam8xcmhkRUVZV1JsenhKRFVGWDZyVEF2aWdoM0NuYndXcjZnTFhhUGJSejYyWTlGOWMyVlh4RnhLODhpWlV2RTNkZWxyUEJ0cnpiNzZmS25iRmk4MjQ1NEROOHJJbHpNbWU0TDVYVzhFSmpWS1U3MUJHUmJsOFYxSDhSR1krWkYrZWJ0THJ6YjBhdURUZTlTb0EyZWRnSGhvWHlNN1h5QkhBRndUOG9zbm9zc1I5VHB6eTg4SUJNMW81MDkxbExXNS96YkZwb1l4TFQ3MnhWdCtDQ0ZlUWJteVZSc2hHVVFWRGUrNzlGS0hia05uNzNoNE5rcTM2WDN2ZzlDUVA3L1BYVGJhcXkwZW01SHQ1RVZNL3JyK2lUa0hNdktoaGJyTUZmdjFuTTV2bG5KRFhXcDhpWHFVdzZYdSs3WW15WkVTVEtlemVCSzhKZ3B4K1NEOTMwQ3ZFcVd6TVJiaFpDbmtkRlpQdVFnMEg0QnNLZ1MwSWw4T1lWWFZWQ3c5dFFBVnVYWjYyLzlkd0pKVno1d0hTczc5Ui9CdmovQ1Znb3JGUm50Z1UwK2ViYjB2Zzg4NzJ6YWdoZzNzT0NDbCt1MCtPNXl1VWdVQ2JuWVN3dVhxUjI2MlQ3WTBxSWpVdmZ4cUR6bU9GaVpXZlhEUlNmZmcxTGltMEh3cTVYbjZJYUtzeGJhdUdZZURic0NuNFRTU0ZTTXVJSnlpZ3I0cUFvRG5YamF0MDVTcWdvNHJGTE5aR2lTNTh0aWIybFBqVTZyQStEVmNyMVVVM09EaWJDSlh5elFqTWMvVkQ4WUFzYzRkRG51WmNYUGhzdmpOeFh6dW5UdHpBemoxZGVhL0V2MHVGc3Z5MTRBSzlLR1FaUmpQMjVLOG12VTgrQTR0QVlheE5UOTB3YUZsU1FJN0pVMjdPUWxrOVJkTFFFK0U2T0VveEljeGhDUEF6d2VBdlh1TExTQmRoQ3lQK0JRS0prM05sUSs5RzFvZURWUlppRkJQZmJtNWtDUkxzczFMOExaTFAzT1dxUEpsUlpEdytrSjFGRi9uQ2Zqbkl2cHA4bXNYQTQ0WXl4WUFzU1ZPRVRiY1ZQUmwxRVB4Tmdpc3dJU3Q0Q1NETUlBdXR5NmdTZHZ5YlZWUytkMWovZHhjRlUzZmxOQjZnYm1PYlhTVTJpYnE4UC9oZS9CdCtXUTErdTVwNUV4Yi84V0ZiQmhjWmh3MzVVb1lGSGwzdzJUTGNtS05rcmtJVkxwVmhaQXRWZVVtNUZWNXN3ZWNTRU5mZW42QndzOGhUTUIwNXg5elJFQnVXcHhSNnhRZEdUNjAxZFFFZi8zR0pka2lGZ3c2MGRxZStTWEtZZjFSQmRsaFN6UVQvZzhwMEZrU3pKNS83WmdCU1JXelkzRVlMNjBva3hRT1orMjdncGRBbHhNYVM4TWRFK0crRzVOcW81bGgwcWQwbWpVL0h2aUFTOThFSmFHNk5DbHFWTVlXWGJjN29CMGNrMUtvWks5dDRKa3h4b0ZDcGtqV09CUXYyemFIOU9BUUZZakxzR01kM0dEMkMrNHdVR2RIZUhKbDUvOUkzWHRpNm4zQ3YvY0xESXNQQks5M3psZzZVVVZ5bHVXSU1KTzlkSENMOXRJZE1vQ3g3SWxuT3JKT1IvYmYxWlcxdkVwVzlJem52NkVUQktaZ1FSRXFleFhBQzBxMFFXb1BTODAyNm9zZnBwRzFpSE5Yenp2ckp4clJPb21vem5SamJBbS90V2ZHazA5TzVFbUY3TkV0aXJHbmJCRkdqd09LNHlrS01IeHk2ZUt2SVRoa2cvazJSY01IdGdjaHFONGQvSzYwL2NvcmF5UjBRam00aTRFMi81SHoyTHRya3ZjRUxTMjQ1Mi9EQmdpUTNzRSsrQzhEcWg0UFYvYktvZGdFWU82S2tmUDVjT05QUnRidTNUQ2VYL0J0QmJsUnJ5eUI5MVFlc04xRjlIYTB4cnpBVE9VejQ2TVZCZGZCeGlrNWhCK1FqV01SQWZUS2Z5K2dkV3RtaDdKMFNKbVdINmlXUXJlTkFOZUpMYnZTQ0NjcW5pNzVUbjlBTHRzSWh4eW1WSmZwU2FrUlNESnB6U3hZWG5Ob3BLR2Rodkl3bHVVVStVZnk2UXVSTTh4S0NOcHpFL2lKSHhWTlZSRXhhR2l4SFg5M3dpWmlIRC85dFJ0T25OQjh2dE4rWS8yQXlKRXV5VXRvV2wvWklKejZvb1I5VnB3YzhwZTBsOGZwa2pCRWNIQ2FCYlhNOVJpM3BXTE1zdWlnOGFSWDRxVzZLeW1XWjMwQ0hwZHUyaHdUQzlxcVN0N1pBS0g3bUdwNS91dGpBaFp6akxPc1FsYkhScXN5NFlsL252a3J0UmNjRlBaakY4VGswRS80VFJDZVhtZFdLRE9SdHNBYjM3M2lZczljZFBqRVhJSnVKbGRjRUxHaWg3U2N2cVNLV2hzWjI3KzVtWGxoNVIvMEVyMEMyeHB6ODU2cGMwNnplRXNveFJHV2tTQ2g2YkRnOTNwVnpGUzFMTE9OMGJ3T3hCWDlKYy9NNzFHeVVBSkcyZnhkS0dydGNkUU1BUzZJMXpCc3VVUzhTWHZ1VkRwajNwb0NSY1hXbjdoNFJMc3Q4MFYzWjFNZjI5VzNPMlAxeGNHRkNTWVZMYkF0R2gxRGJCQTEvYmlDTFAwWXBjWnliVndJMUVmRFRSb2Y3ektYSFRKeUVvd2VpcVFSclVBR2NpU2xFd2JGSmJDMmJpbHd0MzNKb3VNeHJZNU9TcjZrN243Tnl1VGdIVmtaNWhiVW1MUGJVMjJ5b1FVdTZtMGx5R2t5SjB4N0hoVUZZczM2NktjZ3FueDZDdWZoT29XOFRZaG1Vb0tYRngxUS94WDJwWVZpUXI3dE85c0F1QUNIN0FSemMxa1dkVytEWTQ2bzR1OFhZYUNjaGFFejZsOS9BQlNidGlKV0xkNlh4YmtSZ1dSOXdvSWxZUERIUEhRbXdpVXZWRXNqbEhiamlKL0RlYWR0VGx2RGVmak1MV3JDdXdBOFJGZk1QQ0xvOGwyK3B6dDliTHBtYm9SenpsZE96NjBCSFl6RUhrbVlYMWgwK3lsYjg0NkFBWHZhd3c5OVE2dC8vSFFmWW9xZkxSV08wQWZLMWR6dmJPNUVnZUg2enEzV1JPUUd4aG9YTmMxREVidm91UGZKMnFVRHR4TUlUeFVzbThhYTJ2MkU5V0dmZlptbmw0dmlqVTR5aUJSUmhDb01tTTNTbzFyd1VEd09EUzVySkFyRndtaWhRYU5MYnBnajRWeVArVzUwV0kxQlBBSmI0VkxJb2dKRXJFOHBqR2ZTdHVNcTRML09RVVRMaGIrVVFqL0pqT2hkZThWbmNVZXozMlIvSHhiVElGMFBFa1NEZEtxUzdEZTRENncyMUFNNlVIanF4S2t2NUlEMUtvZ3JrblAvaW1vcEZCN2xMM1dlc244ald6VG5qa3JOdDN4ZXdmemtydTBQWHVZdDBUTmVBa2RuTEhMc056Q1piV3J2UVVZcTAvOGYyRGVEdGhVSWQzcm9pYTlWelVrWE9lWHdhUGFySWw3dDJhRGtDcE8xT2RrQWZoc2F1RGpvOXROWVBXZmtET3o4R1N5eFJ5UHBhNnV3cTNuMHhJNmhnc3J2MXoyenFBWDVQU1hidGt4cEdDSVV1WlZQMVlqcmoxYWxBMDhhZUNsVFNqWkxqRXdaMWxZaFhWUWFjY3BYWUNtSFJOdkVXdDdmd3NJaE5zMnQvRDFqQXJpMVRkRUpqU3FXNHFRMStZUG9pZkNnaGJGUDZ6bDRGVENCNnpQTDJwRVNDaHVLRjNtamNVZ2phZU02amtmU0kwZ21pZEFKTTJ0UFRBV2U1amxOM0VLN2JpYm9vV3dVbncxeVBvZ3NPZThxQ0VOR3V1TjlyMy9tOExXRUtjM3QvK2hMQnZjd2NCVWpMV2dIUWtrbXNVZzJnSlF6MVh3S0RlWHoxVi9nUUFTMFhYYkx4eGFwcjJnZnRDUlhnMkJmZUc5SVF5YytzWlZEZjRmR2pJa1ZkeDFZczdtdGxScHhZcmdSMDR1OG9QQnMzNXlTaXJoZ1VoRm05empIRHFLVDNYbjNKUWJRMUVNbkpMWjZma1Q0UTRqWkZTWlMva1ZTR1V4Z0c3ZHJhM0YzY1BpR1hVY2FhMnZ5Ti9yaVgwQkw4Wm5FQU1uZVBOZ2tWWXQyRStOZXduNU9TM1N5QXJ6SGsxWnhGdzBCNE91UjRGbm5zbW5ON0s0NVpoN3dpZ0k3TjJBNEs0TkJpekZteEdiNHJHUUtVWkI4VWMxZUlOVWVtUDNNT1QreTJ3MUlSWVhqSkNDd3MzRElpWkRsZHQ1RDg2WlFSUU81YVhybUlFPScpXQpfRlVOQ19DQUNIRSA9IHt9CgpkZWYgX2V4ZWNfZW5jKGlkeCwga2V5LCBuYW1lLCBhcmdzLCBrd2FyZ3MpOgogICAgaWYgbmFtZSBpbiBfRlVOQ19DQUNIRToKICAgICAgICByZXR1cm4gX0ZVTkNfQ0FDSEVbbmFtZV0oKmFyZ3MsICoqa3dhcmdzKQogICAgcmF3ID0gX0ZFTkNfREFUQVtpZHhdCiAgICBub25jZSwgdGFnID0gKHJhd1s6MTZdLCByYXdbLTE2Ol0pCiAgICBjdCA9IHJhd1sxNjotMTZdCiAgICBhdXRoX2tleSA9IGhhc2hsaWIuc2hhMjU2KGInYXV0aHYxOicgKyBrZXkgKyBub25jZSkuZGlnZXN0KCkKICAgIGlmIG5vdCBobWFjLmNvbXBhcmVfZGlnZXN0KGhhc2hsaWIuc2hhMjU2KGF1dGhfa2V5ICsgY3QpLmRpZ2VzdCgpWzoxNl0sIHRhZyk6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdbZnVuY2VuY10gaW50ZWdyaXR5IGNoZWNrIGZhaWxlZCcpCiAgICBlbmNfa2V5ID0gaGFzaGxpYi5zaGEyNTYoYidlbmN2MTonICsga2V5ICsgbm9uY2UpLmRpZ2VzdCgpCiAgICBwbGFpbl9ieXRlcyA9IF94b3Jfc3RyZWFtKGVuY19rZXksIGN0KQogICAgcGxhaW5fc3RyID0gcGxhaW5fYnl0ZXMuZGVjb2RlKCd1dGYtOCcpCiAgICBucyA9IHt9CiAgICBleGVjKHBsYWluX3N0ciwgZ2xvYmFscygpLCBucykKICAgIGZ1bmMgPSBuc1snX2YnXQogICAgX0ZVTkNfQ0FDSEVbbmFtZV0gPSBmdW5jCiAgICByZXN1bHQgPSBmdW5jKCphcmdzLCAqKmt3YXJncykKICAgIHJldHVybiByZXN1bHQKCmFzeW5jIGRlZiBfZXhlY19lbmNfYXN5bmMoaWR4LCBrZXksIG5hbWUsIGFyZ3MsIGt3YXJncyk6CiAgICBpZiBuYW1lIGluIF9GVU5DX0NBQ0hFOgogICAgICAgIHJldHVybiBhd2FpdCBfRlVOQ19DQUNIRVtuYW1lXSgqYXJncywgKiprd2FyZ3MpCiAgICByYXcgPSBfRkVOQ19EQVRBW2lkeF0KICAgIG5vbmNlLCB0YWcgPSAocmF3WzoxNl0sIHJhd1stMTY6XSkKICAgIGN0ID0gcmF3WzE2Oi0xNl0KICAgIGF1dGhfa2V5ID0gaGFzaGxpYi5zaGEyNTYoYidhdXRodjE6JyArIGtleSArIG5vbmNlKS5kaWdlc3QoKQogICAgaWYgbm90IGhtYWMuY29tcGFyZV9kaWdlc3QoaGFzaGxpYi5zaGEyNTYoYXV0aF9rZXkgKyBjdCkuZGlnZXN0KClbOjE2XSwgdGFnKToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ1tmdW5jZW5jXSBpbnRlZ3JpdHkgY2hlY2sgZmFpbGVkJykKICAgIGVuY19rZXkgPSBoYXNobGliLnNoYTI1NihiJ2VuY3YxOicgKyBrZXkgKyBub25jZSkuZGlnZXN0KCkKICAgIHBsYWluX2J5dGVzID0gX3hvcl9zdHJlYW0oZW5jX2tleSwgY3QpCiAgICBwbGFpbl9zdHIgPSBwbGFpbl9ieXRlcy5kZWNvZGUoJ3V0Zi04JykKICAgIG5zID0ge30KICAgIGV4ZWMocGxhaW5fc3RyLCBnbG9iYWxzKCksIG5zKQogICAgZnVuYyA9IG5zWydfZiddCiAgICBfRlVOQ19DQUNIRVtuYW1lXSA9IGZ1bmMKICAgIHJlc3VsdCA9IGF3YWl0IGZ1bmMoKmFyZ3MsICoqa3dhcmdzKQogICAgcmV0dXJuIHJlc3VsdAoKZGVmIF94b3Jfc3RyZWFtKGtleSwgZGF0YSk6CiAgICByZXN1bHQgPSBieXRlYXJyYXkoKQogICAgY291bnRlciA9IDAKICAgIHdoaWxlIGxlbihyZXN1bHQpIDwgbGVuKGRhdGEpOgogICAgICAgIGtzID0gaGFzaGxpYi5zaGEyNTYoa2V5ICsgY291bnRlci50b19ieXRlcyg4LCAnYmlnJykpLmRpZ2VzdCgpCiAgICAgICAgY2h1bmsgPSBkYXRhW2xlbihyZXN1bHQpOmxlbihyZXN1bHQpICsgMzJdCiAgICAgICAgZm9yIGEsIGIgaW4gemlwKGNodW5rLCBrcyk6CiAgICAgICAgICAgIHJlc3VsdC5hcHBlbmQoYSBeIGIpCiAgICAgICAgY291bnRlciArPSAxCiAgICByZXR1cm4gYnl0ZXMocmVzdWx0KQoKZGVmIF9iKCphcmdzLCAqKmt3YXJncyk6CiAgICByZXR1cm4gX2V4ZWNfZW5jKDAsIF9GVU5DX0tFWSwgJ19iJywgYXJncywga3dhcmdzKQoKZGVmIF9lKCphcmdzLCAqKmt3YXJncyk6CiAgICByZXR1cm4gX2V4ZWNfZW5jKDEsIF9GVU5DX0tFWSwgJ19lJywgYXJncywga3dhcmdzKQoKZGVmIF9mKCphcmdzLCAqKmt3YXJncyk6CiAgICByZXR1cm4gX2V4ZWNfZW5jKDIsIF9GVU5DX0tFWSwgJ19mJywgYXJncywga3dhcmdzKQoKZGVmIF9nKCphcmdzLCAqKmt3YXJncyk6CiAgICByZXR1cm4gX2V4ZWNfZW5jKDMsIF9GVU5DX0tFWSwgJ19nJywgYXJncywga3dhcmdzKQ=="), '<exec>', 'exec'), globals())
    _vm_run(_c, _k, _m, globals(), locals(), _map, _ok, _ht, _pf)
if __name__ == '__main__':
    _ttbowrol()
