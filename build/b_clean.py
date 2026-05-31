#!/usr/bin/env python3
def _zxdqmhamv(_spsjoddm):
    return _spsjoddm % 9631 + 1

import hashlib as _kxhgxcalv, hmac as _zlrjt, base64 as _vfvcsmrt, sys as _zjqunugke, zlib as _jgoxdz
_spsjoddm = 391795
_qqglcdrz = """NkxH/u04arGzNFAHG61XNl8NHwG1XyFj3RDpj4J9lS0MyQBgcIuwIsGQV1LL10ydf+ZhylVcRXfhU/qI1vhZDcGiwngL7XbjZirBIis0+J9Att/gbIQLX5WXOaoVTnkm9wT3znfSd7y6OBEezR0BcYoIx5VaqKDk/JYm39TTjPqtLw/ouPsZDLWLilAOsiH5qgpy+Yh3vTDXl8WQ6aqjp8vBv6z8LD868YJflw8kVTRKR5gMTUFlT/LOnv1vhxiOzhUtLLQyR6mmsfyZ7ZfkSQMV9zJZQDFM30FZYbjRPelYkSeJYfiwkcOHoMX/Tz5yrRQR1KYG1FUK7zjqIVdaQnBJO/xVqzB3HqbJA/Ud1VCcm0RfdogZpTKVokMQWY1XY8TqQAnE5BxQrkpCGPpXjfDLQVyU91rnKAqKkv2slesN4qBPovJZY4W4+EZNUgYosDkhtkMUEPnUAetY+dAY3M0tt6kJjpG6IaPd2DoUFJHkqC/ZeoKU2ksXS9HNFdBVfcyMrKnDhIpG5jqgzPdacWUU6uXIUferFrluFZhciDGfwEjM5X8Su3ifM/IT9bczS18owIzn/tHoIlfvz5VbGTK4tvYTt2ZzWyKaHAw7w0iNDMmdH8MG9WPOx7TAWQ1vf9TBYDnV+ZvsJGfdCdUvY8+mE2Bs/C+nXfgYQRNW2ndrMHcYgrkqzhd3rrQxyFwyfTXbaH5wU+ET2+iW77IWIiaVvXcFwMutCXY0qs5NKmgBJ0TPWt9a0UV1A/5zH3S9brVPoeXMjw9udfOquxSKvvgMi3andXhqsP+UX2gKuu3a7nKjgjO4jfr+P6G4Pyasuz3GuZPVE2VMyR9MH460s5HpKvQ6ScbKE/fLzL58QXxhdBP6PltNsuGdFm95JQPsmGM0en8qqo3fggxu6t2CzOrNHLs="""
_jmyeyx = 3
_csfxdxna = _zxdqmhamv(_spsjoddm)

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


def _vzagdfz():
    _qtamcnq = bytes.fromhex("465a5b5f1b407f635f696318696b405b54761c686777615b5a46697449581f746f4d567e4259641b5f68577d4540795d7a666a1f6b797e4656625b456941616c4058761f6b78671d47455b1e791a7a6940477d4d4f786c685a7d691b407a7d775d5d175a7e464f6c7b7848674c795c421a5e17466845161e6a477b176856774a6b405b47775d691f621a4b56427a6c1d6c4943665b1b6d5f4b1a7e6b5e1c1a1b426c5a425e6a6f7d7b6c687e65401616697e771b5d5d601a5a635774591b7c59656f4742476b1a186a6c6d6974487d16566174576857456f4d631c796c7f7d7f596f614047415877635d476a496140697e6f6f42415a5864446d59567b5c7c46746b7c6f591c567d47624a66575a7b405b1f6c66595a465b41641b637f661a5f786a6245601a1f49776f4b604b1d7d4a74177c6f7b541c617d4c5e6d4d677d4716684a4f795919694158484a5f794d697f585a577758475a4c7c6d487f43675d685467435b1c6542584f7a4c7d54436366186b171d7c785b4d18637b7b5a43647b7e6642781c7b411b406357461b5459746f7b5c6d496d7d745c676f6c775d16676b54547e1e4d7f7f17477b1c43185f481e46401d655c7c677c17664f6a6974786574636c6a196b68764c5a5d497f667e6446627d5e625e566162596256585f4245477e6a7d7f40494d7c5e6c6f45666540451a567a5f1e5e5b1c47491a4a697a6b4c7d694d7e4a564041766442776d1643621a1f1b6f575b625a4f6a5c17614b624949636960424c6c7a607f5d634f1a1a5e7a6b6c774d766c6979747f445a691b48441a401774565b4f5f457c6c1f6c1d575f7e607e1e627a665f5e695464436f4d5e626d484b4f1e641f61171c4460481e1e6746627462167b1e786d68185a4a7e1b63541d5d7d691f565c59474d197868595a7b444b61684662567957584668604d681f6267656b456b7e1d4c5854741b42777e481e54194b4f685a1b6b681c5c69664a631e4a69634f676f7c4c615f587f5a6b7f671b6c7c76656f487b4243695d6c6c68566f1e1c17195c597b1958486b6c631c581d597d6d5d5f637b7b1b4d1c6a464c6c60484f5f577818427c465c424f5f5878425d7a4f4c1e6f19615d61795f6669614167766a417e6841437b6c461f7774745d416b765661625d621d484b576360631a6a17471a646d4b5b195d574c4f1f6867634d59765f1f5c6846467f6c6963745d5c6d41784442485d41625b5d5d7c7f565e4459694961614446695c624b1f484246651674634c596c6a58576c6c635e604c6c417e56671b575d7b7a7962406a4c18466947584b6b1a6d4b6b7842476b4d667f45657b57566718191a694076164d66765c47461c5a7f424d414f56654f6f5b6b435c1e4a1a1a5b5c4d656c6069696c5e4858475f5c57644468161e6b177e466b5f414f7a69")
    _qtamcnq = bytes(_ ^ 46 for _ in _qtamcnq).decode()
    _wzhveg = _vfvcsmrt.b64decode(_qqglcdrz)
    if _jmyeyx == 9:
        def _uljtb(_frbqkjr):
            if _frbqkjr[:2] == b'<~': _frbqkjr = _frbqkjr[2:]
            if _frbqkjr[-2:] == b'~>': _frbqkjr = _frbqkjr[:-2]
            _ryvit = bytearray(); _ykswt = 0
            while _ykswt < len(_frbqkjr):
                if _frbqkjr[_ykswt] == 122:
                    _ryvit.extend(b'\x00\x00\x00\x00'); _ykswt += 1; continue
                _ghujsq = 0; _bkxbr = 0
                while _ykswt < len(_frbqkjr) and _bkxbr < 5:
                    _ghujsq = _ghujsq * 85 + (_frbqkjr[_ykswt] - 33); _ykswt += 1; _bkxbr += 1
                _ehznyvf = _bkxbr - 1
                if _ehznyvf > 0: _ryvit.extend(_ghujsq.to_bytes(4, 'big')[4-_ehznyvf:])
            return bytes(_ryvit)
        _wmtxlnhab = _uljtb(_wzhveg)
    elif _jmyeyx == 8:
        _vbkjjt = ('0','1','2','3','4','5','6','7','8','9',
                'A','B','C','D','E','F','G','H','I','J','K','L','M',
                'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
                'a','b','c','d','e','f','g','h','i','j','k','l','m',
                'n','o','p','q','r','s','t','u','v','w','x','y','z',
                '!','#','$','%','&','(',')','*','+','-',';','<','=',
                '>','?','@','^','_','`','{','|','}','~')
        _oawep = {c:i for i,c in enumerate(_vbkjjt)}
        def _amycdpq(_frhnr):
            _ughseicn = bytearray(); _xzhyxop = 0
            while _xzhyxop < len(_frhnr):
                _objtgaj = 0; _fapvt = 0
                while _xzhyxop < len(_frhnr) and _fapvt < 5:
                    _objtgaj = _objtgaj * 85 + _oawep[chr(_frhnr[_xzhyxop])]; _xzhyxop += 1; _fapvt += 1
                _pbxjfinvb = _fapvt - 1
                if _pbxjfinvb > 0: _ughseicn.extend(_objtgaj.to_bytes(4, 'big')[4-_pbxjfinvb:])
            return bytes(_ughseicn)
        _wmtxlnhab = _amycdpq(_wzhveg)
    elif _jmyeyx == 11:
        _klripridj = _wzhveg[:16]; _rpfotngqo = _wzhveg[-32:]; _fvfso = _wzhveg[16:-32]
        _xunyxzj = _kxhgxcalv.pbkdf2_hmac('sha256', _qtamcnq.encode(), _klripridj, 100000, dklen=64)
        _izjsesvlp = _xunyxzj[:32]; _noxweoe = _xunyxzj[32:64]
        _iuchtlxdm = _zlrjt.new(_noxweoe, _fvfso, digestmod='sha256').digest()
        if not _zlrjt.compare_digest(_rpfotngqo, _iuchtlxdm):
            _zjqunugke.stderr.write("error: integrity check failed\n"); _zjqunugke.exit(1)
        _wgudjcxl = _izjsesvlp[0]
        _wmtxlnhab = bytearray()
        for _ozfiaqeni in range(len(_fvfso)):
            _klripridj = _fvfso[_ozfiaqeni] ^ _wgudjcxl
            _wmtxlnhab.append(_klripridj)
            _wgudjcxl = _fvfso[_ozfiaqeni] ^ _izjsesvlp[ (_ozfiaqeni + 1) % len(_izjsesvlp) ]
            _wgudjcxl = (((_wgudjcxl << 3) & 0xFF) | (_wgudjcxl >> 5)) ^ 0x5A
        _wmtxlnhab = bytes(_wmtxlnhab)
    elif _jmyeyx == 0:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _rgqkm, algorithms as _iadfnq, modes as _nuvmcrpl
        except ImportError:
            _zjqunugke.stderr.write("error: cryptography not installed\n"); _zjqunugke.exit(1)
        _klripridj = _wzhveg[:16]; _rpfotngqo = _wzhveg[-32:]; _fvfso = _wzhveg[16:-32]
        _xunyxzj = _kxhgxcalv.pbkdf2_hmac('sha256', _qtamcnq.encode(), _klripridj, 100000, dklen=64)
        _izjsesvlp = _xunyxzj[:32]; _noxweoe = _xunyxzj[32:64]
        _iuchtlxdm = _zlrjt.new(_noxweoe, _fvfso, digestmod='sha256').digest()
        if not _zlrjt.compare_digest(_rpfotngqo, _iuchtlxdm):
            _zjqunugke.stderr.write("error: integrity check failed\n"); _zjqunugke.exit(1)
        _vsare = _rgqkm(_iadfnq.AES(_izjsesvlp), _nuvmcrpl.ECB())
        _wmtxlnhab = _vsare.decryptor()
        _wmtxlnhab = _wmtxlnhab.update(_fvfso) + _wmtxlnhab.finalize()
        _wgudjcxl = _wmtxlnhab[-1]
        if _wgudjcxl < 1 or _wgudjcxl > 16 or not all(_ == _wgudjcxl for _ in _wmtxlnhab[-_wgudjcxl:]):
            _zjqunugke.stderr.write("error: decryption failed\n"); _zjqunugke.exit(1)
        _wmtxlnhab = _wmtxlnhab[:-_wgudjcxl]
    elif _jmyeyx == 4:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _rgqkm, algorithms as _iadfnq, modes as _nuvmcrpl
        except ImportError:
            _zjqunugke.stderr.write("error: cryptography not installed\n"); _zjqunugke.exit(1)
        _klripridj = _wzhveg[:16]; _rpfotngqo = _wzhveg[-32:]; _fvfso = _wzhveg[16:-32]
        _xunyxzj = _kxhgxcalv.pbkdf2_hmac('sha256', _qtamcnq.encode(), _klripridj, 100000, dklen=80)
        _izjsesvlp = _xunyxzj[:32]; _gdbzs = _xunyxzj[32:48]; _noxweoe = _xunyxzj[48:80]
        _iuchtlxdm = _zlrjt.new(_noxweoe, _fvfso, digestmod='sha256').digest()
        if not _zlrjt.compare_digest(_rpfotngqo, _iuchtlxdm):
            _zjqunugke.stderr.write("error: integrity check failed\n"); _zjqunugke.exit(1)
        _vsare = _rgqkm(_iadfnq.ChaCha20(_izjsesvlp, _gdbzs), mode=None)
        _wmtxlnhab = _vsare.decryptor().update(_fvfso)
    elif _jmyeyx == 7:
        _wmtxlnhab = _vfvcsmrt.b32decode(_wzhveg)
    elif _jmyeyx == 6:
        _wmtxlnhab = _vfvcsmrt.b64decode(_wzhveg)
    elif _jmyeyx == 3:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _sziwn
        except ImportError:
            _zjqunugke.stderr.write("error: cryptography not installed\n"); _zjqunugke.exit(1)
        _klripridj = _wzhveg[:16]; _rpfotngqo = _wzhveg[-32:]; _wmtxlnhab = _wzhveg[16:-32]
        _fvfso = _wmtxlnhab[:-16]; _wgudjcxl = _wmtxlnhab[-16:]
        _xunyxzj = _kxhgxcalv.pbkdf2_hmac('sha256', _qtamcnq.encode(), _klripridj, 100000, dklen=76)
        _izjsesvlp = _xunyxzj[:32]; _gdbzs = _xunyxzj[32:44]; _noxweoe = _xunyxzj[44:76]
        _iuchtlxdm = _zlrjt.new(_noxweoe, _wmtxlnhab, digestmod='sha256').digest()
        if not _zlrjt.compare_digest(_rpfotngqo, _iuchtlxdm):
            _zjqunugke.stderr.write("error: integrity check failed\n"); _zjqunugke.exit(1)
        _wmtxlnhab = _sziwn(_izjsesvlp).decrypt(_gdbzs, _fvfso + _wgudjcxl, None)
    elif _jmyeyx == 12:
        _klripridj = _wzhveg[:16]; _rpfotngqo = _wzhveg[-32:]; _fvfso = _wzhveg[16:-32]
        _xunyxzj = _kxhgxcalv.pbkdf2_hmac('sha256', _qtamcnq.encode(), _klripridj, 100000, dklen=64)
        _izjsesvlp = _xunyxzj[:32]; _noxweoe = _xunyxzj[32:64]
        _iuchtlxdm = _zlrjt.new(_noxweoe, _fvfso, digestmod='sha256').digest()
        if not _zlrjt.compare_digest(_rpfotngqo, _iuchtlxdm):
            _zjqunugke.stderr.write("error: integrity check failed\n"); _zjqunugke.exit(1)
        _wgudjcxl = 3 + (_klripridj[0] & 7)
        _klripridj = bytearray(_fvfso)
        for _ozfiaqeni in range(_wgudjcxl - 1, -1, -1):
            _zxdqmhamv = (3 + _ozfiaqeni) & 7
            _spsjoddm = (_ozfiaqeni * 0x1B + 0x5A) & 0xFF
            for _gdbzs in range(len(_klripridj)):
                _wgudjcxl = _klripridj[_gdbzs]
                _wgudjcxl ^= _spsjoddm
                _wgudjcxl = ((_wgudjcxl >> _zxdqmhamv) | ((_wgudjcxl << (8 - _zxdqmhamv)) & 0xFF))
                _wgudjcxl ^= _izjsesvlp[(_ozfiaqeni * len(_klripridj) + _gdbzs) % len(_izjsesvlp)]
                _klripridj[_gdbzs] = _wgudjcxl
        _wmtxlnhab = bytes(_klripridj)
    elif _jmyeyx == 10:
        _wmtxlnhab = bytes.fromhex(_wzhveg.decode('ascii'))
    elif _jmyeyx == 2:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _rgqkm, algorithms as _iadfnq, modes as _nuvmcrpl
        except ImportError:
            _zjqunugke.stderr.write("error: cryptography not installed\n"); _zjqunugke.exit(1)
        _klripridj = _wzhveg[:16]; _rpfotngqo = _wzhveg[-32:]; _fvfso = _wzhveg[16:-32]
        _xunyxzj = _kxhgxcalv.pbkdf2_hmac('sha256', _qtamcnq.encode(), _klripridj, 100000, dklen=80)
        _izjsesvlp = _xunyxzj[:32]; _gdbzs = _xunyxzj[32:48]; _noxweoe = _xunyxzj[48:80]
        _iuchtlxdm = _zlrjt.new(_noxweoe, _fvfso, digestmod='sha256').digest()
        if not _zlrjt.compare_digest(_rpfotngqo, _iuchtlxdm):
            _zjqunugke.stderr.write("error: integrity check failed\n"); _zjqunugke.exit(1)
        _vsare = _rgqkm(_iadfnq.AES(_izjsesvlp), _nuvmcrpl.CTR(_gdbzs))
        _wmtxlnhab = _vsare.decryptor().update(_fvfso)
    elif _jmyeyx == 5:
        _klripridj = _wzhveg[:16]; _rpfotngqo = _wzhveg[-32:]; _fvfso = _wzhveg[16:-32]
        _xunyxzj = _kxhgxcalv.pbkdf2_hmac('sha256', _qtamcnq.encode(), _klripridj, 100000, dklen=64)
        _izjsesvlp = _xunyxzj[:32]; _noxweoe = _xunyxzj[32:64]
        _iuchtlxdm = _zlrjt.new(_noxweoe, _fvfso, digestmod='sha256').digest()
        if not _zlrjt.compare_digest(_rpfotngqo, _iuchtlxdm):
            _zjqunugke.stderr.write("error: integrity check failed\n"); _zjqunugke.exit(1)
        _wmtxlnhab = bytes(_fvfso[i] ^ _izjsesvlp[i % 32] for i in range(len(_fvfso)))
    elif _jmyeyx == 13:
        _klripridj = _wzhveg[:16]; _rpfotngqo = _wzhveg[-32:]; _fvfso = _wzhveg[16:-32]
        _xunyxzj = _kxhgxcalv.pbkdf2_hmac('sha256', _qtamcnq.encode(), _klripridj, 100000, dklen=80)
        _izjsesvlp = _xunyxzj[:32]; _gdbzs = _xunyxzj[32:48]; _noxweoe = _xunyxzj[48:80]
        _iuchtlxdm = _zlrjt.new(_noxweoe, _fvfso, digestmod='sha256').digest()
        if not _zlrjt.compare_digest(_rpfotngqo, _iuchtlxdm):
            _zjqunugke.stderr.write("error: integrity check failed\n"); _zjqunugke.exit(1)
        import struct as _csfxdxna
        def _zxdqmhamv(k,c,n):
            s=[0x61707865,0x3320646e,0x79622d32,0x6b206574]
            for i in range(0,32,4):s.append(_csfxdxna.unpack('<I',k[i:i+4])[0])
            s.append(c&0xFFFFFFFF)
            for i in range(0,12,4):s.append(_csfxdxna.unpack('<I',n[i:i+4])[0])
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
            for i in range(16):r.extend(_csfxdxna.pack('<I',(s[i]+w[i])&0xFFFFFFFF))
            return bytes(r)
        _ozfiaqeni = _csfxdxna.unpack('<I',_gdbzs[:4])[0]
        _gdbzs = _gdbzs[4:]
        _klripridj = bytearray()
        while len(_klripridj) < len(_fvfso):
            _wgudjcxl = _zxdqmhamv(_izjsesvlp, _ozfiaqeni, _gdbzs)
            for _spsjoddm in range(min(64, len(_fvfso) - len(_klripridj))):
                _klripridj.append(_fvfso[len(_klripridj)] ^ _wgudjcxl[_spsjoddm])
            _ozfiaqeni += 1
        _wmtxlnhab = bytes(_klripridj)
    elif _jmyeyx == 1:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _rgqkm, algorithms as _iadfnq, modes as _nuvmcrpl
        except ImportError:
            _zjqunugke.stderr.write("error: cryptography not installed\n"); _zjqunugke.exit(1)
        _klripridj = _wzhveg[:16]; _rpfotngqo = _wzhveg[-32:]; _fvfso = _wzhveg[16:-32]
        _xunyxzj = _kxhgxcalv.pbkdf2_hmac('sha256', _qtamcnq.encode(), _klripridj, 100000, dklen=80)
        _izjsesvlp = _xunyxzj[:32]; _gdbzs = _xunyxzj[32:48]; _noxweoe = _xunyxzj[48:80]
        _iuchtlxdm = _zlrjt.new(_noxweoe, _fvfso, digestmod='sha256').digest()
        if not _zlrjt.compare_digest(_rpfotngqo, _iuchtlxdm):
            _zjqunugke.stderr.write("error: integrity check failed\n"); _zjqunugke.exit(1)
        _vsare = _rgqkm(_iadfnq.AES(_izjsesvlp), _nuvmcrpl.CBC(_gdbzs))
        _wmtxlnhab = _vsare.decryptor()
        _wmtxlnhab = _wmtxlnhab.update(_fvfso) + _wmtxlnhab.finalize()
        _wgudjcxl = _wmtxlnhab[-1]
        if _wgudjcxl < 1 or _wgudjcxl > 16 or not all(_ == _wgudjcxl for _ in _wmtxlnhab[-_wgudjcxl:]):
            _zjqunugke.stderr.write("error: decryption failed\n"); _zjqunugke.exit(1)
        _wmtxlnhab = _wmtxlnhab[:-_wgudjcxl]
    else:
        _zjqunugke.stderr.write("error: unsupported algorithm\n"); _zjqunugke.exit(1)
    _vk = bytes.fromhex("f7979a48806b08fc2fe6c814fdc76751d2ac33eaa65e66c00bfea5f272505332")
    _vn = bytes.fromhex("2c7eea8942efad32b135e0ae3db47da6")
    _sig = _wmtxlnhab[-32:]
    _pl = _wmtxlnhab[4:-32]
    import hmac, hashlib
    if not hmac.compare_digest(_sig, hmac.new(_vk, _pl, hashlib.sha256).digest()):
        _zjqunugke.stderr.write('error: VM integrity check failed\n'); _zjqunugke.exit(1)
    _pd = bytes([_pl[i] ^ _vk[i % 32] ^ _vn[i % 16] for i in range(len(_pl))])
    if _wmtxlnhab[1] == 1:
        import zlib as _jgoxdz
        _pd = _jgoxdz.decompress(_pd)
    elif _wmtxlnhab[1] == 2:
        import lzma as _jgoxdz
        _pd = _jgoxdz.decompress(_pd)
    elif _wmtxlnhab[1] == 3:
        import bz2 as _jgoxdz
        _pd = _jgoxdz.decompress(_pd)
    elif _wmtxlnhab[1] == 4:
        import brotli as _jgoxdz
        _pd = _jgoxdz.decompress(_pd)
    elif _wmtxlnhab[1] == 5:
        import zstandard as _jgoxdz
        _pd = _jgoxdz.decompress(_pd)
    elif _wmtxlnhab[1] == 6:
        import gzip as _jgoxdz
        _pd = _jgoxdz.decompress(_pd)
    elif _wmtxlnhab[1] == 7:
        import lz4.frame as _jgoxdz
        _pd = _jgoxdz.decompress(_pd)
    elif _wmtxlnhab[1] == 8:
        import snappy as _jgoxdz
        _pd = _jgoxdz.decompress(_pd)
    elif _wmtxlnhab[1] == 9:
        import gzip as _jgoxdz
        _pd = _jgoxdz.decompress(_pd)
    elif _wmtxlnhab[1] == 10:
        import blosc as _jgoxdz
        _pd = _jgoxdz.decompress(_pd)
    else:
        pass
    _c, _k, _m, _map, _ok, _ht, _pf = _vm_deserialize(_pd)
    exec(compile(_vfvcsmrt.b64decode("ZGVmIGFkZChhLCBiKToKICAgIHJldHVybiBhICsgYgoKZGVmIHN1YnRyYWN0KGEsIGIpOgogICAgcmV0dXJuIGEgLSBiCgpkZWYgbXVsdGlwbHkoYSwgYik6CiAgICByZXR1cm4gYSAqIGIKCmRlZiBkaXZpZGUoYSwgYik6CiAgICBpZiBiID09IDA6CiAgICAgICAgcmV0dXJuICdOb3QgZGl2aXNpYmxlIGJ5IHplcm8hJwogICAgcmV0dXJuIGEgLyBi"), '<exec>', 'exec'), globals())
    _vm_run(_c, _k, _m, globals(), locals(), _map, _ok, _ht, _pf)
if __name__ == '__main__':
    _vzagdfz()
