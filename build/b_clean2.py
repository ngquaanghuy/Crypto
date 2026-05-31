#!/usr/bin/env python3
def _hdnsijtr(_hjckppkk):
    return _hjckppkk % 3005 + 1

import hashlib as _qrzbsw, hmac as _ewitworeb, base64 as _pvlmllkc, sys as _dihlrz, zlib as _sdxob
_hjckppkk = 564711
_kmxhc = """+UysgjbYb9E8ZPeDDUkOcHv4ZihKk1HYaFADswfiDqUKIS1Iu9TxI8c6IanMzHqwVs5Ozg43S6hZDuoOuaRCH6DpzvouozJlWg9hCVODrPwdqbo3bNjFt8HwO3SHnCNqlIONOyPmOy6w5P4EtxwLMHLBpkpbEmjuCc9bVPTsDhziNFvyfi2F3eXHd6V7Rv4u0TCS3nO4zRAEYeES3WrtuuFyEfoBfPlf/+dkF7eJLVzT7OPr+Z9ZaHlL2PCJtSSHj4Ip8L8udJjJhVQsAaAZ2jXHYntnBOOscqMADGRKPKhoUpR4k7QXaavI7d5h+6yEMbS8jac9mAcTu92WOpjH3s2mM0VU76VMu1YOPZZKojpnBumUAVgtqQMe1Nkn9f3Gxe1YgeqpsvJw8zmPj/VGtW5GVFRasRZ44TRZ/vIwqkY5arzlClllUY6QwskUYffu1TVICO4z/BcvXMrimmv5T5w2icO1BXdIZRkKHTRCdEJLJj6TvwDTvZx8ji7DooQpgFMvJ+XttGwUxGieaADbgIMNFYa1sVxrno1KIFrLXTULdrFJ/T1+AOavtHHnPtadR32HT9y6Rv8+R9uYZEwN4M0rASUABjaYZgKkHB0UDZdBeb/8jaLz+s+p20Iwg4mVyHqGDrWuBt8Y6/YnXxjioqOZVLYm13E/cuRLRWI4NH9CJvxE3bl59F6n7P1INoOC6NEvXjVG7AE6WgpvsNn7l8L8dr0SCgTl419f0KJahVdm1jTlHbaJMYwK6yQoa8SqfNyp3Tv5aChmKWuZ8tfsfUaFpjqz7uVZWXjZQ3zjDMaMxHz+EzeaToyehTmkVnc2uVdxvx4djWu1SlxseNBwODfvwW7VXKaCUllGZiEM5tSVm1sa6EC+zaTEzUBK6MVUwsYsdcNbgYUO9en84wZF43h+z0muVA=="""
_lfdcaoqoc = 3
_lussijioh = _hdnsijtr(_hjckppkk)

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


def _gofotjq():
    _qyeairrjw = bytes.fromhex("a193d796b1a5aea78ea2d793a5dfac8ab28b8da1d1a18f87a4a7a5a08d969ebfaa80d5a1a2abb7b7939fa4b6a38daaa79fb7958ea39f8194de8ab68ab590829fdeb68ab2d0af89b583bc9eb4b2ad91dfa09e849097839eaaada18f8ed788a2ab8580d2a79f9e9fd48a849e949381958f909fa982b7bc9187add3d0d6bc89d0b4be82d68ea0aa879284b2d3d787a0d5a1d7d4899080a88d949cb1a9b09c9481a0a4bca98781aeaf8590d7ab91d7a19ca4d3d59396a18aa5d58adfb5d38d83bcb292bfa5a295b6adae9090878a97b0879e9f8eded480d79c81df92a4a1b3909fd687d497d38ed3928881939f8bab979390ad9ca4a5b6ab88b6958a859e82949c8196bea5d6d1d6afd0b2df81ab9fb5b0aaa4a5a8a5be8cd0b4d3a584b3b293ab92aebfb6a0ab849089a3df97a4a4b0a985acb6a8ab8c8dbebcb7a289aeb191d3a3aba79181d49687968195b7a5b78b8b8fa4d2b193deb59f81de9fb3b5b68da8b4df888193bfd2adb7d1a9d5b084d1b488b6d081b6a2ac83a19493a98da09fb6a8b6d0afa7adb5969582a5a3ae9f8abe9ea7aaa4d281b4aba5bf8d8ea5928da19280a2d4d0df948ab6aa89bca1a587d3d09794a1a2bf8c97d1d1a488b185de859fbeb6deaeab94bfa3ded297d79595ada8a7908db58c92df8a899ea2b28cd281bfa381ac8cb68082df9ed1b08fd3b5bca5a9b4bc8fb28b81b0b082b7a4d19c8196b1919690acd38c83b390dfb4919ea987d0a58bb6b3aa93b2d0a092b787d092d6d69f81968b9f9cadd388a3ded3a4a7918cb487a2a1a1b5d5d1a5a5b4aaa3a0d38daed48d9490a1b1a496aed6d4ae848cd391be8aafd7bca1a28cafbfd4d7bcab93a2a0aeaea08ab28a87bc9ed2df8881a28893899c8dac9fb3a5dfa2a9b087b482de8f8dd3d3929c8baadfab8d8d8881afbeb090a9859ea280d09e96d0d7afb5a794d1beb688838e8284b6bfaed085a296a5a5df8888abae97a7b4acdf91a2d3b4d2bc8fbea3aeb58f95b5a1d5d6d3dfd5bea29c838eacb6a89381a0878ddfd6d7ad9fdeadafbca893a7a29f95b394aea0b2a8a49fbf89be9ea48aacadae93b297acb4a7a49cb78aa48da591a98ad084a39e8eb4ded28bd7d1a983afd790ac8884d19c91a28d899792ae93a4a2888589938bd38a818aa7d7b3a3d2a9b1aad4d59284b18fa481a9d5d5ded2b2adacd6df96a385be949594d2b6b2d288aebca3d297d692d4dea8d0bca1d7b4b4a18cb0b3a3b1a180afa8b69481af9494add5b2d4a2808ad19683b291d381d4a7de9ca787b5a1d2a484a5b590aab2b3acbe93d78bbfa4b295d2ada592a1bc90a989d0afdf828fb7be80a29388be82b6d3b780978dafd294aca5acacbc91dfd2d0b59ed18ea8b1b4b28fadd5a5a48a8eb3b3ab81a1df88d6d08587ac93afd7abb4a581d6d4a4a5a2848baba7bfac90b797d594a7d1")
    _qyeairrjw = bytes(_ ^ 230 for _ in _qyeairrjw).decode()
    _mvzqzley = _pvlmllkc.b64decode(_kmxhc)
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher as _dfmvgtr, algorithms as _ctrgq, modes as _ctpvtso
    except ImportError:
        _dihlrz.stderr.write("error: cryptography not installed\n"); _dihlrz.exit(1)

    if _lfdcaoqoc == 0:
        _agmawmgy = _mvzqzley[:16]; _tpmtjvhrl = _mvzqzley[-32:]; _yrewcsud = _mvzqzley[16:-32]
        _abmakyd = _qrzbsw.pbkdf2_hmac('sha256', _qyeairrjw.encode(), _agmawmgy, 100000, dklen=64)
        _njhjjypib = _abmakyd[:32]; _fcxwpzw = _abmakyd[32:64]
        _mzcmc = _ewitworeb.new(_fcxwpzw, _yrewcsud, digestmod='sha256').digest()
        if not _ewitworeb.compare_digest(_tpmtjvhrl, _mzcmc):
            _dihlrz.stderr.write("error: integrity check failed\n"); _dihlrz.exit(1)
        _znsjx = _dfmvgtr(_ctrgq.AES(_njhjjypib), _ctpvtso.ECB())
        _aftihabe = _znsjx.decryptor()
        _aftihabe = _aftihabe.update(_yrewcsud) + _aftihabe.finalize()
        _iucmtyd = _aftihabe[-1]
        if _iucmtyd < 1 or _iucmtyd > 16 or not all(_ == _iucmtyd for _ in _aftihabe[-_iucmtyd:]):
            _dihlrz.stderr.write("error: decryption failed\n"); _dihlrz.exit(1)
        _aftihabe = _aftihabe[:-_iucmtyd]
    elif _lfdcaoqoc == 2:
        _agmawmgy = _mvzqzley[:16]; _tpmtjvhrl = _mvzqzley[-32:]; _yrewcsud = _mvzqzley[16:-32]
        _abmakyd = _qrzbsw.pbkdf2_hmac('sha256', _qyeairrjw.encode(), _agmawmgy, 100000, dklen=80)
        _njhjjypib = _abmakyd[:32]; _cesvvh = _abmakyd[32:48]; _fcxwpzw = _abmakyd[48:80]
        _mzcmc = _ewitworeb.new(_fcxwpzw, _yrewcsud, digestmod='sha256').digest()
        if not _ewitworeb.compare_digest(_tpmtjvhrl, _mzcmc):
            _dihlrz.stderr.write("error: integrity check failed\n"); _dihlrz.exit(1)
        _znsjx = _dfmvgtr(_ctrgq.AES(_njhjjypib), _ctpvtso.CTR(_cesvvh))
        _aftihabe = _znsjx.decryptor().update(_yrewcsud)
    elif _lfdcaoqoc == 7:
        _aftihabe = _pvlmllkc.b32decode(_mvzqzley)
    elif _lfdcaoqoc == 9:
        def _pdbtju(_zjwtsgh):
            if _zjwtsgh[:2] == b'<~': _zjwtsgh = _zjwtsgh[2:]
            if _zjwtsgh[-2:] == b'~>': _zjwtsgh = _zjwtsgh[:-2]
            _dmpzw = bytearray(); _zzcfkyt = 0
            while _zzcfkyt < len(_zjwtsgh):
                if _zjwtsgh[_zzcfkyt] == 122:
                    _dmpzw.extend(b'\x00\x00\x00\x00'); _zzcfkyt += 1; continue
                _bivelqqgy = 0; _rumld = 0
                while _zzcfkyt < len(_zjwtsgh) and _rumld < 5:
                    _bivelqqgy = _bivelqqgy * 85 + (_zjwtsgh[_zzcfkyt] - 33); _zzcfkyt += 1; _rumld += 1
                _bghqi = _rumld - 1
                if _bghqi > 0: _dmpzw.extend(_bivelqqgy.to_bytes(4, 'big')[4-_bghqi:])
            return bytes(_dmpzw)
        _aftihabe = _pdbtju(_mvzqzley)
    elif _lfdcaoqoc == 4:
        _agmawmgy = _mvzqzley[:16]; _tpmtjvhrl = _mvzqzley[-32:]; _yrewcsud = _mvzqzley[16:-32]
        _abmakyd = _qrzbsw.pbkdf2_hmac('sha256', _qyeairrjw.encode(), _agmawmgy, 100000, dklen=80)
        _njhjjypib = _abmakyd[:32]; _cesvvh = _abmakyd[32:48]; _fcxwpzw = _abmakyd[48:80]
        _mzcmc = _ewitworeb.new(_fcxwpzw, _yrewcsud, digestmod='sha256').digest()
        if not _ewitworeb.compare_digest(_tpmtjvhrl, _mzcmc):
            _dihlrz.stderr.write("error: integrity check failed\n"); _dihlrz.exit(1)
        _znsjx = _dfmvgtr(_ctrgq.ChaCha20(_njhjjypib, _cesvvh), mode=None)
        _aftihabe = _znsjx.decryptor().update(_yrewcsud)
    elif _lfdcaoqoc == 11:
        _agmawmgy = _mvzqzley[:16]; _tpmtjvhrl = _mvzqzley[-32:]; _yrewcsud = _mvzqzley[16:-32]
        _abmakyd = _qrzbsw.pbkdf2_hmac('sha256', _qyeairrjw.encode(), _agmawmgy, 100000, dklen=64)
        _njhjjypib = _abmakyd[:32]; _fcxwpzw = _abmakyd[32:64]
        _mzcmc = _ewitworeb.new(_fcxwpzw, _yrewcsud, digestmod='sha256').digest()
        if not _ewitworeb.compare_digest(_tpmtjvhrl, _mzcmc):
            _dihlrz.stderr.write("error: integrity check failed\n"); _dihlrz.exit(1)
        _iucmtyd = _njhjjypib[0]
        _aftihabe = bytearray()
        for _quqop in range(len(_yrewcsud)):
            _agmawmgy = _yrewcsud[_quqop] ^ _iucmtyd
            _aftihabe.append(_agmawmgy)
            _iucmtyd = _yrewcsud[_quqop] ^ _njhjjypib[ (_quqop + 1) % len(_njhjjypib) ]
            _iucmtyd = (((_iucmtyd << 3) & 0xFF) | (_iucmtyd >> 5)) ^ 0x5A
        _aftihabe = bytes(_aftihabe)
    elif _lfdcaoqoc == 1:
        _agmawmgy = _mvzqzley[:16]; _tpmtjvhrl = _mvzqzley[-32:]; _yrewcsud = _mvzqzley[16:-32]
        _abmakyd = _qrzbsw.pbkdf2_hmac('sha256', _qyeairrjw.encode(), _agmawmgy, 100000, dklen=80)
        _njhjjypib = _abmakyd[:32]; _cesvvh = _abmakyd[32:48]; _fcxwpzw = _abmakyd[48:80]
        _mzcmc = _ewitworeb.new(_fcxwpzw, _yrewcsud, digestmod='sha256').digest()
        if not _ewitworeb.compare_digest(_tpmtjvhrl, _mzcmc):
            _dihlrz.stderr.write("error: integrity check failed\n"); _dihlrz.exit(1)
        _znsjx = _dfmvgtr(_ctrgq.AES(_njhjjypib), _ctpvtso.CBC(_cesvvh))
        _aftihabe = _znsjx.decryptor()
        _aftihabe = _aftihabe.update(_yrewcsud) + _aftihabe.finalize()
        _iucmtyd = _aftihabe[-1]
        if _iucmtyd < 1 or _iucmtyd > 16 or not all(_ == _iucmtyd for _ in _aftihabe[-_iucmtyd:]):
            _dihlrz.stderr.write("error: decryption failed\n"); _dihlrz.exit(1)
        _aftihabe = _aftihabe[:-_iucmtyd]
    elif _lfdcaoqoc == 10:
        _aftihabe = bytes.fromhex(_mvzqzley.decode('ascii'))
    elif _lfdcaoqoc == 13:
        _agmawmgy = _mvzqzley[:16]; _tpmtjvhrl = _mvzqzley[-32:]; _yrewcsud = _mvzqzley[16:-32]
        _abmakyd = _qrzbsw.pbkdf2_hmac('sha256', _qyeairrjw.encode(), _agmawmgy, 100000, dklen=80)
        _njhjjypib = _abmakyd[:32]; _cesvvh = _abmakyd[32:48]; _fcxwpzw = _abmakyd[48:80]
        _mzcmc = _ewitworeb.new(_fcxwpzw, _yrewcsud, digestmod='sha256').digest()
        if not _ewitworeb.compare_digest(_tpmtjvhrl, _mzcmc):
            _dihlrz.stderr.write("error: integrity check failed\n"); _dihlrz.exit(1)
        import struct as _lussijioh
        def _hdnsijtr(k,c,n):
            s=[0x61707865,0x3320646e,0x79622d32,0x6b206574]
            for i in range(0,32,4):s.append(_lussijioh.unpack('<I',k[i:i+4])[0])
            s.append(c&0xFFFFFFFF)
            for i in range(0,12,4):s.append(_lussijioh.unpack('<I',n[i:i+4])[0])
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
            for i in range(16):r.extend(_lussijioh.pack('<I',(s[i]+w[i])&0xFFFFFFFF))
            return bytes(r)
        _quqop = _lussijioh.unpack('<I',_cesvvh[:4])[0]
        _cesvvh = _cesvvh[4:]
        _agmawmgy = bytearray()
        while len(_agmawmgy) < len(_yrewcsud):
            _iucmtyd = _hdnsijtr(_njhjjypib, _quqop, _cesvvh)
            for _hjckppkk in range(min(64, len(_yrewcsud) - len(_agmawmgy))):
                _agmawmgy.append(_yrewcsud[len(_agmawmgy)] ^ _iucmtyd[_hjckppkk])
            _quqop += 1
        _aftihabe = bytes(_agmawmgy)
    elif _lfdcaoqoc == 5:
        _agmawmgy = _mvzqzley[:16]; _tpmtjvhrl = _mvzqzley[-32:]; _yrewcsud = _mvzqzley[16:-32]
        _abmakyd = _qrzbsw.pbkdf2_hmac('sha256', _qyeairrjw.encode(), _agmawmgy, 100000, dklen=64)
        _njhjjypib = _abmakyd[:32]; _fcxwpzw = _abmakyd[32:64]
        _mzcmc = _ewitworeb.new(_fcxwpzw, _yrewcsud, digestmod='sha256').digest()
        if not _ewitworeb.compare_digest(_tpmtjvhrl, _mzcmc):
            _dihlrz.stderr.write("error: integrity check failed\n"); _dihlrz.exit(1)
        _aftihabe = bytes(_yrewcsud[i] ^ _njhjjypib[i % 32] for i in range(len(_yrewcsud)))
    elif _lfdcaoqoc == 3:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _xvgyytcju
        _agmawmgy = _mvzqzley[:16]; _tpmtjvhrl = _mvzqzley[-32:]; _aftihabe = _mvzqzley[16:-32]
        _yrewcsud = _aftihabe[:-16]; _iucmtyd = _aftihabe[-16:]
        _abmakyd = _qrzbsw.pbkdf2_hmac('sha256', _qyeairrjw.encode(), _agmawmgy, 100000, dklen=76)
        _njhjjypib = _abmakyd[:32]; _cesvvh = _abmakyd[32:44]; _fcxwpzw = _abmakyd[44:76]
        _mzcmc = _ewitworeb.new(_fcxwpzw, _aftihabe, digestmod='sha256').digest()
        if not _ewitworeb.compare_digest(_tpmtjvhrl, _mzcmc):
            _dihlrz.stderr.write("error: integrity check failed\n"); _dihlrz.exit(1)
        _aftihabe = _xvgyytcju(_njhjjypib).decrypt(_cesvvh, _yrewcsud + _iucmtyd, None)
    elif _lfdcaoqoc == 12:
        _agmawmgy = _mvzqzley[:16]; _tpmtjvhrl = _mvzqzley[-32:]; _yrewcsud = _mvzqzley[16:-32]
        _abmakyd = _qrzbsw.pbkdf2_hmac('sha256', _qyeairrjw.encode(), _agmawmgy, 100000, dklen=64)
        _njhjjypib = _abmakyd[:32]; _fcxwpzw = _abmakyd[32:64]
        _mzcmc = _ewitworeb.new(_fcxwpzw, _yrewcsud, digestmod='sha256').digest()
        if not _ewitworeb.compare_digest(_tpmtjvhrl, _mzcmc):
            _dihlrz.stderr.write("error: integrity check failed\n"); _dihlrz.exit(1)
        _iucmtyd = 3 + (_agmawmgy[0] & 7)
        _agmawmgy = bytearray(_yrewcsud)
        for _quqop in range(_iucmtyd - 1, -1, -1):
            _hdnsijtr = (3 + _quqop) & 7
            _hjckppkk = (_quqop * 0x1B + 0x5A) & 0xFF
            for _cesvvh in range(len(_agmawmgy)):
                _iucmtyd = _agmawmgy[_cesvvh]
                _iucmtyd ^= _hjckppkk
                _iucmtyd = ((_iucmtyd >> _hdnsijtr) | ((_iucmtyd << (8 - _hdnsijtr)) & 0xFF))
                _iucmtyd ^= _njhjjypib[(_quqop * len(_agmawmgy) + _cesvvh) % len(_njhjjypib)]
                _agmawmgy[_cesvvh] = _iucmtyd
        _aftihabe = bytes(_agmawmgy)
    elif _lfdcaoqoc == 6:
        _aftihabe = _pvlmllkc.b64decode(_mvzqzley)
    elif _lfdcaoqoc == 8:
        _zkkery = ('0','1','2','3','4','5','6','7','8','9',
                'A','B','C','D','E','F','G','H','I','J','K','L','M',
                'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
                'a','b','c','d','e','f','g','h','i','j','k','l','m',
                'n','o','p','q','r','s','t','u','v','w','x','y','z',
                '!','#','$','%','&','(',')','*','+','-',';','<','=',
                '>','?','@','^','_','`','{','|','}','~')
        _xusow = {c:i for i,c in enumerate(_zkkery)}
        def _ffcjhxa(_svtllpdb):
            _ycrkgi = bytearray(); _hgeawbnd = 0
            while _hgeawbnd < len(_svtllpdb):
                _rmpopsjk = 0; _uvdzwkz = 0
                while _hgeawbnd < len(_svtllpdb) and _uvdzwkz < 5:
                    _rmpopsjk = _rmpopsjk * 85 + _xusow[chr(_svtllpdb[_hgeawbnd])]; _hgeawbnd += 1; _uvdzwkz += 1
                _blglwnta = _uvdzwkz - 1
                if _blglwnta > 0: _ycrkgi.extend(_rmpopsjk.to_bytes(4, 'big')[4-_blglwnta:])
            return bytes(_ycrkgi)
        _aftihabe = _ffcjhxa(_mvzqzley)
    else:
        _dihlrz.stderr.write("error: unsupported algorithm\n"); _dihlrz.exit(1)
    _vk = bytes.fromhex("9191ee5d577ecf8409d6d4b06ae0bc592e2efd0a1bd73b21d27598faeac7793a")
    _vn = bytes.fromhex("f241c3b8d402df6ad518b97191d269be")
    _sig = _aftihabe[-32:]
    _pl = _aftihabe[4:-32]
    import hmac, hashlib
    if not hmac.compare_digest(_sig, hmac.new(_vk, _pl, hashlib.sha256).digest()):
        _dihlrz.stderr.write('error: VM integrity check failed\n'); _dihlrz.exit(1)
    _pd = bytes([_pl[i] ^ _vk[i % 32] ^ _vn[i % 16] for i in range(len(_pl))])
    if _aftihabe[1] == 1:
        import zlib as _sdxob
        _pd = _sdxob.decompress(_pd)
    elif _aftihabe[1] == 2:
        import lzma as _sdxob
        _pd = _sdxob.decompress(_pd)
    elif _aftihabe[1] == 3:
        import bz2 as _sdxob
        _pd = _sdxob.decompress(_pd)
    elif _aftihabe[1] == 4:
        import brotli as _sdxob
        _pd = _sdxob.decompress(_pd)
    elif _aftihabe[1] == 5:
        import zstandard as _sdxob
        _pd = _sdxob.decompress(_pd)
    elif _aftihabe[1] == 6:
        import gzip as _sdxob
        _pd = _sdxob.decompress(_pd)
    elif _aftihabe[1] == 7:
        import lz4.frame as _sdxob
        _pd = _sdxob.decompress(_pd)
    elif _aftihabe[1] == 8:
        import snappy as _sdxob
        _pd = _sdxob.decompress(_pd)
    elif _aftihabe[1] == 9:
        import gzip as _sdxob
        _pd = _sdxob.decompress(_pd)
    elif _aftihabe[1] == 10:
        import blosc as _sdxob
        _pd = _sdxob.decompress(_pd)
    else:
        pass
    _c, _k, _m, _map, _ok, _ht, _pf = _vm_deserialize(_pd)
    exec(compile(_pvlmllkc.b64decode("ZGVmIGFkZChhLCBiKToKICAgIHJldHVybiBhICsgYgoKZGVmIHN1YnRyYWN0KGEsIGIpOgogICAgcmV0dXJuIGEgLSBiCgpkZWYgbXVsdGlwbHkoYSwgYik6CiAgICByZXR1cm4gYSAqIGIKCmRlZiBkaXZpZGUoYSwgYik6CiAgICBpZiBiID09IDA6CiAgICAgICAgcmV0dXJuICdOb3QgZGl2aXNpYmxlIGJ5IHplcm8hJwogICAgcmV0dXJuIGEgLyBi"), '<exec>', 'exec'), globals())
    _vm_run(_c, _k, _m, globals(), locals(), _map, _ok, _ht, _pf)
if __name__ == '__main__':
    _gofotjq()
