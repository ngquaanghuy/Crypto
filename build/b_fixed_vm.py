#!/usr/bin/env python3
def _iszav(_wlqyw):
    return _wlqyw % 6647 + 1

import hashlib as _qgdxpgivg, hmac as _gfpymo, base64 as _glava, sys as _oemsoah, zlib as _spuqf
_wlqyw = 305579
_acinkn = """eN7/ED2n9hisfNH+wDbWZ3WerNr6jFOw8FFsOxc7AKKNZzs7Clwi9E72zeS3SHjXSbEr2rZYS3YFVKi+G3TLU5Eu55kNKGSNdfFZ3of0Ub2QDCL8em6Jkdeq29r73PClTVnINHC+N8TXDFemjYJht0hB8rNEu1sVg+xd3A9UznLVbD2HgIMbrShh6zHixSSYwqe+ZR/J3FLxqCi6qILQV2q8E548hK94nVrIcxWpVhXhD+zRM4exeiZRezsN1ALgngMXXDvDSaSW5Dl1pI91AThdxBoGUAI5v1lgCexR7o2UmULst800fODd8Js1dRfMivPowog/GgWWL7i6sHiHECOe04Gvh6RYN1c3yGlMrXCbaUWP6slUuukbw0fFS78LJ9qeWyD0aBxaHWrgDuh87TSoi1xLC4SIUwVlcAT9ICmXtqpsqW8xnguvUO6XzxcgO9Uvcmq2y1YLqjiCD3Nj/4JeedJtaRSrUpSM9kZgdOga5wzHhE2stiBdNXCYjX9E2ZH1CmIqFzW4wxdwmbtG7wNMI5qqY+v+wj3Mdp58n83F+arV7cSg3iX9M4/k/wMNDjyW4q8QLF82kw64d+VMYexyNUSshhIZN44EIG44W8bWmmMON5oAHg1qKs12vxxFfiXV5J0k6x3R/HZHouLEElM/Uahwjz2MpLpm7YrvaluttldDn2YHhMwGKkhyoV2qMayu0vRh5cemBLVE0lG9LSUGLE0KrKc28GukTv39xPvK679SgfzBc/krTMiPUyoj0U8lmECTGHp4hHnmkarvP7jzSEgaVmqo/0NtDNtN07SimFKNWGiV18pIH207KTUbRZ2lfLiQRasIg4nA7xLinwAdGPxv4XzIgLBbmXS9z/Oi9KUPqIcQN2m3+17b3dbAFHRFkMSx0f4oS92HuR/lUquYsJ7RsLTaLGo="""
_iatfi = 3
_rsuonmwh = _iszav(_wlqyw)

# Helper: return (mapped_rs2, unmapped_rs2) for ops that use rs2 as count
def _vm_rs2(_dec, _rm, _op):
    _raw = _dec[3]
    _mapped = _rm[_raw & 0x3F] if (_raw & 0x3F) < 64 else 0
    # Ops using rs2 as count (not register): BUILD_TUPLE(43), BUILD_LIST(44), BUILD_STRING(63)
    # Also BUILD_STRING - the Python compiler uses rs2 for count. Others use _imm low bits.
    _count_ops = frozenset((43, 44, 63))
    if _op in _count_ops:
        return _raw, _raw  # return unmapped as both (used as count)
    return _mapped, _raw  # mapped for register, raw for reference

def _vm_decode_vl(_c, _p, _k, _m, _rm):
    _tag = _c[_p] ^ _k[_p % 32]
    _cls = (_tag >> 6) & 0x3
    if _cls == 0:
        _op = _m[_tag & 0x0F]
        _rd = _rm[(_c[_p+1] >> 4) & 0x0F] if _c[_p+1] < 64 else 0
        _rs1 = _rm[_c[_p+1] & 0x0F] if (_c[_p+1] & 0x0F) < 64 else 0
        return _op, _rd, _rs1, 0, 0, 2, 0
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
        return _op, _rd, _rs1, 0, _imm, 4, 0
    elif _cls == 2:
        _b1 = _c[_p+1] ^ _k[(_p+1) % 32]
        _b2 = _c[_p+2] ^ _k[(_p+2) % 32]
        _b3 = _c[_p+3] ^ _k[(_p+3) % 32]
        _b4 = _c[_p+4] ^ _k[(_p+4) % 32]
        _op = _m[_b1 & 0xFF]
        _rd = _rm[_b2 & 0x3F] if (_b2 & 0x3F) < 64 else 0
        _rs1 = _rm[_b3 & 0x3F] if (_b3 & 0x3F) < 64 else 0
        _rs2_m = _rm[_b4 & 0x3F] if (_b4 & 0x3F) < 64 else 0
        _rs2_u = _b4 & 0x3F
        _i0 = _c[_p+5] ^ _k[(_p+5) % 32]
        _i1 = _c[_p+6] ^ _k[(_p+6) % 32]
        _i2 = _c[_p+7] ^ _k[(_p+7) % 32]
        _i3 = _c[_p+8] ^ _k[(_p+8) % 32]
        _imm = _i0 | (_i1 << 8) | (_i2 << 16) | (_i3 << 24)
        _count_ops = frozenset((43, 44, 63))
        _rs2 = _rs2_u if _op in _count_ops else _rs2_m
        return _op, _rd, _rs1, _rs2, _imm, 9, _rs2_u
    else:
        _nb = _tag & 0x0F
        if _nb == 0:
            _nb = 1
        _op = _m[(_c[_p+1] ^ _k[(_p+1) % 32]) & 0xFF]
        _rd = _rm[(_c[_p+2] ^ _k[(_p+2) % 32]) & 0x3F] if ((_c[_p+2] ^ _k[(_p+2) % 32]) & 0x3F) < 64 else 0
        _rs1 = _rm[(_c[_p+3] ^ _k[(_p+3) % 32]) & 0x3F] if ((_c[_p+3] ^ _k[(_p+3) % 32]) & 0x3F) < 64 else 0
        _rs2_m = _rm[(_c[_p+4] ^ _k[(_p+4) % 32]) & 0x3F] if ((_c[_p+4] ^ _k[(_p+4) % 32]) & 0x3F) < 64 else 0
        _rs2_u = (_c[_p+4] ^ _k[(_p+4) % 32]) & 0x3F
        _i0 = _c[_p+5] ^ _k[(_p+5) % 32]
        _i1 = _c[_p+6] ^ _k[(_p+6) % 32]
        _i2 = _c[_p+7] ^ _k[(_p+7) % 32]
        _i3 = _c[_p+8] ^ _k[(_p+8) % 32]
        _imm = _i0 | (_i1 << 8) | (_i2 << 16) | (_i3 << 24)
        _ilen = 2 + _nb * 8
        _count_ops = frozenset((43, 44, 63))
        _rs2 = _rs2_u if _op in _count_ops else _rs2_m
        return _op, _rd, _rs1, _rs2, _imm, _ilen, _rs2_u

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
            return _m[_tag & 0x0F], _rd, _rs1, 0, 0, 2, 0
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
                return _m[_op_v1 & 0xFF], _rm[_rd_v1] if _rd_v1 < 64 else 0, _rm[_rs1_v1] if _rs1_v1 < 64 else 0, 0, 0, 3, 0
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
                return _m[_op2], _rm[_rd_bits], _rm[_rs1_val] if _rs1_val < 64 else 0, 0, 0, 3, 0
        # Fallback
        return _m[_tag & 0x0F], 0, 0, 0, 0, 2, 0
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
            return _m[_op0], _rm[_rd0] if _rd0 < 64 else 0, _rm[_rs1_0] if _rs1_0 < 64 else 0, 0, _imm0, 4, 0
        elif _vbit and _p + 4 <= len(_c):
            # Variant 1 (imm in tag, bit 5 = 1)
            _op1 = (_b3 >> 3) & 0x1F
            _imm_lo = _tag & 0x1F
            _imm_hi = (_b2 | ((_b3 & 0x07) << 8))
            _imm1 = (_imm_hi << 5) | _imm_lo
            if _imm1 & 0x8000:
                _imm1 = _imm1 | (-1 << 16)
            return _m[_op1], _rm[_rd0] if _rd0 < 64 else 0, _rm[_rs1_0] if _rs1_0 < 64 else 0, 0, _imm1, 4, 0
        # Fallback
        return 0, 0, 0, 0, 0, 2, 0
    elif _cls == 2:
        # Long class
        _count_ops = frozenset((43, 44, 63))
        _variant = (_tag >> 2) & 0x0F
        if _variant == 0 and _p + 9 <= len(_c):
            _b1 = _c[_p+1] ^ _k[(_p+1) % 32]
            _b2 = _c[_p+2] ^ _k[(_p+2) % 32]
            _b3 = _c[_p+3] ^ _k[(_p+3) % 32]
            _b4 = _c[_p+4] ^ _k[(_p+4) % 32]
            _op = _m[_b1 & 0xFF]
            _rd = _rm[_b2 & 0x3F] if (_b2 & 0x3F) < 64 else 0
            _rs1 = _rm[_b3 & 0x3F] if (_b3 & 0x3F) < 64 else 0
            _rs2_u = _b4 & 0x3F
            _rs2 = _rs2_u if _op in _count_ops else _rm[_rs2_u]
            _i0 = _c[_p+5] ^ _k[(_p+5) % 32]
            _i1 = _c[_p+6] ^ _k[(_p+6) % 32]
            _i2 = _c[_p+7] ^ _k[(_p+7) % 32]
            _i3 = _c[_p+8] ^ _k[(_p+8) % 32]
            _imm = _i0 | (_i1 << 8) | (_i2 << 16) | (_i3 << 24)
            return _op, _rd, _rs1, _rs2, _imm, 9, _rs2_u
        elif _variant == 1 and _p + 9 <= len(_c):
            _b1 = _c[_p+1] ^ _k[(_p+1) % 32]
            _b2 = _c[_p+2] ^ _k[(_p+2) % 32]
            _b3 = _c[_p+3] ^ _k[(_p+3) % 32]
            _b4 = _c[_p+4] ^ _k[(_p+4) % 32]
            _op = _m[_b2 & 0xFF]
            _rd = _rm[_b1 & 0x3F] if (_b1 & 0x3F) < 64 else 0
            _rs1 = _rm[_b4 & 0x3F] if (_b4 & 0x3F) < 64 else 0
            _rs2_u = _b3 & 0x3F
            _rs2 = _rs2_u if _op in _count_ops else _rm[_rs2_u]
            _i0 = _c[_p+5] ^ _k[(_p+5) % 32]
            _i1 = _c[_p+6] ^ _k[(_p+6) % 32]
            _i2 = _c[_p+7] ^ _k[(_p+7) % 32]
            _i3 = _c[_p+8] ^ _k[(_p+8) % 32]
            _imm = _i0 | (_i1 << 8) | (_i2 << 16) | (_i3 << 24)
            return _op, _rd, _rs1, _rs2, _imm, 9, _rs2_u
        elif _variant == 2 and _p + 10 <= len(_c):
            _b1 = _c[_p+1] ^ _k[(_p+1) % 32]
            _b2 = _c[_p+2] ^ _k[(_p+2) % 32]
            _b3 = _c[_p+3] ^ _k[(_p+3) % 32]
            _b4 = _c[_p+4] ^ _k[(_p+4) % 32]
            _op = _m[_b1 & 0xFF]
            _rd = _rm[_b3 & 0x3F] if (_b3 & 0x3F) < 64 else 0
            _rs1 = _rm[_b4 & 0x3F] if (_b4 & 0x3F) < 64 else 0
            _rs2_u = _b2 & 0x3F
            _rs2 = _rs2_u if _op in _count_ops else _rm[_rs2_u]
            _i0 = _c[_p+7] ^ _k[(_p+7) % 32]
            _i1 = _c[_p+8] ^ _k[(_p+8) % 32]
            _i2 = _c[_p+5] ^ _k[(_p+5) % 32]
            _i3 = _c[_p+6] ^ _k[(_p+6) % 32]
            _imm = _i0 | (_i1 << 8) | (_i2 << 16) | (_i3 << 24)
            return _op, _rd, _rs1, _rs2, _imm, 10, _rs2_u
        # Fallback
        if _p + 9 <= len(_c):
            _b1 = _c[_p+1] ^ _k[(_p+1) % 32]
            _b2 = _c[_p+2] ^ _k[(_p+2) % 32]
            _b3 = _c[_p+3] ^ _k[(_p+3) % 32]
            _b4 = _c[_p+4] ^ _k[(_p+4) % 32]
            _op = _m[_b1 & 0xFF]
            _rd = _rm[_b2 & 0x3F] if (_b2 & 0x3F) < 64 else 0
            _rs1 = _rm[_b3 & 0x3F] if (_b3 & 0x3F) < 64 else 0
            _rs2_u = _b4 & 0x3F
            _rs2 = _rs2_u if _op in _count_ops else _rm[_rs2_u]
            _i0 = _c[_p+5] ^ _k[(_p+5) % 32]
            _i1 = _c[_p+6] ^ _k[(_p+6) % 32]
            _i2 = _c[_p+7] ^ _k[(_p+7) % 32]
            _i3 = _c[_p+8] ^ _k[(_p+8) % 32]
            _imm = _i0 | (_i1 << 8) | (_i2 << 16) | (_i3 << 24)
            return _op, _rd, _rs1, _rs2, _imm, 9, _rs2_u
        return 0, 0, 0, 0, 0, 2, 0
    else:
        _count_ops = frozenset((43, 44, 63))
        _nb = _tag & 0x0F
        if _nb == 0:
            _nb = 1
        _op = _m[(_c[_p+1] ^ _k[(_p+1) % 32]) & 0xFF]
        _rd = _rm[(_c[_p+2] ^ _k[(_p+2) % 32]) & 0x3F] if ((_c[_p+2] ^ _k[(_p+2) % 32]) & 0x3F) < 64 else 0
        _rs1 = _rm[(_c[_p+3] ^ _k[(_p+3) % 32]) & 0x3F] if ((_c[_p+3] ^ _k[(_p+3) % 32]) & 0x3F) < 64 else 0
        _rs2_u = (_c[_p+4] ^ _k[(_p+4) % 32]) & 0x3F
        _rs2 = _rs2_u if _op in _count_ops else _rm[_rs2_u]
        _i0 = _c[_p+5] ^ _k[(_p+5) % 32]
        _i1 = _c[_p+6] ^ _k[(_p+6) % 32]
        _i2 = _c[_p+7] ^ _k[(_p+7) % 32]
        _i3 = _c[_p+8] ^ _k[(_p+8) % 32]
        _imm = _i0 | (_i1 << 8) | (_i2 << 16) | (_i3 << 24)
        _ilen = 2 + _nb * 8
        return _op, _rd, _rs1, _rs2, _imm, _ilen, _rs2_u

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
    # Helper: compute runtime register for consecutive compiler registers
    def _rr(_base_runtime, _offset):
        _cbase = _reg_map.index(_base_runtime)
        return _reg_map[_cbase + _offset]
    while _ip < _n:
        _cycle += 1
        _op, _rd, _rs1, _rs2, _imm, _ilen, _ = _decode()
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
            _args = tuple(_r[_rr(_rs1, 1 + _i)] for _i in range(_imm & 0xFFFF))
            _r[_rd] = _fn(*_args)
        elif _op == 41:
            _r[_rd] = _names[_rd](*[_r[_rr(_rs1, _i)] for _i in range(_imm & 0xFFFF)])
        elif _op == 42:
            return _r[_rd]
        elif _op == 43:
            _r[_rd] = tuple(_r[_rr(_rs1, _i)] for _i in range(_rs2))
        elif _op == 44:
            _r[_rd] = list(_r[_rr(_rs1, _i)] for _i in range(_rs2))
        elif _op == 62:
            _r[_rd] = str(_r[_rs1])
        elif _op == 63:
            _r[_rd] = ''.join(str(_r[_rr(_rs1, _i)]) for _i in range(_rs2))
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
            _args = tuple(_r[_rr(_rs1, 1 + _i)] for _i in range(_argc))
            _r[_rd] = _fn(*_args)
        elif _op == 81:
            _obj = _r[_rs1]
            _vtable = _r[_rr(_rs1, 1)]
            _midx = _imm & 0xFFFF
            _argc = (_imm >> 16) & 0xFFFF
            _method = _vtable[_midx]
            _args = tuple(_r[_rr(_rs1, 2 + _i)] for _i in range(_argc))
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
    _rs2_u = _dec[3] & 0x3F
    _count_ops = frozenset((43, 44, 63))
    _rs2 = _rs2_u if _op in _count_ops else _rm[_rs2_u]
    _imm = _dec[4] | (_dec[5] << 8) | (_dec[6] << 16) | (_dec[7] << 24)
    return _op, _rd, _rs1, _rs2, _imm, 8, _rs2_u

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


def _rrpta():
    _ifhmt = bytes.fromhex("b7ab8ab28bf0b0f2b4b59296afa6a1958688f3f0a9b392f4a38d9aa1b48eb89390b5f3fba3948b97f6faa09383aab687bab6b4a5faa983a18093a4a5adbab6a1aa84a0f68f909ba68e8aa894a8b0aba1ad8f80fb9092fbb4f0a7aaab8a80f7f0b4838890b398f6f3a18fa7f6abb7f6b387a3b390a48ff48c89888ba3a3b1abf183a79390baf59485b1f1a196f4f5908788adf2b5b48a80a492a4b4f4f29a96a68e9390baa8908d958c80ba8ea3baf48e958ca18493a9b2baac9881b4f18ba0a394fb85948890bbb795b6aa93af92ac8ba89091b5f0a1aaab90adb0b0a78d8bbba38cf4a9f683f5f58d8381faaa8788bba5a5a085f3ac8b8bb0f1f28c81f29883b2a7aba087f590f0b1f3a6a59a90b38f859aa5a1ab8ff28b93fa98ada1a88b95b0f581939886858f8c8b93a6b184958384a7a88aa9b0b098f2b498b0a9b0a0afa890b28ca496819ba8b7f588858bf29184f092928797a1819a8984abad84ab8c81bab3a0baa08aa19484f5878fb08888a9b198b297938c91a6a8b88197b193aefa96ad81f4f3b3afa5b2898da18da9b0a0a49b948ca48e98abb49385f5b7f59480b8f6f4b7f18af19ab6f7baa6a6868ca6f7b589ab91f0b596b6b6baf3b1859a9af7af8d8cb2b6a785aa879a8094b5898080aa81f681a5f2fb9187b0a1fbbb9685a78b92a0fb8781bafaa0f2859780b1f495aabb98a6f3a0a6f6f68d8c83a4a9a4b38afaa8a9838a8ab0a895f3858480a3a5b0f79790fa93848493b4879197908990858cf48ff68dfbbaa990bba8fa91f692a8a7f58e86f79887b3bbb7abafb8f09ab1b7adf38095f49a8db285b4838bfbb0f2ba9ab4abba86f1b5b495a687a7a3f2a080afa490b3a8a1aba6b1f386b7f3a5a588b098afae8a8fa3f7b6a79af4ba948dbbf5a69183a38588b68afbb88a8b8f9b91acf6f2a8ae92919485ada8978d8bb0868d898a8c97b2b7b09b8c90abad9af5989a86988590a0a0988492f1f6acaa8ea6a186a4b3a9a8f5fb8e9394a8f3f2abb8aeb6808af380a58f8f90abf0a697ae81aaf7b79a858a97849aadb28cb489b481fa97b7a6f1b6b0abacbab4b481f180f38cb4b28593a4a3948ab881878b9a80898fa7a4f7ba9ab2b588afaba591a48d8ea8ad979687f4a38092b49b84b6f7a3ae9bfa848fae8cb7b8b297f0ad83afbbb793b7a8aa88f38784f48cfb8391a693f29786808186aa81baf4a0f3b2b48a86f0ba8a97b2aef1a98e8598fa85aaa18ead95f3b3978da1a69a989b98fb93f6b5f0908baa9ab4ac85858fa48ebb9ba6b18eb18b90af80aa93b08ff0878f95979a8d9abbb5868daf8d948aafb7abb5a895b4b1a591b6a0faa0afad80ac8784b6b195978b88a0b5f4b28db4fa85ab8f85fa9590afb09580889294898b89f49bf286b2aff08aa692f394f78db2a19ba0b2a4ac8d988483ada8f280f59383af")
    _ifhmt = bytes(_ ^ 194 for _ in _ifhmt).decode()
    _andcvsukp = _glava.b64decode(_acinkn)
    if _iatfi == 8:
        _vfjhrc = ('0','1','2','3','4','5','6','7','8','9',
                'A','B','C','D','E','F','G','H','I','J','K','L','M',
                'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
                'a','b','c','d','e','f','g','h','i','j','k','l','m',
                'n','o','p','q','r','s','t','u','v','w','x','y','z',
                '!','#','$','%','&','(',')','*','+','-',';','<','=',
                '>','?','@','^','_','`','{','|','}','~')
        _movbsglr = {c:i for i,c in enumerate(_vfjhrc)}
        def _ndinj(_mfrphpj):
            _jequojxkx = bytearray(); _fyilmzgzc = 0
            while _fyilmzgzc < len(_mfrphpj):
                _pledrv = 0; _akblvibqw = 0
                while _fyilmzgzc < len(_mfrphpj) and _akblvibqw < 5:
                    _pledrv = _pledrv * 85 + _movbsglr[chr(_mfrphpj[_fyilmzgzc])]; _fyilmzgzc += 1; _akblvibqw += 1
                _pikcp = _akblvibqw - 1
                if _pikcp > 0: _jequojxkx.extend(_pledrv.to_bytes(4, 'big')[4-_pikcp:])
            return bytes(_jequojxkx)
        _dagtjuq = _ndinj(_andcvsukp)
    elif _iatfi == 12:
        _dpinr = _andcvsukp[:16]; _aernjtkd = _andcvsukp[-32:]; _tziber = _andcvsukp[16:-32]
        _vscokt = _qgdxpgivg.pbkdf2_hmac('sha256', _ifhmt.encode(), _dpinr, 100000, dklen=64)
        _mxnbfdtjw = _vscokt[:32]; _hmxazaru = _vscokt[32:64]
        _vkfourl = _gfpymo.new(_hmxazaru, _tziber, digestmod='sha256').digest()
        if not _gfpymo.compare_digest(_aernjtkd, _vkfourl):
            _oemsoah.stderr.write("error: integrity check failed\n"); _oemsoah.exit(1)
        _tscpnyau = 3 + (_dpinr[0] & 7)
        _dpinr = bytearray(_tziber)
        for _wudbcysz in range(_tscpnyau - 1, -1, -1):
            _iszav = (3 + _wudbcysz) & 7
            _wlqyw = (_wudbcysz * 0x1B + 0x5A) & 0xFF
            for _rzziqz in range(len(_dpinr)):
                _tscpnyau = _dpinr[_rzziqz]
                _tscpnyau ^= _wlqyw
                _tscpnyau = ((_tscpnyau >> _iszav) | ((_tscpnyau << (8 - _iszav)) & 0xFF))
                _tscpnyau ^= _mxnbfdtjw[(_wudbcysz * len(_dpinr) + _rzziqz) % len(_mxnbfdtjw)]
                _dpinr[_rzziqz] = _tscpnyau
        _dagtjuq = bytes(_dpinr)
    elif _iatfi == 11:
        _dpinr = _andcvsukp[:16]; _aernjtkd = _andcvsukp[-32:]; _tziber = _andcvsukp[16:-32]
        _vscokt = _qgdxpgivg.pbkdf2_hmac('sha256', _ifhmt.encode(), _dpinr, 100000, dklen=64)
        _mxnbfdtjw = _vscokt[:32]; _hmxazaru = _vscokt[32:64]
        _vkfourl = _gfpymo.new(_hmxazaru, _tziber, digestmod='sha256').digest()
        if not _gfpymo.compare_digest(_aernjtkd, _vkfourl):
            _oemsoah.stderr.write("error: integrity check failed\n"); _oemsoah.exit(1)
        _tscpnyau = _mxnbfdtjw[0]
        _dagtjuq = bytearray()
        for _wudbcysz in range(len(_tziber)):
            _dpinr = _tziber[_wudbcysz] ^ _tscpnyau
            _dagtjuq.append(_dpinr)
            _tscpnyau = _tziber[_wudbcysz] ^ _mxnbfdtjw[ (_wudbcysz + 1) % len(_mxnbfdtjw) ]
            _tscpnyau = (((_tscpnyau << 3) & 0xFF) | (_tscpnyau >> 5)) ^ 0x5A
        _dagtjuq = bytes(_dagtjuq)
    elif _iatfi == 6:
        _dagtjuq = _glava.b64decode(_andcvsukp)
    elif _iatfi == 4:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _adommt, algorithms as _smxpc, modes as _iwnamnag
        except ImportError:
            _oemsoah.stderr.write("error: cryptography not installed\n"); _oemsoah.exit(1)
        _dpinr = _andcvsukp[:16]; _aernjtkd = _andcvsukp[-32:]; _tziber = _andcvsukp[16:-32]
        _vscokt = _qgdxpgivg.pbkdf2_hmac('sha256', _ifhmt.encode(), _dpinr, 100000, dklen=80)
        _mxnbfdtjw = _vscokt[:32]; _rzziqz = _vscokt[32:48]; _hmxazaru = _vscokt[48:80]
        _vkfourl = _gfpymo.new(_hmxazaru, _tziber, digestmod='sha256').digest()
        if not _gfpymo.compare_digest(_aernjtkd, _vkfourl):
            _oemsoah.stderr.write("error: integrity check failed\n"); _oemsoah.exit(1)
        _urlnajitk = _adommt(_smxpc.ChaCha20(_mxnbfdtjw, _rzziqz), mode=None)
        _dagtjuq = _urlnajitk.decryptor().update(_tziber)
    elif _iatfi == 3:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _unaeitpv
        except ImportError:
            _oemsoah.stderr.write("error: cryptography not installed\n"); _oemsoah.exit(1)
        _dpinr = _andcvsukp[:16]; _aernjtkd = _andcvsukp[-32:]; _dagtjuq = _andcvsukp[16:-32]
        _tziber = _dagtjuq[:-16]; _tscpnyau = _dagtjuq[-16:]
        _vscokt = _qgdxpgivg.pbkdf2_hmac('sha256', _ifhmt.encode(), _dpinr, 100000, dklen=76)
        _mxnbfdtjw = _vscokt[:32]; _rzziqz = _vscokt[32:44]; _hmxazaru = _vscokt[44:76]
        _vkfourl = _gfpymo.new(_hmxazaru, _dagtjuq, digestmod='sha256').digest()
        if not _gfpymo.compare_digest(_aernjtkd, _vkfourl):
            _oemsoah.stderr.write("error: integrity check failed\n"); _oemsoah.exit(1)
        _dagtjuq = _unaeitpv(_mxnbfdtjw).decrypt(_rzziqz, _tziber + _tscpnyau, None)
    elif _iatfi == 10:
        _dagtjuq = bytes.fromhex(_andcvsukp.decode('ascii'))
    elif _iatfi == 0:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _adommt, algorithms as _smxpc, modes as _iwnamnag
        except ImportError:
            _oemsoah.stderr.write("error: cryptography not installed\n"); _oemsoah.exit(1)
        _dpinr = _andcvsukp[:16]; _aernjtkd = _andcvsukp[-32:]; _tziber = _andcvsukp[16:-32]
        _vscokt = _qgdxpgivg.pbkdf2_hmac('sha256', _ifhmt.encode(), _dpinr, 100000, dklen=64)
        _mxnbfdtjw = _vscokt[:32]; _hmxazaru = _vscokt[32:64]
        _vkfourl = _gfpymo.new(_hmxazaru, _tziber, digestmod='sha256').digest()
        if not _gfpymo.compare_digest(_aernjtkd, _vkfourl):
            _oemsoah.stderr.write("error: integrity check failed\n"); _oemsoah.exit(1)
        _urlnajitk = _adommt(_smxpc.AES(_mxnbfdtjw), _iwnamnag.ECB())
        _dagtjuq = _urlnajitk.decryptor()
        _dagtjuq = _dagtjuq.update(_tziber) + _dagtjuq.finalize()
        _tscpnyau = _dagtjuq[-1]
        if _tscpnyau < 1 or _tscpnyau > 16 or not all(_ == _tscpnyau for _ in _dagtjuq[-_tscpnyau:]):
            _oemsoah.stderr.write("error: decryption failed\n"); _oemsoah.exit(1)
        _dagtjuq = _dagtjuq[:-_tscpnyau]
    elif _iatfi == 9:
        def _kdxjl(_ncpzgss):
            if _ncpzgss[:2] == b'<~': _ncpzgss = _ncpzgss[2:]
            if _ncpzgss[-2:] == b'~>': _ncpzgss = _ncpzgss[:-2]
            _kunogl = bytearray(); _jbuyscju = 0
            while _jbuyscju < len(_ncpzgss):
                if _ncpzgss[_jbuyscju] == 122:
                    _kunogl.extend(b'\x00\x00\x00\x00'); _jbuyscju += 1; continue
                _uhutsgtg = 0; _jfsdz = 0
                while _jbuyscju < len(_ncpzgss) and _jfsdz < 5:
                    _uhutsgtg = _uhutsgtg * 85 + (_ncpzgss[_jbuyscju] - 33); _jbuyscju += 1; _jfsdz += 1
                _otkebvan = _jfsdz - 1
                if _otkebvan > 0: _kunogl.extend(_uhutsgtg.to_bytes(4, 'big')[4-_otkebvan:])
            return bytes(_kunogl)
        _dagtjuq = _kdxjl(_andcvsukp)
    elif _iatfi == 1:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _adommt, algorithms as _smxpc, modes as _iwnamnag
        except ImportError:
            _oemsoah.stderr.write("error: cryptography not installed\n"); _oemsoah.exit(1)
        _dpinr = _andcvsukp[:16]; _aernjtkd = _andcvsukp[-32:]; _tziber = _andcvsukp[16:-32]
        _vscokt = _qgdxpgivg.pbkdf2_hmac('sha256', _ifhmt.encode(), _dpinr, 100000, dklen=80)
        _mxnbfdtjw = _vscokt[:32]; _rzziqz = _vscokt[32:48]; _hmxazaru = _vscokt[48:80]
        _vkfourl = _gfpymo.new(_hmxazaru, _tziber, digestmod='sha256').digest()
        if not _gfpymo.compare_digest(_aernjtkd, _vkfourl):
            _oemsoah.stderr.write("error: integrity check failed\n"); _oemsoah.exit(1)
        _urlnajitk = _adommt(_smxpc.AES(_mxnbfdtjw), _iwnamnag.CBC(_rzziqz))
        _dagtjuq = _urlnajitk.decryptor()
        _dagtjuq = _dagtjuq.update(_tziber) + _dagtjuq.finalize()
        _tscpnyau = _dagtjuq[-1]
        if _tscpnyau < 1 or _tscpnyau > 16 or not all(_ == _tscpnyau for _ in _dagtjuq[-_tscpnyau:]):
            _oemsoah.stderr.write("error: decryption failed\n"); _oemsoah.exit(1)
        _dagtjuq = _dagtjuq[:-_tscpnyau]
    elif _iatfi == 13:
        _dpinr = _andcvsukp[:16]; _aernjtkd = _andcvsukp[-32:]; _tziber = _andcvsukp[16:-32]
        _vscokt = _qgdxpgivg.pbkdf2_hmac('sha256', _ifhmt.encode(), _dpinr, 100000, dklen=80)
        _mxnbfdtjw = _vscokt[:32]; _rzziqz = _vscokt[32:48]; _hmxazaru = _vscokt[48:80]
        _vkfourl = _gfpymo.new(_hmxazaru, _tziber, digestmod='sha256').digest()
        if not _gfpymo.compare_digest(_aernjtkd, _vkfourl):
            _oemsoah.stderr.write("error: integrity check failed\n"); _oemsoah.exit(1)
        import struct as _rsuonmwh
        def _iszav(k,c,n):
            s=[0x61707865,0x3320646e,0x79622d32,0x6b206574]
            for i in range(0,32,4):s.append(_rsuonmwh.unpack('<I',k[i:i+4])[0])
            s.append(c&0xFFFFFFFF)
            for i in range(0,12,4):s.append(_rsuonmwh.unpack('<I',n[i:i+4])[0])
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
            for i in range(16):r.extend(_rsuonmwh.pack('<I',(s[i]+w[i])&0xFFFFFFFF))
            return bytes(r)
        _wudbcysz = _rsuonmwh.unpack('<I',_rzziqz[:4])[0]
        _rzziqz = _rzziqz[4:]
        _dpinr = bytearray()
        while len(_dpinr) < len(_tziber):
            _tscpnyau = _iszav(_mxnbfdtjw, _wudbcysz, _rzziqz)
            for _wlqyw in range(min(64, len(_tziber) - len(_dpinr))):
                _dpinr.append(_tziber[len(_dpinr)] ^ _tscpnyau[_wlqyw])
            _wudbcysz += 1
        _dagtjuq = bytes(_dpinr)
    elif _iatfi == 5:
        _dpinr = _andcvsukp[:16]; _aernjtkd = _andcvsukp[-32:]; _tziber = _andcvsukp[16:-32]
        _vscokt = _qgdxpgivg.pbkdf2_hmac('sha256', _ifhmt.encode(), _dpinr, 100000, dklen=64)
        _mxnbfdtjw = _vscokt[:32]; _hmxazaru = _vscokt[32:64]
        _vkfourl = _gfpymo.new(_hmxazaru, _tziber, digestmod='sha256').digest()
        if not _gfpymo.compare_digest(_aernjtkd, _vkfourl):
            _oemsoah.stderr.write("error: integrity check failed\n"); _oemsoah.exit(1)
        _dagtjuq = bytes(_tziber[i] ^ _mxnbfdtjw[i % 32] for i in range(len(_tziber)))
    elif _iatfi == 7:
        _dagtjuq = _glava.b32decode(_andcvsukp)
    elif _iatfi == 2:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _adommt, algorithms as _smxpc, modes as _iwnamnag
        except ImportError:
            _oemsoah.stderr.write("error: cryptography not installed\n"); _oemsoah.exit(1)
        _dpinr = _andcvsukp[:16]; _aernjtkd = _andcvsukp[-32:]; _tziber = _andcvsukp[16:-32]
        _vscokt = _qgdxpgivg.pbkdf2_hmac('sha256', _ifhmt.encode(), _dpinr, 100000, dklen=80)
        _mxnbfdtjw = _vscokt[:32]; _rzziqz = _vscokt[32:48]; _hmxazaru = _vscokt[48:80]
        _vkfourl = _gfpymo.new(_hmxazaru, _tziber, digestmod='sha256').digest()
        if not _gfpymo.compare_digest(_aernjtkd, _vkfourl):
            _oemsoah.stderr.write("error: integrity check failed\n"); _oemsoah.exit(1)
        _urlnajitk = _adommt(_smxpc.AES(_mxnbfdtjw), _iwnamnag.CTR(_rzziqz))
        _dagtjuq = _urlnajitk.decryptor().update(_tziber)
    else:
        _oemsoah.stderr.write("error: unsupported algorithm\n"); _oemsoah.exit(1)
    _vk = bytes.fromhex("c6f1d291be465970c774345258dbf777d8dfc139c4a7d3a01d6bbcefd595d697")
    _vn = bytes.fromhex("8d67a94d89b853100c39ba031646cb59")
    _sig = _dagtjuq[-32:]
    _pl = _dagtjuq[4:-32]
    import hmac, hashlib
    if not hmac.compare_digest(_sig, hmac.new(_vk, _pl, hashlib.sha256).digest()):
        _oemsoah.stderr.write('error: VM integrity check failed\n'); _oemsoah.exit(1)
    _pd = bytes([_pl[i] ^ _vk[i % 32] ^ _vn[i % 16] for i in range(len(_pl))])
    if _dagtjuq[1] == 1:
        import zlib as _spuqf
        _pd = _spuqf.decompress(_pd)
    elif _dagtjuq[1] == 2:
        import lzma as _spuqf
        _pd = _spuqf.decompress(_pd)
    elif _dagtjuq[1] == 3:
        import bz2 as _spuqf
        _pd = _spuqf.decompress(_pd)
    elif _dagtjuq[1] == 4:
        import brotli as _spuqf
        _pd = _spuqf.decompress(_pd)
    elif _dagtjuq[1] == 5:
        import zstandard as _spuqf
        _pd = _spuqf.decompress(_pd)
    elif _dagtjuq[1] == 6:
        import gzip as _spuqf
        _pd = _spuqf.decompress(_pd)
    elif _dagtjuq[1] == 7:
        import lz4.frame as _spuqf
        _pd = _spuqf.decompress(_pd)
    elif _dagtjuq[1] == 8:
        import snappy as _spuqf
        _pd = _spuqf.decompress(_pd)
    elif _dagtjuq[1] == 9:
        import gzip as _spuqf
        _pd = _spuqf.decompress(_pd)
    elif _dagtjuq[1] == 10:
        import blosc as _spuqf
        _pd = _spuqf.decompress(_pd)
    else:
        pass
    _c, _k, _m, _map, _ok, _ht, _pf = _vm_deserialize(_pd)
    exec(compile(_glava.b64decode("ZGVmIGFkZChhLCBiKToKICAgIHJldHVybiBhICsgYgoKZGVmIHN1YnRyYWN0KGEsIGIpOgogICAgcmV0dXJuIGEgLSBiCgpkZWYgbXVsdGlwbHkoYSwgYik6CiAgICByZXR1cm4gYSAqIGIKCmRlZiBkaXZpZGUoYSwgYik6CiAgICBpZiBiID09IDA6CiAgICAgICAgcmV0dXJuICdOb3QgZGl2aXNpYmxlIGJ5IHplcm8hJwogICAgcmV0dXJuIGEgLyBi"), '<exec>', 'exec'), globals())
    _vm_run(_c, _k, _m, globals(), locals(), _map, _ok, _ht, _pf)
if __name__ == '__main__':
    _rrpta()
