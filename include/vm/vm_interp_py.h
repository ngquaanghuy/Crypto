#ifndef CRYPTO_VM_INTERP_PY_H
#define CRYPTO_VM_INTERP_PY_H

// Python VM interpreter — embedded in generated stub
static const char VM_INTERP_SCRIPT[] = R"vm_interp(
# Helper: return (mapped_rs2, unmapped_rs2) for ops that use rs2 as count
def _vm_rs2(_dec, _rm, _op):
    _raw = _dec[3]
    _mapped = _rm[_raw & 0x3F] if (_raw & 0x3F) < 64 else 0
    # Ops using rs2 as count (not register): BUILD_TUPLE(43), BUILD_LIST(44), BUILD_STRING(63)
    # Also BUILD_STRING - the Python compiler uses rs2 for count. Others use _imm low bits.
    _count_ops = frozenset((43, 44, 63, 164, 165, 270, 277, 284, 285))
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
        _count_ops = frozenset((43, 44, 63, 164, 165, 270, 277, 284, 285))
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
        _count_ops = frozenset((43, 44, 63, 164, 165, 270, 277, 284, 285))
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
        _count_ops = frozenset((43, 44, 63, 164, 165, 270, 277, 284, 285))
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
        _count_ops = frozenset((43, 44, 63, 164, 165, 270, 277, 284, 285))
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
    import sys, random, types
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
    _exc_stack = []
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
        elif _op == 54:
            _r_set(_rd, types.FunctionType(_r_get(_rs1), _globals))
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

        # ═══════════════════════════════════════════════════════
        # DATA STRUCTURES (161-179)
        # ═══════════════════════════════════════════════════════

        # BINARY_SLICE (161): obj[start:stop] → pop obj, start, stop; push slice
        elif _op == 161:
            _obj = _r_get(_rs1)
            _start = _r_get(_rs2)
            _stop = _r_get(_rd)
            try:
                _r_set(_rd, _obj[_start:_stop])
            except Exception as _e:
                raise _e

        # DELETE_SUBSCR (162): del obj[key]
        elif _op == 162:
            _obj = _r_get(_rs1)
            _key = _r_get(_rs2)
            try:
                del _obj[_key]
            except Exception as _e:
                raise _e

        # STORE_SLICE (163): obj[start:stop] = val
        elif _op == 163:
            _val = _r_get(_rd)
            _obj = _r_get(_rs1)
            _start = _r_get(_rs2)
            try:
                _obj[_start:_imm] = _val
            except Exception as _e:
                raise _e

        # BUILD_MAP (164): Create dict from consecutive key-value pairs (count = _rs2)
        elif _op == 164:
            _cnt = _rs2 & 0xFFFF
            _d = {}
            for _i in range(_cnt):
                _key_off = _rr(_rd, _i * 2)
                _val_off = _rr(_rd, _i * 2 + 1)
                _d[_r_get(_key_off)] = _r_get(_val_off)
            _r_set(_rd, _d)

        # BUILD_SET (165): Create set from items (count = _rs2)
        elif _op == 165:
            _cnt = _rs2 & 0xFFFF
            _s = set()
            for _i in range(_cnt):
                _item_off = _rr(_rd, _i + 1)
                _s.add(_r_get(_item_off))
            _r_set(_rd, _s)

        # BUILD_SLICE (166): slice(start, stop[, step])
        elif _op == 166:
            _start = _r_get(_rd)
            _stop = _r_get(_rs1)
            if _imm >= 3:
                _step = _r_get(_rs2)
            else:
                _step = None
            from builtins import slice as _slice
            _r_set(_rd, _slice(_start, _stop, _step))

        # COPY (167): Shallow copy rd = copy(rs1)
        elif _op == 167:
            _v = _r_get(_rs1)
            try:
                _r_set(_rd, _v.copy() if hasattr(_v, 'copy') else _v[:] if hasattr(_v, '__getitem__') else _v)
            except Exception:
                _r_set(_rd, _v)

        # DICT_MERGE (168): dict |= other
        elif _op == 168:
            _d = _r_get(_rd)
            _o = _r_get(_rs1)
            if isinstance(_d, dict) and isinstance(_o, dict):
                _d.update(_o)
            _r_set(_rd, _d)

        # DICT_UPDATE (169): dict.update(other)
        elif _op == 169:
            _d = _r_get(_rd)
            _o = _r_get(_rs1)
            if isinstance(_d, dict):
                _d.update(_o)

        # MAP_ADD (170): dict[key] = value (dict comprehension)
        elif _op == 170:
            _d = _r_get(_rd)
            _k = _r_get(_rs1)
            _v = _r_get(_rs2)
            if isinstance(_d, dict):
                _d[_k] = _v

        # SET_ADD (171): set.add(item)
        elif _op == 171:
            _s = _r_get(_rd)
            _item = _r_get(_rs1)
            if isinstance(_s, set):
                _s.add(_item)

        # SET_UPDATE (172): set.update(other)
        elif _op == 172:
            _s = _r_get(_rd)
            _other = _r_get(_rs1)
            if isinstance(_s, set):
                _s.update(_other)

        # ═══════════════════════════════════════════════════════
        # ITERATOR / GENERATOR / ASYNC (180-199)
        # ═══════════════════════════════════════════════════════

        # END_SEND (180): End of generator send pair
        elif _op == 180:
            pass

        # GET_AITER (181): Get async iterator
        elif _op == 181:
            _obj = _r_get(_rs1)
            _r_set(_rd, _obj.__aiter__())

        # GET_ANEXT (182): Get next async item
        elif _op == 182:
            _aiter = _r_get(_rs1)
            _r_set(_rd, _aiter.__anext__())

        # GET_YIELD_FROM_ITER (183): Get iterator for yield from
        elif _op == 183:
            _obj = _r_get(_rs1)
            try:
                _iter = _obj.__iter__()
            except AttributeError:
                _iter = iter(_obj)
            _r_set(_rd, _iter)

        # LOAD_BUILD_CLASS (184): Load __build_class__ builtin
        elif _op == 184:
            _r_set(_rd, _b['__build_class__'])

        # RETURN_GENERATOR (185): Create generator from frame
        elif _op == 185:
            _fn = _r_get(_rs1)
            if callable(_fn):
                _gen = _fn()
                if hasattr(_gen, '__next__'):
                    _r_set(_rd, _gen)
                else:
                    _r_set(_rd, _gen)
            else:
                _r_set(_rd, None)

        # COPY_FREE_VARS (186): Copy closure variables (imm = count)
        elif _op == 186:
            pass

        # DELETE_DEREF (187): del closure variable
        elif _op == 187:
            _nm = _names[_imm] if _imm < len(_names) else None
            if _nm and _nm in _locals:
                del _locals[_nm]

        # END_ASYNC_FOR (188): Cleanup after async for
        elif _op == 188:
            pass

        # GET_AWAITABLE (189): Get awaitable from object
        elif _op == 189:
            _obj = _r_get(_rs1)
            if hasattr(_obj, '__await__'):
                _r_set(_rd, _obj.__await__())
            else:
                _r_set(_rd, _obj)

        # LOAD_DEREF (190): Load from closure (imm = name index)
        elif _op == 190:
            _nm = _names[_imm] if _imm < len(_names) else None
            _v = _locals.get(_nm) if _nm else None
            if _v is None:
                _v = _globals.get(_nm) if _nm else None
            _r_set(_rd, _v)

        # MAKE_CELL (191): Create closure cell
        elif _op == 191:
            _v = _r_get(_rs1)
            _cell_type = type((lambda: 1).__closure__[0]) if (lambda: 1).__closure__ else type(None)
            try:
                _r_set(_rd, (lambda _x: lambda: _x)(_v).__closure__[0])
            except Exception:
                _r_set(_rd, _v)

        # SEND (192): Generator send — send value, get next result
        # rd = result, rs1 = generator, rs2 = value to send, imm = jump target on StopIteration
        elif _op == 192:
            _gen = _r_get(_rs1)
            _val = _r_get(_rs2)
            try:
                _result = _gen.send(_val)
                _r_set(_rd, _result)
            except StopIteration:
                _ip = _imm
                continue

        # STORE_DEREF (193): Store to closure (rd=val_reg, imm=name_index)
        elif _op == 193:
            _nm = _names[_imm] if _imm < len(_names) else None
            _v = _r_get(_rd)
            if _nm:
                _locals[_nm] = _v

        # YIELD_VALUE (194): yield expression — value is in rd, result is next sent value
        elif _op == 194:
            _val = _r_get(_rs1)
            _r_set(_rd, _val)
            _ip += _ilen
            continue

        # LOAD_CLOSURE (195): Load closure for cells
        elif _op == 195:
            _nm = _names[_imm] if _imm < len(_names) else None
            _v = _locals.get(_nm) if _nm else _globals.get(_nm) if _nm else None
            _r_set(_rd, _v)

        # ═══════════════════════════════════════════════════════
        # EXCEPTION HANDLING (200-219)
        # ═══════════════════════════════════════════════════════

        # CHECK_EG_MATCH (200): Check exception group matching
        elif _op == 200:
            _exc = _r_get(_rs1)
            _match_types = _r_get(_rs2)
            try:
                _r_set(_rd, isinstance(_exc, _match_types) if isinstance(_match_types, type) else False)
            except Exception:
                _r_set(_rd, False)

        # CHECK_EXC_MATCH (201): Check exception matching
        elif _op == 201:
            _exc_val = _r_get(_rs1)
            _handler_type = _r_get(_rd)
            _matched = False
            if isinstance(_handler_type, type) and isinstance(_exc_val, BaseException):
                _matched = isinstance(_exc_val, _handler_type)
            elif isinstance(_handler_type, tuple):
                _matched = isinstance(_exc_val, _handler_type)
            _r_set(_rd, _matched)

        # CLEANUP_THROW (202): Cleanup during throw
        elif _op == 202:
            pass

        # POP_EXCEPT (203): Pop exception info from exc stack
        elif _op == 203:
            if _exc_stack:
                _exc_stack.pop()

        # PUSH_EXC_INFO (204): Push exception info
        elif _op == 204:
            _exc_val = _r_get(_rd)
            _exc_stack.append(_exc_val)

        # WITH_EXCEPT_START (205): Call context manager __exit__
        elif _op == 205:
            _ctx = _r_get(_rs1)
            _exc = _r_get(_rs2)
            _typ, _val, _tb = sys.exc_info()
            try:
                _result = _ctx.__exit__(_typ, _val, _tb)
                _r_set(_rd, _result)
            except Exception:
                _r_set(_rd, False)

        # RERAISE (206): Reraise exception
        elif _op == 206:
            _exc = _r_get(_rd)
            if _exc is not None and isinstance(_exc, BaseException):
                raise _exc
            raise

        # POP_BLOCK (207): Pop block from handler stack
        elif _op == 207:
            if _handler_stack:
                _handler_stack.pop()

        # SETUP_CLEANUP (208): Setup cleanup handler (imm = jump target)
        elif _op == 208:
            _handler_stack.append({'s': _ip, 'e': _n, 'c': _imm, 't': Exception})

        # SETUP_FINALLY (209): Setup finally block (imm = jump target)
        elif _op == 209:
            _handler_stack.append({'s': _ip, 'e': _n, 'c': _imm, 't': BaseException})

        # SETUP_WITH (210): Setup context manager (imm = exit handler target)
        elif _op == 210:
            _ctx = _r_get(_rs1)
            try:
                _enter_result = _ctx.__enter__()
                _handler_stack.append({'s': _ip, 'e': _n, 'c': _imm, 't': BaseException})
                _r_set(_rd, _enter_result)
            except Exception as _e:
                raise _e

        # ═══════════════════════════════════════════════════════
        # PATTERN MATCHING (220-229)
        # ═══════════════════════════════════════════════════════

        # MATCH_KEYS (220): Match dict keys pattern
        elif _op == 220:
            _subj = _r_get(_rs1)
            _keys = _r_get(_rs2)
            if isinstance(_subj, dict) and hasattr(_keys, '__iter__'):
                _matched = all(_k in _subj for _k in _keys)
                if _matched:
                    _vals = tuple(_subj[_k] for _k in _keys)
                    _r_set(_rd, _vals)
                else:
                    _r_set(_rd, None)
            else:
                _r_set(_rd, None)

        # MATCH_MAPPING (221): Check if subject is a mapping
        elif _op == 221:
            _subj = _r_get(_rs1)
            _r_set(_rd, isinstance(_subj, dict) or hasattr(_subj, 'keys'))

        # MATCH_SEQUENCE (222): Check if subject is a sequence of given length (imm = min len)
        elif _op == 222:
            _subj = _r_get(_rs1)
            _min_len = _imm & 0xFFFF
            _r_set(_rd, isinstance(_subj, (list, tuple)) and len(_subj) >= _min_len)

        # MATCH_CLASS (223): Match class pattern
        elif _op == 223:
            _subj = _r_get(_rs1)
            _cls_name = _names[_imm] if _imm < len(_names) else None
            _nargs = _rs2 & 0xFF
            _matched = False
            if _cls_name is not None:
                _cls = _globals.get(_cls_name) or _b.get(_cls_name)
                if _cls is not None and isinstance(_subj, _cls):
                    _matched = True
            _r_set(_rd, _matched)

        # ═══════════════════════════════════════════════════════
        # CONTROL FLOW — PYTHON 3.14+ (230-239)
        # ═══════════════════════════════════════════════════════

        # POP_ITER (230): Pop iterator after loop ends
        elif _op == 230:
            pass

        # JUMP_BACKWARD_NO_INTERRUPT (231): Uninterruptible backward jump
        elif _op == 231:
            if _vl_flag:
                _ip = _imm
            else:
                _ip = _imm * 8
            continue

        # JUMP (232): Unified jump instruction
        elif _op == 232:
            if _vl_flag:
                _ip = _imm
            else:
                _ip = _imm * 8
            continue

        # JUMP_IF_FALSE (233): Jump if false
        elif _op == 233:
            if not _r_get(_rd):
                if _vl_flag:
                    _ip = _imm
                else:
                    _ip = _imm * 8
            else:
                _ip += _ilen
            continue

        # JUMP_IF_TRUE (234): Jump if true
        elif _op == 234:
            if _r_get(_rd):
                if _vl_flag:
                    _ip = _imm
                else:
                    _ip = _imm * 8
            else:
                _ip += _ilen
            continue

        # JUMP_NO_INTERRUPT (235): Jump without interrupt check
        elif _op == 235:
            if _vl_flag:
                _ip = _imm
            else:
                _ip = _imm * 8
            continue

        # ═══════════════════════════════════════════════════════
        # ATTRIBUTE OPERATIONS (240-244)
        # ═══════════════════════════════════════════════════════

        # DELETE_ATTR (240): del obj.attr
        elif _op == 240:
            _obj = _r_get(_rd)
            _attr = _names[_imm] if _imm < len(_names) else None
            if _obj is not None and _attr is not None:
                try:
                    delattr(_obj, _attr)
                except AttributeError as _e:
                    raise _e

        # LOAD_SUPER_ATTR (241): super().attr
        elif _op == 241:
            _attr = _names[_imm] if _imm < len(_names) else None
            try:
                _r_set(_rd, super(_r_get(_rs1), _r_get(_rs2)).__getattribute__(_attr) if _attr else None)
            except Exception:
                _r_set(_rd, getattr(_r_get(_rs2), _attr) if _attr else None)

        # STORE_ATTR (242): obj.attr = value
        elif _op == 242:
            _val = _r_get(_rd)
            _obj = _r_get(_rs1)
            _attr = _names[_imm] if _imm < len(_names) else None
            if _obj is not None and _attr is not None:
                setattr(_obj, _attr, _val)

        # ═══════════════════════════════════════════════════════
        # CALL VARIANTS (245-249)
        # ═══════════════════════════════════════════════════════

        # CALL_FUNCTION_EX (245): f(*args, **kwargs)
        elif _op == 245:
            _fn = _r_get(_rs1)
            _args = _r_get(_rs2) if _rs2 < 64 else ()
            _flags = _imm & 0xFF
            _has_kwargs = _flags & 1
            if isinstance(_args, tuple) and len(_args) > 0 and isinstance(_args[-1], dict):
                _pos_args = _args[:-1]
                _kw_args = _args[-1]
            elif isinstance(_args, dict):
                _pos_args = ()
                _kw_args = _args
            else:
                _pos_args = _args if isinstance(_args, (tuple, list)) else ()
                _kw_args = {}
            _fn_args = _pos_args
            if _has_kwargs:
                _kw_reg = _rr(_rs1, 1)
                _kw = _r_get(_kw_reg)
                if isinstance(_kw, dict):
                    _fn_kwargs = _kw
                else:
                    _fn_kwargs = {}
            else:
                _fn_kwargs = {}
            try:
                _r_set(_rd, _fn(*_fn_args, **_fn_kwargs))
            except Exception as _e:
                raise _e

        # CALL_INTRINSIC_1 (246): Intrinsic call with 1 argument (imm = intrinsic index)
        elif _op == 246:
            _v = _r_get(_rs1)
            _idx = _imm & 0xFF
            if _idx == 0:       # INTRINSIC_1_INVALID
                _r_set(_rd, None)
            elif _idx == 1:     # INTRINSIC_1_IS_NONE
                _r_set(_rd, _v is None)
            elif _idx == 2:     # INTRINSIC_1_IS_TRUE
                _r_set(_rd, bool(_v) if _v is not None else False)
            elif _idx == 3:     # INTRINSIC_1_LEN
                _r_set(_rd, len(_v))
            elif _idx == 4:     # INTRINSIC_1_STR
                _r_set(_rd, str(_v))
            elif _idx == 5:     # INTRINSIC_1_REPR
                _r_set(_rd, repr(_v))
            elif _idx == 6:     # INTRINSIC_1_ASCII
                _r_set(_rd, ascii(_v))
            elif _idx == 7:     # INTRINSIC_1_BOOL
                _r_set(_rd, bool(_v))
            elif _idx == 8:     # INTRINSIC_1_ORDER
                _r_set(_rd, _v.__order__() if hasattr(_v, '__order__') else _v)
            else:
                _r_set(_rd, _v)

        # CALL_INTRINSIC_2 (247): Intrinsic call with 2 arguments
        elif _op == 247:
            _v1 = _r_get(_rs1)
            _v2 = _r_get(_rs2)
            _idx = _imm & 0xFF
            if _idx == 0:       # INTRINSIC_2_INVALID
                _r_set(_rd, None)
            elif _idx == 1:     # INTRINSIC_2_IS_EQUAL
                _r_set(_rd, _v1 == _v2)
            elif _idx == 2:     # INTRINSIC_2_IS_NOT_EQUAL
                _r_set(_rd, _v1 != _v2)
            elif _idx == 3:     # INTRINSIC_2_IS_INSTANCE
                _r_set(_rd, isinstance(_v1, _v2) if isinstance(_v2, type) else False)
            elif _idx == 4:     # INTRINSIC_2_IS_SUBCLASS
                _r_set(_rd, issubclass(_v1, _v2) if isinstance(_v1, type) and isinstance(_v2, type) else False)
            elif _idx == 5:     # INTRINSIC_2_CONTAINS
                try:
                    _r_set(_rd, _v2 in _v1)
                except Exception:
                    _r_set(_rd, False)
            elif _idx == 6:     # INTRINSIC_2_NOT_CONTAINS
                try:
                    _r_set(_rd, _v2 not in _v1)
                except Exception:
                    _r_set(_rd, True)
            elif _idx == 7:     # INTRINSIC_2_POW
                _r_set(_rd, _v1 ** _v2)
            elif _idx == 8:     # INTRINSIC_2_DIVMOD
                _r_set(_rd, divmod(_v1, _v2))
            else:
                _r_set(_rd, None)

        # CALL_KW (248): Call with keyword args (imm = arg count)
        elif _op == 248:
            _fn = _r_get(_rs1)
            _names_reg = _rs2
            _argc = _imm & 0xFFFF
            _names_tuple = _r_get(_names_reg) if _names_reg < 64 else None
            if isinstance(_names_tuple, tuple) and len(_names_tuple) == _argc:
                _kw_names = _names_tuple
            else:
                _kw_names = (None,) * _argc
            _pos_args = []
            _kw_args = {}
            for _i in range(_argc):
                _aval = _r_get(_rr(_rs1, 1 + _i))
                if _i < len(_kw_names) and _kw_names[_i] is not None:
                    _kw_args[_kw_names[_i]] = _aval
                else:
                    _pos_args.append(_aval)
            try:
                _r_set(_rd, _fn(*_pos_args, **_kw_args))
            except Exception as _e:
                raise _e

        # ═══════════════════════════════════════════════════════
        # NAME OPERATIONS — DELETE (250-255)
        # ═══════════════════════════════════════════════════════

        # DELETE_FAST (250): del local variable
        elif _op == 250:
            _nm = _names[_imm] if _imm < len(_names) else None
            if _nm and _nm in _locals:
                del _locals[_nm]

        # DELETE_GLOBAL (251): del global variable
        elif _op == 251:
            _nm = _names[_imm] if _imm < len(_names) else None
            if _nm and _nm in _globals:
                del _globals[_nm]

        # DELETE_NAME (252): del name
        elif _op == 252:
            _nm = _names[_imm] if _imm < len(_names) else None
            if _nm:
                if _nm in _locals:
                    del _locals[_nm]
                elif _nm in _globals:
                    del _globals[_nm]

        # LOAD_FROM_DICT_OR_DEREF (253): Load from dict or closure
        elif _op == 253:
            _d = _r_get(_rs1)
            _nm = _names[_imm] if _imm < len(_names) else None
            _v = _locals.get(_nm) if _nm else None
            if _v is None and isinstance(_d, dict) and _nm:
                _v = _d.get(_nm)
            if _v is None and _nm:
                _v = _globals.get(_nm) or _b.get(_nm)
            _r_set(_rd, _v)

        # LOAD_FROM_DICT_OR_GLOBALS (254): Load from dict or globals
        elif _op == 254:
            _d = _r_get(_rs1)
            _nm = _names[_imm] if _imm < len(_names) else None
            _v = _globals.get(_nm) if _nm else None
            if _v is None and isinstance(_d, dict) and _nm:
                _v = _d.get(_nm)
            if _v is None and _nm:
                _v = _b.get(_nm)
            _r_set(_rd, _v)

        # ═══════════════════════════════════════════════════════
        # UNARY / BITWISE (256-259)
        # ═══════════════════════════════════════════════════════

        # UNARY_INVERT (7): ~x
        elif _op == 7:
            _v = _r_get(_rs1)
            try:
                _r_set(_rd, ~_v)
            except Exception:
                _r_set(_rd, _v)

        # UNARY_NOT (8): not x
        elif _op == 8:
            _v = _r_get(_rs1)
            _r_set(_rd, not _v)

        # ═══════════════════════════════════════════════════════
        # TYPE SYSTEM (260-269)
        # ═══════════════════════════════════════════════════════

        # SETUP_ANNOTATIONS (9): Setup __annotations__ in locals
        elif _op == 9:
            if '__annotations__' not in _locals:
                _locals['__annotations__'] = {}

        # CONVERT_VALUE (110): Convert value to type (imm = conversion code)
        elif _op == 110:
            _v = _r_get(_rs1)
            _conv = _imm & 0xFF
            if _conv == 0:      # CONVERT_VALUE_TO_STR
                _r_set(_rd, str(_v))
            elif _conv == 1:    # CONVERT_VALUE_TO_REPR
                _r_set(_rd, repr(_v))
            elif _conv == 2:    # CONVERT_VALUE_TO_ASCII
                _r_set(_rd, ascii(_v))
            elif _conv == 3:    # CONVERT_VALUE_TO_BOOL
                _r_set(_rd, bool(_v))
            elif _conv == 4:    # CONVERT_VALUE_TO_INT
                _r_set(_rd, int(_v) if _v is not None else 0)
            elif _conv == 5:    # CONVERT_VALUE_TO_FLOAT
                _r_set(_rd, float(_v) if _v is not None else 0.0)
            else:
                _r_set(_rd, _v)

        # LOAD_COMMON_CONSTANT (111): Load common constant (imm = constant ID)
        elif _op == 111:
            _cc = _imm & 0xFF
            if _cc == 0:
                _r_set(_rd, None)
            elif _cc == 1:
                _r_set(_rd, True)
            elif _cc == 2:
                _r_set(_rd, False)
            elif _cc == 3:
                _r_set(_rd, 0)
            elif _cc == 4:
                _r_set(_rd, 1)
            elif _cc == 5:
                _r_set(_rd, '')
            elif _cc == 6:
                _r_set(_rd, ())
            elif _cc == 7:
                _r_set(_rd, 0.0)
            elif _cc == 8:
                _r_set(_rd, Ellipsis)
            elif _cc == 9:
                _r_set(_rd, NotImplemented)
            else:
                _r_set(_rd, None)

        # LOAD_SPECIAL (112): Load special attribute (imm = name index)
        elif _op == 112:
            _obj = _r_get(_rs1)
            _attr = _names[_imm] if _imm < len(_names) else None
            if _attr is not None:
                try:
                    _r_set(_rd, getattr(_obj, _attr))
                except AttributeError:
                    _r_set(_rd, None)
            else:
                _r_set(_rd, None)

        # ANNOTATIONS_PLACEHOLDER (113): Placeholder for annotations
        elif _op == 113:
            _r_set(_rd, None)

        # ═══════════════════════════════════════════════════════
        # OTHER / MISC (114-139)
        # ═══════════════════════════════════════════════════════

        # BUILD_TEMPLATE (270): Build template string (f-string with formatting)
        elif _op == 114:
            _cnt = _rs2 & 0xFFFF
            _parts = []
            for _i in range(_cnt):
                _p = _r_get(_rr(_rd, 1 + _i))
                _parts.append(str(_p) if _p is not None else 'None')
            _r_set(_rd, ''.join(_parts))

        # END_FOR (271): End of for loop — pop iterator
        elif _op == 115:
            pass

        # EXIT_INIT_CHECK (272): Check __init__ completed properly
        elif _op == 116:
            pass

        # FORMAT_WITH_SPEC (273): Format value with format spec
        elif _op == 117:
            _v = _r_get(_rs1)
            _fmt = _r_get(_rs2)
            if isinstance(_fmt, str) and _fmt:
                try:
                    _r_set(_rd, format(_v, _fmt))
                except Exception:
                    _r_set(_rd, str(_v))
            else:
                _r_set(_rd, format(_v, '') if hasattr(_v, '__format__') else str(_v))

        # RESERVED (274): Reserved opcode — no-op
        elif _op == 118:
            pass

        # GET_LEN (275): Get length of object
        elif _op == 119:
            _v = _r_get(_rs1)
            try:
                _r_set(_rd, len(_v))
            except Exception:
                _r_set(_rd, 0)

        # INTERPRETER_EXIT (276): Exit the interpreter
        elif _op == 124:
            sys.exit(0)

        # BUILD_INTERPOLATION (277): Build interpolated string
        elif _op == 125:
            _cnt = _rs2 & 0xFFFF
            _parts = []
            for _i in range(_cnt):
                _p = _r_get(_rr(_rd, 1 + _i))
                _parts.append(str(_p) if _p is not None else 'None')
            _r_set(_rd, ''.join(_parts))

        # CONTAINS_OP (278): in / not in operator
        elif _op == 126:
            _item = _r_get(_rs1)
            _seq = _r_get(_rs2)
            _invert = _imm & 0xFF
            try:
                _result = _item in _seq
                if _invert:
                    _result = not _result
                _r_set(_rd, _result)
            except Exception:
                _r_set(_rd, False)

        # IS_OP (279): is / is not operator
        elif _op == 127:
            _v1 = _r_get(_rs1)
            _v2 = _r_get(_rs2)
            _invert = _imm & 0xFF
            _result = _v1 is _v2
            if _invert:
                _result = not _result
            _r_set(_rd, _result)

        # LOAD_FAST_CHECK (280): Load fast with unbound check
        elif _op == 128:
            _nm = _names[_imm] if _imm < len(_names) else None
            _v = _locals.get(_nm) if _nm else None
            if _v is None and _nm is not None and _nm not in _locals:
                raise UnboundLocalError(f"local variable '{_nm}' referenced before assignment")
            _r_set(_rd, _v)

        # RAISE_VARARGS (281): raise statement (rd = exc, rs1 = cause)
        elif _op == 129:
            _exc = _r_get(_rd)
            _cause = _r_get(_rs1)
            _argc = _imm & 0xFF
            if _argc == 0:
                raise
            elif _argc == 1:
                raise _exc
            else:
                if _cause is not None:
                    raise _exc from _cause
                else:
                    raise _exc.with_traceback(None)

        # STORE_FAST_LOAD_FAST (282): Store local then load next local
        elif _op == 134:
            _nm = _names[_imm] if _imm < len(_names) else None
            _v = _r_get(_rs1)
            if _nm:
                _locals[_nm] = _v
            _r_set(_rd, _v)

        # STORE_FAST_STORE_FAST (283): Store local then store next local
        elif _op == 135:
            _nm = _names[_imm] if _imm < len(_names) else None
            _v = _r_get(_rd)
            if _nm:
                _locals[_nm] = _v

        # UNPACK_EX (284): Unpack with starred target (rd = nbefore, rs1 = seq, rs2 = nafter)
        elif _op == 136:
            _nbefore = _rd & 0xFF
            _nafter = _rs2 & 0xFF
            _seq = _r_get(_rs1)
            _nstar = len(_seq) - _nbefore - _nafter
            if _nstar < 0:
                raise ValueError(f"not enough values to unpack (expected at least {_nbefore + _nafter}, got {len(_seq)})")
            _result = []
            for _i in range(_nbefore):
                _result.append(_seq[_i])
            _result.append(list(_seq[_nbefore:_nbefore + _nstar]))
            for _i in range(_nafter):
                _result.append(_seq[len(_seq) - _nafter + _i])
            for _i, _v in enumerate(_result):
                _r_set(_rr(_rd, _i), _v)

        # UNPACK_SEQUENCE (285): Unpack sequence to registers (rd = count, rs1 = seq)
        elif _op == 137:
            _cnt = _rd & 0xFF
            _seq = _r_get(_rs1)
            if len(_seq) != _cnt:
                raise ValueError(f"cannot unpack {len(_seq)} values into {_cnt} targets")
            for _i in range(_cnt):
                _r_set(_rr(_rd, 1 + _i), _seq[_i])

        # ENTER_EXECUTOR (286): Enter executor (imm = target, rd = result)
        elif _op == 138:
            _exc_reg = _r_get(_rs1)
            if hasattr(_exc_reg, '__enter__'):
                _r_set(_rd, _exc_reg.__enter__())
            else:
                _r_set(_rd, _exc_reg)

        # STORE_FAST_MAYBE_NULL (287): Like STORE_FAST but may store None
        elif _op == 139:
            _nm = _names[_imm] if _imm < len(_names) else None
            _v = _r_get(_rd)
            if _nm:
                _locals[_nm] = _v

        _ip += _ilen

def _vm_decode_fixed(_c, _p, _k, _m, _rm):
    _raw = _c[_p:_p+8]
    _dec = bytes([_raw[i] ^ _k[i % 32] for i in range(len(_raw))])
    _op = _m[_dec[0]]
    _rd = _rm[_dec[1] & 0x3F] if (_dec[1] & 0x3F) < 64 else 0
    _rs1 = _rm[_dec[2] & 0x3F] if (_dec[2] & 0x3F) < 64 else 0
    _rs2_u = _dec[3] & 0x3F
    _count_ops = frozenset((43, 44, 63, 164, 165, 270, 277, 284, 285))
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

)vm_interp";
#endif