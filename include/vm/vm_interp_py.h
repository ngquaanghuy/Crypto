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

    # ═══════════════════════════════════════════════════════════
    # DISPATCH TABLE — O(1) lookup replaces if-elif chain
    # ═══════════════════════════════════════════════════════════
    _S_SAME = -1  # normal: ip += ilen
    _S_EXIT = -2  # exit interpreter
    _vm_retval = None

    # ─── Opcode handler helpers ───
    def _h_nop():
        pass
    def _h_load_const():
        _r_set(_rd, _consts[_imm])
    def _h_load_name():
        _nm = _names[_imm]
        _r_set(_rd, _globals.get(_nm) if _nm in _globals else _b.get(_nm, _nm))
    def _h_store_name():
        _globals[_names[_imm]] = _r_get(_rd)
    def _h_load_fast():
        _r_set(_rd, _locals.get(_names[_imm], None))
    def _h_store_fast():
        _locals[_names[_imm]] = _r_get(_rd)
    def _h_move():
        _r_set(_rd, _r_get(_rs1))

    # Unary (7,8)
    def _h_unary_invert():
        _v = _r_get(_rs1)
        try:
            _r_set(_rd, ~_v)
        except Exception:
            _r_set(_rd, _v)
    def _h_unary_not():
        _r_set(_rd, not _r_get(_rs1))

    # Setup annotations (9)
    def _h_setup_annotations():
        if '__annotations__' not in _locals:
            _locals['__annotations__'] = {}

    # Arithmetic (10-15)
    def _h_add():
        _r_set(_rd, _r_get(_rs1) + _r_get(_rs2))
    def _h_sub():
        _r_set(_rd, _r_get(_rs1) - _r_get(_rs2))
    def _h_mul():
        _r_set(_rd, _r_get(_rs1) * _r_get(_rs2))
    def _h_div():
        _r_set(_rd, _r_get(_rs1) / _r_get(_rs2))
    def _h_pow():
        _r_set(_rd, _r_get(_rs1) ** _r_get(_rs2))
    def _h_neg():
        _r_set(_rd, -_r_get(_rs1))

    # Bitwise / extended arithmetic (16-19, 34-36)
    def _h_bit_or():
        _r_set(_rd, _r_get(_rs1) | _r_get(_rs2))
    def _h_bit_and():
        _r_set(_rd, _r_get(_rs1) & _r_get(_rs2))
    def _h_bit_xor():
        _r_set(_rd, _r_get(_rs1) ^ _r_get(_rs2))
    def _h_lshift():
        _r_set(_rd, _r_get(_rs1) << _r_get(_rs2))
    def _h_rshift():
        _r_set(_rd, _r_get(_rs1) >> _r_get(_rs2))
    def _h_floor_div():
        _r_set(_rd, _r_get(_rs1) // _r_get(_rs2))
    def _h_mod():
        _r_set(_rd, _r_get(_rs1) % _r_get(_rs2))

    # Comparison (20-25)
    def _h_cmp_eq():
        _r_set(_rd, _r_get(_rs1) == _r_get(_rs2))
    def _h_cmp_ne():
        _r_set(_rd, _r_get(_rs1) != _r_get(_rs2))
    def _h_cmp_lt():
        _r_set(_rd, _r_get(_rs1) < _r_get(_rs2))
    def _h_cmp_le():
        _r_set(_rd, _r_get(_rs1) <= _r_get(_rs2))
    def _h_cmp_gt():
        _r_set(_rd, _r_get(_rs1) > _r_get(_rs2))
    def _h_cmp_ge():
        _r_set(_rd, _r_get(_rs1) >= _r_get(_rs2))

    # Control flow (30-32: jump handlers return new ip)
    def _h_jmp():
        return _imm if _vl_flag else _imm * 8
    def _h_jmp_if_true():
        if _r_get(_rd):
            return _imm if _vl_flag else _imm * 8
        return _S_SAME
    def _h_jmp_if_false():
        if not _r_get(_rd):
            return _imm if _vl_flag else _imm * 8
        return _S_SAME
    def _h_binary_subscr():
        _r_set(_rd, _r_get(_rs1)[_r_get(_rs2)])

    # Call / Return (40-44)
    def _h_call():
        _fn = _r_get(_rs1)
        _args = tuple(_r_get(_rr(_rs1, 1 + _i)) for _i in range(_imm & 0xFFFF))
        _r_set(_rd, _fn(*_args))
    def _h_call_name():
        _r_set(_rd, _names[_rd](*[_r_get(_rr(_rs1, _i)) for _i in range(_imm & 0xFFFF)]))
    def _h_return_op():
        nonlocal _vm_retval
        _vm_retval = _r_get(_rd)
        return _S_EXIT
    def _h_build_tuple():
        _r_set(_rd, tuple(_r_get(_rr(_rs1, _i)) for _i in range(_rs2)))
    def _h_build_list():
        _r_set(_rd, list(_r_get(_rr(_rs1, _i)) for _i in range(_rs2)))

    # Store subscr (50)
    def _h_store_subscr():
        _r_get(_rs1)[_r_get(_rs2)] = _r_get(_rd)

    # Opaque predicates (52-53)
    def _h_opaque_true():
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
    def _h_opaque_false():
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

    # MAKE_FUNCTION (54)
    def _h_make_function():
        _r_set(_rd, types.FunctionType(_r_get(_rs1), _globals))

    # Attribute / Import (60-63)
    def _h_load_attr():
        _r_set(_rd, getattr(_r_get(_rs1), _names[_imm]))
    def _h_import_name():
        _r_set(_rd, __import__(_names[_imm]))
    def _h_format_simple():
        _r_set(_rd, str(_r_get(_rs1)))
    def _h_build_string():
        _r_set(_rd, ''.join(str(_r_get(_rr(_rs1, _i))) for _i in range(_rs2)))

    # Iteration (70-75)
    def _h_get_iter():
        _r_set(_rd, iter(_r_get(_rs1)))
    def _h_for_iter():
        try:
            _r_set(_rd, next(_r_get(_rs1)))
        except StopIteration:
            return _imm
    def _h_list_extend():
        _r_get(_rd).extend(_r_get(_rs1))
    def _h_list_append():
        _r_get(_rd).append(_r_get(_rs1))

    # Indirect & Virtual Call (80-81)
    def _h_call_indirect():
        _fn = _r_get(_rs1)
        _argc = _imm & 0xFFFF
        _args = tuple(_r_get(_rr(_rs1, 1 + _i)) for _i in range(_argc))
        _r_set(_rd, _fn(*_args))
    def _h_call_vtable():
        _obj = _r_get(_rs1)
        _vtable = _r_get(_rr(_rs1, 1))
        _midx = _imm & 0xFFFF
        _argc = (_imm >> 16) & 0xFFFF
        _method = _vtable[_midx]
        _args = tuple(_r_get(_rr(_rs1, 2 + _i)) for _i in range(_argc))
        _r_set(_rd, _method(_obj, *_args))

    # Exception Handling (90-93)
    def _h_try():
        _handler_stack.append({'s': _ip, 'e': _ip + _imm, 'c': None, 't': None})
    def _h_catch():
        if _handler_stack:
            _handler_stack[-1]['t'] = _r_get(_rd)
            _handler_stack[-1]['c'] = _ip + _ilen
    def _h_throw():
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
        return _ip
    def _h_end_try():
        if _handler_stack:
            _handler_stack.pop()

    # Obfuscated branching (100-109) — all return new ip or _S_SAME
    def _h_jmp_if_true_obf():
        _v = _r_get(_rd)
        _t1 = (_v & _v) | _v
        _t2 = (_t1 ^ 0) + 0
        _t3 = _t2 ^ _t2
        if _t3 == 0 and _t2:
            return _imm
        return _S_SAME
    def _h_jmp_if_false_obf():
        _v = _r_get(_rd)
        _t1 = _v | 0
        _t2 = _t1 & _t1
        if (_t2 ^ _t2) == 0 and not _t2:
            return _imm
        return _S_SAME
    def _h_jmp_eq():
        _d = _r_get(_rd) - _r_get(_rs1) if isinstance(_r_get(_rd), (int, float)) and isinstance(_r_get(_rs1), (int, float)) else 1
        _o = _r_get(_rd) ^ _r_get(_rd) if isinstance(_r_get(_rd), int) else 0
        if _o == 0 and _d == 0:
            return _imm
        return _S_SAME
    def _h_jmp_ne():
        _d = _r_get(_rd) - _r_get(_rs1) if isinstance(_r_get(_rd), (int, float)) and isinstance(_r_get(_rs1), (int, float)) else 1
        _m = _r_get(_rd) | 0 if isinstance(_r_get(_rd), int) else 0
        if _m == _m and _d != 0:
            return _imm
        return _S_SAME
    def _h_jmp_lt():
        _d = _r_get(_rd) - _r_get(_rs1) if isinstance(_r_get(_rd), (int, float)) and isinstance(_r_get(_rs1), (int, float)) else 1
        _t = (_d ^ _d) & 0
        if _t == 0 and _d < 0:
            return _imm
        return _S_SAME
    def _h_jmp_le():
        _d = _r_get(_rd) - _r_get(_rs1) if isinstance(_r_get(_rd), (int, float)) and isinstance(_r_get(_rs1), (int, float)) else 1
        _o = _r_get(_rs1) ^ _r_get(_rs1) if isinstance(_r_get(_rs1), int) else 0
        if _o == 0 and _d <= 0:
            return _imm
        return _S_SAME
    def _h_jmp_gt():
        _d = _r_get(_rd) - _r_get(_rs1) if isinstance(_r_get(_rd), (int, float)) and isinstance(_r_get(_rs1), (int, float)) else 1
        if (_d * 0) == 0 and _d > 0:
            return _imm
        return _S_SAME
    def _h_jmp_ge():
        _d = _r_get(_rd) - _r_get(_rs1) if isinstance(_r_get(_rd), (int, float)) and isinstance(_r_get(_rs1), (int, float)) else 1
        _v = _r_get(_rd) & 0xFFFFFFFF if isinstance(_r_get(_rd), int) else 0
        if (_v ^ _v) == 0 and _d >= 0:
            return _imm
        return _S_SAME
    def _h_jmp_indirect():
        _target = _r_get(_rd)
        if isinstance(_target, int) and 0 <= _target < _n:
            return _target
        return 0
    def _h_jmp_table():
        _idx = _r_get(_rd)
        _table_base = _imm & 0xFFFF
        _default_off = (_imm >> 16) & 0xFFFF
        _num_entries = _rs1 & 0xFF
        if isinstance(_idx, int) and 0 <= _idx < _num_entries:
            _entry_off = _table_base + _idx * 4
            if _entry_off + 4 <= _n:
                _off = (_code[_entry_off] | (_code[_entry_off+1] << 8) | (_code[_entry_off+2] << 16) | (_code[_entry_off+3] << 24))
                return _ip + _off
            return _ip + _default_off
        return _ip + _default_off

    # Register Spilling (120-123)
    def _h_spill():
        _spill_stack.append(_r_get(_rd))
    def _h_restore():
        if _spill_stack:
            _r_set(_rd, _spill_stack.pop())
    def _h_spill_many():
        _mask = _imm & 0xFFFF
        for _b in range(16):
            if _mask & (1 << _b):
                _reg = _rd + _b
                if _reg < 64:
                    _spill_stack.append(_r_get(_reg))
                    _r_set(_reg, None)
    def _h_restore_many():
        _cnt = _imm & 0xFF
        for _ in range(min(_cnt, len(_spill_stack))):
            _spill_stack.pop()

    # SMC (130-133)
    def _h_patch_instr():
        _off = _r_get(_rd)
        _plen = _r_get(_rs1)
        _key = _r_get(_rs2)
        if isinstance(_off, int) and isinstance(_plen, int) and isinstance(_key, int):
            if 0 <= _off and _off + _plen <= _n and abs(_off - _ip) > 16:
                _ks = _key.to_bytes(8, 'little')
                for _i in range(min(_plen, 8)):
                    _code[_off + _i] ^= _ks[_i % len(_ks)]
    def _h_patch_opcode():
        _shuf = _rd & 0xFF
        _new_op = _rs1 & 0xFF
        if _shuf < 256:
            _map[_shuf] = _new_op
    def _h_smc_encrypt():
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
    def _h_smc_decrypt():
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

    # Data Obfuscation (140-142)
    def _h_obf_move():
        _v = _r_get(_rs1)
        _t = (_v ^ _v) & 0
        _r_set(_rd, _t | _v)
    def _h_obf_add():
        _v = _r_get(_rs1) + _r_get(_rs2)
        _m = _r_get(_rs1) ^ _r_get(_rs2)
        _r_set(_rd, _v + _m - _m)
    def _h_obf_xor():
        _v = _r_get(_rs1)
        _k = _r_get(_rs2)
        if isinstance(_v, int) and isinstance(_k, int):
            _r_set(_rd, (_v | _k) - (_v & _k) + (_v & _k) - (_v | _k) + (_v ^ _k))
        else:
            _r_set(_rd, _v)

    # CFI (150-152)
    def _h_cfi_check():
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
            sys.stderr.write('error: CFI violation detected\\n')
            sys.exit(1)
    def _h_cfi_fail():
        sys.stderr.write('error: integrity failure\\n')
        sys.exit(1)
    def _h_cfi_table():
        pass

    # CONST_DECRYPT (160)
    def _h_const_decrypt():
        _r_set(_rd, _consts[_imm])

    # Data structures (161-172)
    def _h_binary_slice():
        _obj = _r_get(_rs1); _start = _r_get(_rs2); _stop = _r_get(_rd)
        try:
            _r_set(_rd, _obj[_start:_stop])
        except Exception as _e:
            raise _e
    def _h_delete_subscr():
        _obj = _r_get(_rs1); _key = _r_get(_rs2)
        try:
            del _obj[_key]
        except Exception as _e:
            raise _e
    def _h_store_slice():
        _val = _r_get(_rd); _obj = _r_get(_rs1); _start = _r_get(_rs2)
        try:
            _obj[_start:_imm] = _val
        except Exception as _e:
            raise _e
    def _h_build_map():
        _cnt = _rs2 & 0xFFFF; _d = {}
        for _i in range(_cnt):
            _key_off = _rr(_rd, _i * 2); _val_off = _rr(_rd, _i * 2 + 1)
            _d[_r_get(_key_off)] = _r_get(_val_off)
        _r_set(_rd, _d)
    def _h_build_set():
        _cnt = _rs2 & 0xFFFF; _s = set()
        for _i in range(_cnt):
            _s.add(_r_get(_rr(_rd, _i + 1)))
        _r_set(_rd, _s)
    def _h_build_slice():
        _start = _r_get(_rd); _stop = _r_get(_rs1)
        _step = _r_get(_rs2) if _imm >= 3 else None
        from builtins import slice as _slice
        _r_set(_rd, _slice(_start, _stop, _step))
    def _h_copy():
        _v = _r_get(_rs1)
        try:
            _r_set(_rd, _v.copy() if hasattr(_v, 'copy') else _v[:] if hasattr(_v, '__getitem__') else _v)
        except Exception:
            _r_set(_rd, _v)
    def _h_dict_merge():
        _d = _r_get(_rd); _o = _r_get(_rs1)
        if isinstance(_d, dict) and isinstance(_o, dict):
            _d.update(_o)
        _r_set(_rd, _d)
    def _h_dict_update():
        _d = _r_get(_rd); _o = _r_get(_rs1)
        if isinstance(_d, dict):
            _d.update(_o)
    def _h_map_add():
        _d = _r_get(_rd); _k = _r_get(_rs1); _v = _r_get(_rs2)
        if isinstance(_d, dict):
            _d[_k] = _v
    def _h_set_add():
        _s = _r_get(_rd); _item = _r_get(_rs1)
        if isinstance(_s, set):
            _s.add(_item)
    def _h_set_update():
        _s = _r_get(_rd); _other = _r_get(_rs1)
        if isinstance(_s, set):
            _s.update(_other)

    # Iterator / Generator / Async (180-195)
    def _h_get_aiter():
        _r_set(_rd, _r_get(_rs1).__aiter__())
    def _h_get_anext():
        _r_set(_rd, _r_get(_rs1).__anext__())
    def _h_get_yield_from_iter():
        _obj = _r_get(_rs1)
        try:
            _r_set(_rd, _obj.__iter__())
        except AttributeError:
            _r_set(_rd, iter(_obj))
    def _h_load_build_class():
        _r_set(_rd, _b['__build_class__'])
    def _h_return_generator():
        _fn = _r_get(_rs1)
        if callable(_fn):
            _r_set(_rd, _fn())
        else:
            _r_set(_rd, None)
    def _h_delete_deref():
        _nm = _names[_imm] if _imm < len(_names) else None
        if _nm and _nm in _locals:
            del _locals[_nm]
    def _h_get_awaitable():
        _obj = _r_get(_rs1)
        _r_set(_rd, _obj.__await__() if hasattr(_obj, '__await__') else _obj)
    def _h_load_deref():
        _nm = _names[_imm] if _imm < len(_names) else None
        _v = _locals.get(_nm) if _nm else None
        if _v is None:
            _v = _globals.get(_nm) if _nm else None
        _r_set(_rd, _v)
    def _h_make_cell():
        _v = _r_get(_rs1)
        try:
            _r_set(_rd, (lambda _x: lambda: _x)(_v).__closure__[0])
        except Exception:
            _r_set(_rd, _v)
    def _h_send():
        _gen = _r_get(_rs1); _val = _r_get(_rs2)
        try:
            _r_set(_rd, _gen.send(_val))
        except StopIteration:
            return _imm
    def _h_store_deref():
        _nm = _names[_imm] if _imm < len(_names) else None
        if _nm:
            _locals[_nm] = _r_get(_rd)
    def _h_yield_value():
        _r_set(_rd, _r_get(_rs1))
        return _ip + _ilen
    def _h_load_closure():
        _nm = _names[_imm] if _imm < len(_names) else None
        _v = _locals.get(_nm) if _nm else _globals.get(_nm) if _nm else None
        _r_set(_rd, _v)

    # Exception handling advanced (200-210)
    def _h_check_eg_match():
        _exc = _r_get(_rs1); _mt = _r_get(_rs2)
        try:
            _r_set(_rd, isinstance(_exc, _mt) if isinstance(_mt, type) else False)
        except Exception:
            _r_set(_rd, False)
    def _h_check_exc_match():
        _ev = _r_get(_rs1); _ht = _r_get(_rd)
        _m = False
        if isinstance(_ht, type) and isinstance(_ev, BaseException):
            _m = isinstance(_ev, _ht)
        elif isinstance(_ht, tuple):
            _m = isinstance(_ev, _ht)
        _r_set(_rd, _m)
    def _h_pop_except():
        if _exc_stack:
            _exc_stack.pop()
    def _h_push_exc_info():
        _exc_stack.append(_r_get(_rd))
    def _h_with_except_start():
        _ctx = _r_get(_rs1)
        _typ, _val, _tb = sys.exc_info()
        try:
            _r_set(_rd, _ctx.__exit__(_typ, _val, _tb))
        except Exception:
            _r_set(_rd, False)
    def _h_reraise():
        _exc = _r_get(_rd)
        if _exc is not None and isinstance(_exc, BaseException):
            raise _exc
        raise
    def _h_pop_block():
        if _handler_stack:
            _handler_stack.pop()
    def _h_setup_cleanup():
        _handler_stack.append({'s': _ip, 'e': _n, 'c': _imm, 't': Exception})
    def _h_setup_finally():
        _handler_stack.append({'s': _ip, 'e': _n, 'c': _imm, 't': BaseException})
    def _h_setup_with():
        _ctx = _r_get(_rs1)
        try:
            _handler_stack.append({'s': _ip, 'e': _n, 'c': _imm, 't': BaseException})
            _r_set(_rd, _ctx.__enter__())
        except Exception as _e:
            raise _e

    # Pattern matching (220-223)
    def _h_match_keys():
        _sj = _r_get(_rs1); _ks = _r_get(_rs2)
        if isinstance(_sj, dict) and hasattr(_ks, '__iter__'):
            if all(_k in _sj for _k in _ks):
                _r_set(_rd, tuple(_sj[_k] for _k in _ks))
            else:
                _r_set(_rd, None)
        else:
            _r_set(_rd, None)
    def _h_match_mapping():
        _sj = _r_get(_rs1)
        _r_set(_rd, isinstance(_sj, dict) or hasattr(_sj, 'keys'))
    def _h_match_sequence():
        _sj = _r_get(_rs1); _ml = _imm & 0xFFFF
        _r_set(_rd, isinstance(_sj, (list, tuple)) and len(_sj) >= _ml)
    def _h_match_class():
        _sj = _r_get(_rs1); _cn = _names[_imm] if _imm < len(_names) else None; _na = _rs2 & 0xFF
        _m = False
        if _cn is not None:
            _cls = _globals.get(_cn) or _b.get(_cn)
            if _cls is not None and isinstance(_sj, _cls):
                _m = True
        _r_set(_rd, _m)

    # Control flow 3.14+ (230-235: jump handlers return ip)
    # Uses shared handlers: _h_nop (230), _h_jmp (231,232,235), _h_jmp_if_false (233), _h_jmp_if_true (234)

    # Attribute ops (240-242)
    def _h_delete_attr():
        _obj = _r_get(_rd); _attr = _names[_imm] if _imm < len(_names) else None
        if _obj is not None and _attr is not None:
            try:
                delattr(_obj, _attr)
            except AttributeError as _e:
                raise _e
    def _h_load_super_attr():
        _attr = _names[_imm] if _imm < len(_names) else None
        try:
            _r_set(_rd, super(_r_get(_rs1), _r_get(_rs2)).__getattribute__(_attr) if _attr else None)
        except Exception:
            _r_set(_rd, getattr(_r_get(_rs2), _attr) if _attr else None)
    def _h_store_attr():
        _val = _r_get(_rd); _obj = _r_get(_rs1); _attr = _names[_imm] if _imm < len(_names) else None
        if _obj is not None and _attr is not None:
            setattr(_obj, _attr, _val)

    # Call variants (245-248)
    def _h_call_function_ex():
        _fn = _r_get(_rs1); _args = _r_get(_rs2) if _rs2 < 64 else (); _fl = _imm & 0xFF
        _hk = _fl & 1
        if isinstance(_args, tuple) and len(_args) > 0 and isinstance(_args[-1], dict):
            _pa = _args[:-1]; _ka = _args[-1]
        elif isinstance(_args, dict):
            _pa = (); _ka = _args
        else:
            _pa = _args if isinstance(_args, (tuple, list)) else (); _ka = {}
        if _hk:
            _kw = _r_get(_rr(_rs1, 1))
            _fka = _kw if isinstance(_kw, dict) else {}
        else:
            _fka = {}
        try:
            _r_set(_rd, _fn(*_pa, **_fka))
        except Exception as _e:
            raise _e
    def _h_call_intrinsic_1():
        _v = _r_get(_rs1); _ix = _imm & 0xFF
        if _ix == 0: _r_set(_rd, None)
        elif _ix == 1: _r_set(_rd, _v is None)
        elif _ix == 2: _r_set(_rd, bool(_v) if _v is not None else False)
        elif _ix == 3: _r_set(_rd, len(_v))
        elif _ix == 4: _r_set(_rd, str(_v))
        elif _ix == 5: _r_set(_rd, repr(_v))
        elif _ix == 6: _r_set(_rd, ascii(_v))
        elif _ix == 7: _r_set(_rd, bool(_v))
        elif _ix == 8: _r_set(_rd, _v.__order__() if hasattr(_v, '__order__') else _v)
        else: _r_set(_rd, _v)
    def _h_call_intrinsic_2():
        _v1 = _r_get(_rs1); _v2 = _r_get(_rs2); _ix = _imm & 0xFF
        if _ix == 0: _r_set(_rd, None)
        elif _ix == 1: _r_set(_rd, _v1 == _v2)
        elif _ix == 2: _r_set(_rd, _v1 != _v2)
        elif _ix == 3: _r_set(_rd, isinstance(_v1, _v2) if isinstance(_v2, type) else False)
        elif _ix == 4: _r_set(_rd, issubclass(_v1, _v2) if isinstance(_v1, type) and isinstance(_v2, type) else False)
        elif _ix == 5:
            try: _r_set(_rd, _v2 in _v1)
            except Exception: _r_set(_rd, False)
        elif _ix == 6:
            try: _r_set(_rd, _v2 not in _v1)
            except Exception: _r_set(_rd, True)
        elif _ix == 7: _r_set(_rd, _v1 ** _v2)
        elif _ix == 8: _r_set(_rd, divmod(_v1, _v2))
        else: _r_set(_rd, None)
    def _h_call_kw():
        _fn = _r_get(_rs1); _nr = _rs2; _ac = _imm & 0xFFFF
        _nt = _r_get(_nr) if _nr < 64 else None
        _kwn = _nt if isinstance(_nt, tuple) and len(_nt) == _ac else (None,) * _ac
        _pa = []; _ka = {}
        for _i in range(_ac):
            _av = _r_get(_rr(_rs1, 1 + _i))
            if _i < len(_kwn) and _kwn[_i] is not None:
                _ka[_kwn[_i]] = _av
            else:
                _pa.append(_av)
        try:
            _r_set(_rd, _fn(*_pa, **_ka))
        except Exception as _e:
            raise _e

    # Name delete (250-254)
    def _h_delete_fast():
        _nm = _names[_imm] if _imm < len(_names) else None
        if _nm and _nm in _locals:
            del _locals[_nm]
    def _h_delete_global():
        _nm = _names[_imm] if _imm < len(_names) else None
        if _nm and _nm in _globals:
            del _globals[_nm]
    def _h_delete_name():
        _nm = _names[_imm] if _imm < len(_names) else None
        if _nm:
            if _nm in _locals:
                del _locals[_nm]
            elif _nm in _globals:
                del _globals[_nm]
    def _h_load_from_dict_or_deref():
        _d = _r_get(_rs1); _nm = _names[_imm] if _imm < len(_names) else None
        _v = _locals.get(_nm) if _nm else None
        if _v is None and isinstance(_d, dict) and _nm:
            _v = _d.get(_nm)
        if _v is None and _nm:
            _v = _globals.get(_nm) or _b.get(_nm)
        _r_set(_rd, _v)
    def _h_load_from_dict_or_globals():
        _d = _r_get(_rs1); _nm = _names[_imm] if _imm < len(_names) else None
        _v = _globals.get(_nm) if _nm else None
        if _v is None and isinstance(_d, dict) and _nm:
            _v = _d.get(_nm)
        if _v is None and _nm:
            _v = _b.get(_nm)
        _r_set(_rd, _v)

    # Misc: Convert, Common Constant, Special, Annotations (110-113)
    def _h_convert_value():
        _v = _r_get(_rs1); _conv = _imm & 0xFF
        if _conv == 0: _r_set(_rd, str(_v))
        elif _conv == 1: _r_set(_rd, repr(_v))
        elif _conv == 2: _r_set(_rd, ascii(_v))
        elif _conv == 3: _r_set(_rd, bool(_v))
        elif _conv == 4: _r_set(_rd, int(_v) if _v is not None else 0)
        elif _conv == 5: _r_set(_rd, float(_v) if _v is not None else 0.0)
        else: _r_set(_rd, _v)
    def _h_load_common_constant():
        _cc = _imm & 0xFF
        if _cc == 0: _r_set(_rd, None)
        elif _cc == 1: _r_set(_rd, True)
        elif _cc == 2: _r_set(_rd, False)
        elif _cc == 3: _r_set(_rd, 0)
        elif _cc == 4: _r_set(_rd, 1)
        elif _cc == 5: _r_set(_rd, '')
        elif _cc == 6: _r_set(_rd, ())
        elif _cc == 7: _r_set(_rd, 0.0)
        elif _cc == 8: _r_set(_rd, Ellipsis)
        elif _cc == 9: _r_set(_rd, NotImplemented)
        else: _r_set(_rd, None)
    def _h_load_special():
        _obj = _r_get(_rs1); _attr = _names[_imm] if _imm < len(_names) else None
        if _attr is not None:
            try:
                _r_set(_rd, getattr(_obj, _attr))
            except AttributeError:
                _r_set(_rd, None)
        else:
            _r_set(_rd, None)
    def _h_annotations_placeholder():
        _r_set(_rd, None)

    # Misc ops (114-119, 124-129, 134-139)
    def _h_build_template():
        _cnt = _rs2 & 0xFFFF; _parts = []
        for _i in range(_cnt):
            _parts.append(str(_r_get(_rr(_rd, 1 + _i))) if _r_get(_rr(_rd, 1 + _i)) is not None else 'None')
        _r_set(_rd, ''.join(_parts))
    def _h_format_with_spec():
        _v = _r_get(_rs1); _fmt = _r_get(_rs2)
        if isinstance(_fmt, str) and _fmt:
            try:
                _r_set(_rd, format(_v, _fmt))
            except Exception:
                _r_set(_rd, str(_v))
        else:
            _r_set(_rd, format(_v, '') if hasattr(_v, '__format__') else str(_v))
    def _h_get_len():
        _v = _r_get(_rs1)
        try:
            _r_set(_rd, len(_v))
        except Exception:
            _r_set(_rd, 0)
    def _h_interpreter_exit():
        sys.exit(0)
    def _h_build_interpolation():
        _cnt = _rs2 & 0xFFFF; _parts = []
        for _i in range(_cnt):
            _parts.append(str(_r_get(_rr(_rd, 1 + _i))) if _r_get(_rr(_rd, 1 + _i)) is not None else 'None')
        _r_set(_rd, ''.join(_parts))
    def _h_contains_op():
        _item = _r_get(_rs1); _seq = _r_get(_rs2); _inv = _imm & 0xFF
        try:
            _r = _item in _seq
            _r_set(_rd, not _r if _inv else _r)
        except Exception:
            _r_set(_rd, False)
    def _h_is_op():
        _v1 = _r_get(_rs1); _v2 = _r_get(_rs2); _inv = _imm & 0xFF
        _r = _v1 is _v2
        _r_set(_rd, not _r if _inv else _r)
    def _h_load_fast_check():
        _nm = _names[_imm] if _imm < len(_names) else None
        _v = _locals.get(_nm) if _nm else None
        if _v is None and _nm is not None and _nm not in _locals:
            raise UnboundLocalError(f"local variable '{_nm}' referenced before assignment")
        _r_set(_rd, _v)
    def _h_raise_varargs():
        _exc = _r_get(_rd); _cause = _r_get(_rs1); _argc = _imm & 0xFF
        if _argc == 0:
            raise
        elif _argc == 1:
            raise _exc
        else:
            if _cause is not None:
                raise _exc from _cause
            else:
                raise _exc.with_traceback(None)
    def _h_store_fast_load_fast():
        _nm = _names[_imm] if _imm < len(_names) else None
        _v = _r_get(_rs1)
        if _nm:
            _locals[_nm] = _v
        _r_set(_rd, _v)
    def _h_store_fast_store_fast():
        _nm = _names[_imm] if _imm < len(_names) else None
        if _nm:
            _locals[_nm] = _r_get(_rd)
    def _h_unpack_ex():
        _nb = _rd & 0xFF; _na = _rs2 & 0xFF; _seq = _r_get(_rs1)
        _ns = len(_seq) - _nb - _na
        if _ns < 0:
            raise ValueError(f"not enough values to unpack (expected at least {_nb + _na}, got {len(_seq)})")
        _res = []
        for _i in range(_nb):
            _res.append(_seq[_i])
        _res.append(list(_seq[_nb:_nb + _ns]))
        for _i in range(_na):
            _res.append(_seq[len(_seq) - _na + _i])
        for _i, _v in enumerate(_res):
            _r_set(_rr(_rd, _i), _v)
    def _h_unpack_sequence():
        _cnt = _rd & 0xFF; _seq = _r_get(_rs1)
        if len(_seq) != _cnt:
            raise ValueError(f"cannot unpack {len(_seq)} values into {_cnt} targets")
        for _i in range(_cnt):
            _r_set(_rr(_rd, 1 + _i), _seq[_i])
    def _h_enter_executor():
        _er = _r_get(_rs1)
        _r_set(_rd, _er.__enter__() if hasattr(_er, '__enter__') else _er)
    def _h_store_fast_maybe_null():
        _nm = _names[_imm] if _imm < len(_names) else None
        if _nm:
            _locals[_nm] = _r_get(_rd)

    # ─── Build dispatch table (indexed by opcode) ───
    _dt = [None] * 256
    _dt[0] = _h_nop
    _dt[1] = _h_load_const
    _dt[2] = _h_load_name
    _dt[3] = _h_store_name
    _dt[4] = _h_load_fast
    _dt[5] = _h_store_fast
    _dt[6] = _h_move
    _dt[7] = _h_unary_invert
    _dt[8] = _h_unary_not
    _dt[9] = _h_setup_annotations
    _dt[10] = _h_add
    _dt[11] = _h_sub
    _dt[12] = _h_mul
    _dt[13] = _h_div
    _dt[14] = _h_pow
    _dt[15] = _h_neg
    _dt[16] = _h_bit_or
    _dt[17] = _h_bit_and
    _dt[18] = _h_bit_xor
    _dt[19] = _h_lshift
    _dt[20] = _h_cmp_eq
    _dt[21] = _h_cmp_ne
    _dt[22] = _h_cmp_lt
    _dt[23] = _h_cmp_le
    _dt[24] = _h_cmp_gt
    _dt[25] = _h_cmp_ge
    _dt[30] = _h_jmp
    _dt[34] = _h_rshift
    _dt[35] = _h_floor_div
    _dt[36] = _h_mod
    _dt[31] = _h_jmp_if_true
    _dt[32] = _h_jmp_if_false
    _dt[33] = _h_binary_subscr
    _dt[40] = _h_call
    _dt[41] = _h_call_name
    _dt[42] = _h_return_op
    _dt[43] = _h_build_tuple
    _dt[44] = _h_build_list
    _dt[50] = _h_store_subscr
    _dt[52] = _h_opaque_true
    _dt[53] = _h_opaque_false
    _dt[54] = _h_make_function
    _dt[60] = _h_load_attr
    _dt[61] = _h_import_name
    _dt[62] = _h_format_simple
    _dt[63] = _h_build_string
    _dt[70] = _h_get_iter
    _dt[71] = _h_for_iter
    _dt[72] = _h_list_extend
    _dt[75] = _h_list_append
    _dt[80] = _h_call_indirect
    _dt[81] = _h_call_vtable
    _dt[90] = _h_try
    _dt[91] = _h_catch
    _dt[92] = _h_throw
    _dt[93] = _h_end_try
    _dt[100] = _h_jmp_if_true_obf
    _dt[101] = _h_jmp_if_false_obf
    _dt[102] = _h_jmp_eq
    _dt[103] = _h_jmp_ne
    _dt[104] = _h_jmp_lt
    _dt[105] = _h_jmp_le
    _dt[106] = _h_jmp_gt
    _dt[107] = _h_jmp_ge
    _dt[108] = _h_jmp_indirect
    _dt[109] = _h_jmp_table
    _dt[110] = _h_convert_value
    _dt[111] = _h_load_common_constant
    _dt[112] = _h_load_special
    _dt[113] = _h_annotations_placeholder
    _dt[114] = _h_build_template
    _dt[115] = _h_nop
    _dt[116] = _h_nop
    _dt[117] = _h_format_with_spec
    _dt[118] = _h_nop
    _dt[119] = _h_get_len
    _dt[120] = _h_spill
    _dt[121] = _h_restore
    _dt[122] = _h_spill_many
    _dt[123] = _h_restore_many
    _dt[124] = _h_interpreter_exit
    _dt[125] = _h_build_interpolation
    _dt[126] = _h_contains_op
    _dt[127] = _h_is_op
    _dt[128] = _h_load_fast_check
    _dt[129] = _h_raise_varargs
    _dt[130] = _h_patch_instr
    _dt[131] = _h_patch_opcode
    _dt[132] = _h_smc_encrypt
    _dt[133] = _h_smc_decrypt
    _dt[134] = _h_store_fast_load_fast
    _dt[135] = _h_store_fast_store_fast
    _dt[136] = _h_unpack_ex
    _dt[137] = _h_unpack_sequence
    _dt[138] = _h_enter_executor
    _dt[139] = _h_store_fast_maybe_null
    _dt[140] = _h_obf_move
    _dt[141] = _h_obf_add
    _dt[142] = _h_obf_xor
    _dt[150] = _h_cfi_check
    _dt[151] = _h_cfi_fail
    _dt[152] = _h_nop
    _dt[160] = _h_const_decrypt
    _dt[161] = _h_binary_slice
    _dt[162] = _h_delete_subscr
    _dt[163] = _h_store_slice
    _dt[164] = _h_build_map
    _dt[165] = _h_build_set
    _dt[166] = _h_build_slice
    _dt[167] = _h_copy
    _dt[168] = _h_dict_merge
    _dt[169] = _h_dict_update
    _dt[170] = _h_map_add
    _dt[171] = _h_set_add
    _dt[172] = _h_set_update
    _dt[180] = _h_nop
    _dt[181] = _h_get_aiter
    _dt[182] = _h_get_anext
    _dt[183] = _h_get_yield_from_iter
    _dt[184] = _h_load_build_class
    _dt[185] = _h_return_generator
    _dt[186] = _h_nop
    _dt[187] = _h_delete_deref
    _dt[188] = _h_nop
    _dt[189] = _h_get_awaitable
    _dt[190] = _h_load_deref
    _dt[191] = _h_make_cell
    _dt[192] = _h_send
    _dt[193] = _h_store_deref
    _dt[194] = _h_yield_value
    _dt[195] = _h_load_closure
    _dt[200] = _h_check_eg_match
    _dt[201] = _h_check_exc_match
    _dt[202] = _h_nop
    _dt[203] = _h_pop_except
    _dt[204] = _h_push_exc_info
    _dt[205] = _h_with_except_start
    _dt[206] = _h_reraise
    _dt[207] = _h_pop_block
    _dt[208] = _h_setup_cleanup
    _dt[209] = _h_setup_finally
    _dt[210] = _h_setup_with
    _dt[220] = _h_match_keys
    _dt[221] = _h_match_mapping
    _dt[222] = _h_match_sequence
    _dt[223] = _h_match_class
    _dt[230] = _h_nop
    _dt[231] = _h_jmp
    _dt[232] = _h_jmp
    _dt[233] = _h_jmp_if_false
    _dt[234] = _h_jmp_if_true
    _dt[235] = _h_jmp
    _dt[240] = _h_delete_attr
    _dt[241] = _h_load_super_attr
    _dt[242] = _h_store_attr
    _dt[245] = _h_call_function_ex
    _dt[246] = _h_call_intrinsic_1
    _dt[247] = _h_call_intrinsic_2
    _dt[248] = _h_call_kw
    _dt[250] = _h_delete_fast
    _dt[251] = _h_delete_global
    _dt[252] = _h_delete_name
    _dt[253] = _h_load_from_dict_or_deref
    _dt[254] = _h_load_from_dict_or_globals
    # Fill remaining slots with no-op
    for _di in range(256):
        if _dt[_di] is None:
            _dt[_di] = _h_nop

    # ═══════════════════════════════════════════════════════════
    # MAIN DISPATCH LOOP
    # ═══════════════════════════════════════════════════════════
    _dispatch_state = 0
    while _ip < _n:
        _cycle += 1

        # Anti-debug: timing check
        if _cycle % _vm_timing_interval == 0:
            if _vm_tm.time() - _vm_t0 > 0.25:
                _r_set(_rd, None)
            _vm_t0 = _vm_tm.time()

        # Periodic re-garbler: rotate keys every 32 cycles
        if _cycle & 0x1F == 0:
            _r_re_garbler()

        # Rotating dispatch: 4 modes for anti-analysis
        _dispatch_state = (_dispatch_state + (_cycle & 1) + 1) & 0x3
        _guard_0 = _cycle ^ _cycle

        if _dispatch_state == 0:
            if _guard_0 == 0:
                _op, _rd, _rs1, _rs2, _imm, _ilen, _ = _decode()
        elif _dispatch_state == 1:
            _op, _rd, _rs1, _rs2, _imm, _ilen, _ = _decode()
        else:
            if _dispatch_state == 2:
                _op, _rd, _rs1, _rs2, _imm, _ilen, _ = _decode()
            else:
                _op, _rd, _rs1, _rs2, _imm, _ilen, _ = _decode()

        # O(1) dispatch via lookup table (vs O(n) if-elif chain)
        # Handlers return: _S_EXIT (exit), int (new ip for jumps),
        # _S_SAME or None (normal flow — ip += ilen)
        _new_ip = _dt[_op]()
        if _new_ip is _S_EXIT:
            break
        if _new_ip is _S_SAME or _new_ip is None:
            _ip += _ilen
        else:
            _ip = _new_ip

    return _vm_retval

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