# Helper: return (mapped_rs2, unmapped_rs2) for ops that use rs2 as count
def _vm_rs2(_dec, _rm, _op):
    _raw = _dec[3]
    _mapped = _rm[_raw & 0x3F] if (_raw & 0x3F) < 64 else 0
    # Ops using rs2 as count (not register): BUILD_TUPLE(43), BUILD_LIST(44), BUILD_STRING(63),
    # BUILD_TEMPLATE(114), BUILD_INTERPOLATION(125), UNPACK_EX(136), UNPACK_SEQUENCE(137),
    # BUILD_MAP(164), BUILD_SET(165).
    _count_ops = frozenset((43, 44, 63, 114, 125, 136, 137, 164, 165))
    if _op in _count_ops:
        return _raw, _raw  # return unmapped as both (used as count)
    return _mapped, _raw  # mapped for register, raw for reference

def _vm_decode_vl(_c, _p, _k, _m, _rm):
    _tag = _c[_p] ^ _k[_p % 32]
    _cls = (_tag >> 6) & 0x3
    if _cls == 0:
        if _p + 2 > len(_c): return 0, 0, 0, 0, 0, 1, 0
        _op = _m[_tag & 0x0F]
        _b1 = _c[_p+1] ^ _k[(_p+1) % 32]
        _rd = _rm[(_b1 >> 4) & 0x0F] if ((_b1 >> 4) & 0x0F) < 64 else 0
        _rs1 = _rm[_b1 & 0x0F] if (_b1 & 0x0F) < 64 else 0
        return _op, _rd, _rs1, 0, 0, 2, 0
    elif _cls == 1:
        if _p + 4 > len(_c): return 0, 0, 0, 0, 0, 1, 0
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
        if _p + 9 > len(_c): return 0, 0, 0, 0, 0, 1, 0
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
        _count_ops = frozenset((43, 44, 63, 114, 125, 136, 137, 164, 165))
        _rs2 = _rs2_u if _op in _count_ops else _rs2_m
        return _op, _rd, _rs1, _rs2, _imm, 9, _rs2_u
    else:
        _nb = _tag & 0x0F
        if _nb == 0:
            _nb = 1
        _ilen = 2 + _nb * 8
        if _p + _ilen > len(_c): return 0, 0, 0, 0, 0, 1, 0
        _op = _m[(_c[_p+1] ^ _k[(_p+1) % 32]) & 0xFF]
        _b2 = _c[_p+2] ^ _k[(_p+2) % 32]
        _rd = _rm[_b2 & 0x3F] if (_b2 & 0x3F) < 64 else 0
        _b3 = _c[_p+3] ^ _k[(_p+3) % 32]
        _rs1 = _rm[_b3 & 0x3F] if (_b3 & 0x3F) < 64 else 0
        _b4 = _c[_p+4] ^ _k[(_p+4) % 32]
        _rs2_m = _rm[_b4 & 0x3F] if (_b4 & 0x3F) < 64 else 0
        _rs2_u = _b4 & 0x3F
        _i0 = _c[_p+5] ^ _k[(_p+5) % 32]
        _i1 = _c[_p+6] ^ _k[(_p+6) % 32]
        _i2 = _c[_p+7] ^ _k[(_p+7) % 32]
        _i3 = _c[_p+8] ^ _k[(_p+8) % 32]
        _imm = _i0 | (_i1 << 8) | (_i2 << 16) | (_i3 << 24)
        _count_ops = frozenset((43, 44, 63, 114, 125, 136, 137, 164, 165))
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
        _count_ops = frozenset((43, 44, 63, 114, 125, 136, 137, 164, 165))
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
        _count_ops = frozenset((43, 44, 63, 114, 125, 136, 137, 164, 165))
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

def _vm_run(_code, _consts, _names, _globals, _locals, _map, _op_key, _vl_flag, _poly_flag=False, _vram_flag=False, _vram_size=4096):
    import sys, random, types
    import time as _vm_tm
    import os as _vm_os

    # ─── Anti-Hook: Cache builtins at startup before any hook can replace them ───
    _hook_getattr = getattr
    _hook_setattr = setattr
    _hook_hasattr = hasattr
    _hook_isinstance = isinstance
    _hook_issubclass = issubclass
    _hook_type = type
    _hook_callable = callable
    _hook_len = len
    _hook_iter = iter
    _hook_next = next
    _hook_str = str
    _hook_repr = repr
    _hook_dir = dir
    _hook_hash = hash
    _hook_id = id
    _hook_ord = ord
    _hook_chr = chr
    _hook_bytes = bytes
    _hook_bytearray = bytearray
    _hook_list = list
    _hook_dict = dict
    _hook_tuple = tuple
    _hook_set = set
    _hook_frozenset = frozenset
    _hook_range = range
    _hook_enumerate = enumerate
    _hook_zip = zip
    _hook_map = map
    _hook_filter = filter
    _hook_sum = sum
    _hook_all = all
    _hook_any = any
    _hook_sorted = sorted
    _hook_reversed = reversed
    _hook_min = min
    _hook_max = max
    _hook_abs = abs
    _hook_hex = hex
    _hook_bin = bin
    _hook_oct = oct
    _hook_int = int
    _hook_float = float
    _hook_bool = bool
    _hook_complex = complex
    _hook_slice = slice
    _hookobject_getattribute = object.__getattribute__
    _hook_super = super
    _hook_import = __import__

    # ─── Anti-Debug Layer 1: Trace & Module Detection ───
    if _hook_getattr(sys, 'gettrace', None) is not None:
        if _hook_getattr(sys, 'gettrace')() is not None:
            sys.exit(1)
    _mods = sys.modules
    for _dm in ['pdb', 'pydevd', 'pydevconsole', 'IPython.terminal', 'pydevd_frame_evaluator']:
        if _dm in _mods:
            sys.exit(1)
    # Also scan module names for debugger patterns
    for _dm_name in _hook_list(_mods.keys()):
        _dm_lower = _dm_name.lower()
        if 'pdb' in _dm_lower or 'pydev' in _dm_lower or 'debug' in _dm_lower:
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
    _r_type = [0] * 64  # type tracking: 0=non-int/unknown, 1=int — avoids isinstance()
    _garbler_keys = [[random.getrandbits(64) for _ in range(64)]]

    def _r_get(_ix):
        # Return raw stored value - no garbler XOR (fixes int corruption bug)
        return _r_even[_ix >> 1] if (_ix & 1) == 0 else _r_odd[_ix >> 1]

    def _r_set(_ix, _vv):
        # Store raw value - no garbler XOR (fixes int corruption bug)
        _r_type[_ix] = 0
        if (_ix & 1) == 0:
            _r_even[_ix >> 1] = _vv
        else:
            _r_odd[_ix >> 1] = _vv
        # ─── Record write history (critical for debugging register corruption) ───
        if _vm_trace_reg >= 0 and _ix == _vm_trace_reg:
            _op_name = {1:'LDC',2:'LDN',3:'STN',4:'LDF',5:'STF',6:'MOV',7:'INV',8:'NOT',
                        10:'ADD',11:'SUB',12:'MUL',13:'DIV',30:'JMP',31:'JMT',32:'JMF',
                        33:'SUB',40:'CAL',42:'RET',43:'TUP',44:'LST',50:'SBS',
                        54:'MKF',60:'LDA',61:'IMP',62:'FMT',63:'BST',70:'ITR',
                        71:'FOR',72:'LEX',75:'LAP',110:'CVT',111:'LCC',112:'LSP',
                        114:'TPL',117:'FWS',119:'LEN',125:'BIN',126:'CTN',127:'ISO',
                        128:'LFC',134:'SFL',135:'SFS',136:'UPX',137:'UNP',138:'ENT',
                        139:'SFN',161:'BSL',163:'STS',164:'MAP',165:'SET',166:'SLI',
                        167:'CPY',170:'MAD',171:'SAD',172:'SUP',190:'LDR',191:'MKC',
                        192:'SND',193:'SDR',194:'YLD',195:'LDC',
                        220:'MKY',221:'MMP',222:'MSQ',223:'MCL',
                        240:'DAT',241:'LSA',242:'STA',245:'CFX',246:'CI1',247:'CI2',
                        248:'KW ',250:'DLF',251:'DLG',252:'DLN',253:'LFD',254:'LFG'}.get(_op, f'{_op:3d}')
            import sys as _tr_sys
            _tr_sys.stderr.write(f'[TRACE r{_ix}] cycle={_cycle} op={_op_name} val={repr(_vv)[:60]}\n')
            _tr_sys.stderr.flush()
        _vm_reg_history[_ix] = (_cycle, _rd, _rs1, _rs2, _op)

    # Re-garbler: rotate all 64 XOR keys simultaneously
    def _r_re_garbler():
        _nk = [random.getrandbits(64) for _ in range(64)]
        for _gi in range(64):
            _gv = _r_even[_gi >> 1] if (_gi & 1) == 0 else _r_odd[_gi >> 1]
            if _r_type[_gi]:  # fast: only re-XOR int-typed values
                _dv = _gv ^ _garbler_keys[0][_gi] ^ _nk[_gi]
                if (_gi & 1) == 0:
                    _r_even[_gi >> 1] = _dv
                else:
                    _r_odd[_gi >> 1] = _dv
        _garbler_keys[0] = _nk

    # ─── Page-Based Virtual RAM ───
    # Sparse paged memory: only allocates pages that are actually written to.
    # _VM_RAM_PAGES = { page_index: bytearray(256) } — zero-fill on read, auto-allocate on write.
    # Garble only touches allocated pages — O(used_pages) instead of O(total_size).
    _VM_PAGE_SIZE = 256
    _VM_RAM_PAGES = {}
    _VM_RAM_KEY = bytes(16) if not _vram_flag else bytes(random.getrandbits(8) for _ in range(16))

    def _vm_page_idx(_addr):
        return _addr >> 8  # same as _addr // 256
    def _vm_page_off(_addr):
        return _addr & 0xFF  # same as _addr % 256

    def _vm_ram_read(_addr):
        if _addr < 0:
            return 0
        _pi = _vm_page_idx(_addr)
        _po = _vm_page_off(_addr)
        _pg = _VM_RAM_PAGES.get(_pi)
        if _pg is None:
            return 0  # unallocated page → zero-fill
        return _pg[_po] ^ (_VM_RAM_KEY[_addr & 15] & 0xFF)

    def _vm_ram_write(_addr, _val):
        if _addr < 0:
            return
        _pi = _vm_page_idx(_addr)
        _po = _vm_page_off(_addr)
        _pg = _VM_RAM_PAGES.get(_pi)
        if _pg is None:
            _pg = bytearray(_VM_PAGE_SIZE)
            _VM_RAM_PAGES[_pi] = _pg
        _pg[_po] = (_val & 0xFF) ^ (_VM_RAM_KEY[_addr & 15] & 0xFF)

    def _vm_ram_read_w(_addr):
        if _addr < 0:
            return 0
        _end = _addr + 4
        _v = 0
        for _i in range(4):
            _a = _addr + _i
            _pi = _vm_page_idx(_a)
            _po = _vm_page_off(_a)
            _pg = _VM_RAM_PAGES.get(_pi)
            if _pg is None:
                _b = 0
            else:
                _b = _pg[_po] ^ (_VM_RAM_KEY[_a & 15] & 0xFF)
            _v |= _b << (_i * 8)
        return _v

    def _vm_ram_write_w(_addr, _val):
        if _addr < 0:
            return
        for _i in range(4):
            _a = _addr + _i
            _pi = _vm_page_idx(_a)
            _po = _vm_page_off(_a)
            _pg = _VM_RAM_PAGES.get(_pi)
            if _pg is None:
                _pg = bytearray(_VM_PAGE_SIZE)
                _VM_RAM_PAGES[_pi] = _pg
            _pg[_po] = ((_val >> (_i * 8)) & 0xFF) ^ (_VM_RAM_KEY[_a & 15] & 0xFF)

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

    # ─── Cached register values (pre-read from _r_get, post-write via _r_set) ───
    _rd_val = _rs1_val = _rs2_val = None
    _rd_modified = False

    # ─── Opcode handler helpers ───
    # Simple handlers use cached _rd_val/_rs1_val/_rs2_val (no _r_get/_r_set call)
    # Complex handlers use _r_get/_r_set directly (call, exception, SMC, etc.)
    #
    # Main loop does:
    #   1. Pre-read: _rd_val = _r_get(_rd), _rs1_val = _r_get(_rs1), _rs2_val = _r_get(_rs2)
    #   2. Call handler
    #   3. If _rd_modified: _r_set(_rd, _rd_val)

    def _h_nop():
        pass
    def _h_load_const():
        nonlocal _rd_val, _rd_modified
        _rd_val = _consts[_imm]
        _rd_modified = True
    def _h_load_name():
        nonlocal _rd_val, _rd_modified
        _nm = _names[_imm]
        _rd_val = _globals.get(_nm) if _nm in _globals else _b.get(_nm, _nm)
        _rd_modified = True
    def _h_store_name():
        if _vm_debug:
            import sys
            _nm = _names[_imm] if _imm < len(_names) else '???'
            print(f'[vm STN] store {_nm!r} = {repr(_rd_val)[:60]} (rd={_rd}, rs1={_rs1}, _reg_map[rd]={_reg_map[_rd] if _rd < 64 else "?"})', file=sys.stderr)
        _globals[_names[_imm]] = _rd_val
    def _h_load_fast():
        nonlocal _rd_val, _rd_modified
        _rd_val = _locals.get(_names[_imm], None)
        _rd_modified = True
    def _h_store_fast():
        _locals[_names[_imm]] = _rd_val
    def _h_move():
        nonlocal _rd_val, _rd_modified
        _rd_val = _rs1_val
        _rd_modified = True

    # Unary (7,8)
    def _h_unary_invert():
        nonlocal _rd_val, _rd_modified
        try:
            _rd_val = ~_rs1_val
        except Exception:
            _rd_val = _rs1_val
        _rd_modified = True
    def _h_unary_not():
        nonlocal _rd_val, _rd_modified
        _rd_val = not _rs1_val
        _rd_modified = True

    # Setup annotations (9)
    def _h_setup_annotations():
        if '__annotations__' not in _locals:
            _locals['__annotations__'] = {}

    # Arithmetic (10-15)
    def _h_add():
        nonlocal _rd_val, _rd_modified
        _rd_val = _rs1_val + _rs2_val
        _rd_modified = True
    def _h_sub():
        nonlocal _rd_val, _rd_modified
        _rd_val = _rs1_val - _rs2_val
        _rd_modified = True
    def _h_mul():
        nonlocal _rd_val, _rd_modified
        _rd_val = _rs1_val * _rs2_val
        _rd_modified = True
    def _h_div():
        nonlocal _rd_val, _rd_modified
        _rd_val = _rs1_val / _rs2_val
        _rd_modified = True
    def _h_pow():
        nonlocal _rd_val, _rd_modified
        _rd_val = _rs1_val ** _rs2_val
        _rd_modified = True
    def _h_neg():
        nonlocal _rd_val, _rd_modified
        _rd_val = -_rs1_val
        _rd_modified = True

    # Bitwise / extended arithmetic (16-19, 34-36)
    def _h_bit_or():
        nonlocal _rd_val, _rd_modified
        _rd_val = _rs1_val | _rs2_val
        _rd_modified = True
    def _h_bit_and():
        nonlocal _rd_val, _rd_modified
        _rd_val = _rs1_val & _rs2_val
        _rd_modified = True
    def _h_bit_xor():
        nonlocal _rd_val, _rd_modified
        _rd_val = _rs1_val ^ _rs2_val
        _rd_modified = True
    def _h_lshift():
        nonlocal _rd_val, _rd_modified
        _rd_val = _rs1_val << _rs2_val
        _rd_modified = True
    def _h_rshift():
        nonlocal _rd_val, _rd_modified
        _rd_val = _rs1_val >> _rs2_val
        _rd_modified = True
    def _h_floor_div():
        nonlocal _rd_val, _rd_modified
        _rd_val = _rs1_val // _rs2_val
        _rd_modified = True
    def _h_mod():
        nonlocal _rd_val, _rd_modified
        _rd_val = _rs1_val % _rs2_val
        _rd_modified = True

    # Comparison (20-25)
    def _h_cmp_eq():
        nonlocal _rd_val, _rd_modified
        _rd_val = _rs1_val == _rs2_val
        _rd_modified = True
    def _h_cmp_ne():
        nonlocal _rd_val, _rd_modified
        _rd_val = _rs1_val != _rs2_val
        _rd_modified = True
    def _h_cmp_lt():
        nonlocal _rd_val, _rd_modified
        _rd_val = _rs1_val < _rs2_val
        _rd_modified = True
    def _h_cmp_le():
        nonlocal _rd_val, _rd_modified
        _rd_val = _rs1_val <= _rs2_val
        _rd_modified = True
    def _h_cmp_gt():
        nonlocal _rd_val, _rd_modified
        _rd_val = _rs1_val > _rs2_val
        _rd_modified = True
    def _h_cmp_ge():
        nonlocal _rd_val, _rd_modified
        _rd_val = _rs1_val >= _rs2_val
        _rd_modified = True

    # Control flow (30-32: jump handlers return new ip)
    def _h_jmp():
        return _imm if _vl_flag else _imm * 8
    def _h_jmp_if_true():
        if _rd_val:
            return _imm if _vl_flag else _imm * 8
        return _S_SAME
    def _h_jmp_if_false():
        if not _rd_val:
            return _imm if _vl_flag else _imm * 8
        return _S_SAME
    def _h_binary_subscr():
        nonlocal _rd_val, _rd_modified
        _rd_val = _rs1_val[_rs2_val]
        _rd_modified = True

    # Call / Return (40-44) — complex, use _r_get/_r_set directly
    def _h_call():
        nonlocal _vm_t0
        _fn = _rs1_val
        _args = tuple(_r_get(_rr(_rs1, 1 + _i)) for _i in range(_imm & 0xFFFF))
        _r_set(_rd, _fn(*_args))
        # Reset timer after native call — prevents false timing trigger from
        # slow operations (RSA keygen, disk I/O, network, etc.) that run INSIDE
        # the native function call, making the timing check only measure actual
        # VM dispatch overhead (which is always sub-millisecond).
        _vm_t0 = _vm_tm.time()
    def _h_call_name():
        _r_set(_rd, _names[_rd](*[_r_get(_rr(_rs1, _i)) for _i in range(_imm & 0xFFFF)]))
    def _h_return_op():
        nonlocal _vm_retval
        _vm_retval = _rd_val
        return _S_EXIT
    def _h_build_tuple():
        _r_set(_rd, tuple(_r_get(_rr(_rs1, _i)) for _i in range(_rs2)))
    def _h_build_list():
        _r_set(_rd, list(_r_get(_rr(_rs1, _i)) for _i in range(_rs2)))

    # Store subscr (50)
    def _h_store_subscr():
        _rs1_val[_rs2_val] = _rd_val

    # Opaque predicates (52-53)
    def _h_opaque_true():
        try:
            if _imm == 0:
                if not (_rs1_val + 1 == _rs1_val): pass
            elif _imm == 1:
                if not (_rs1_val != _rs1_val): pass
            else:
                if not (_rs1_val - 1 == _rs1_val): pass
        except TypeError:
            pass
    def _h_opaque_false():
        try:
            if _imm == 0:
                if _rs1_val * 0 != 0: pass
            elif _imm == 1:
                if _rs1_val != _rs1_val: pass
            else:
                if _rs1_val + 1 == _rs1_val: pass
        except TypeError:
            pass

    # MAKE_FUNCTION (54)
    def _h_make_function():
        nonlocal _rd_val, _rd_modified
        _rd_val = types.FunctionType(_rs1_val, _globals)
        _rd_modified = True

    # Attribute / Import (60-63)
    def _h_load_attr():
        nonlocal _rd_val, _rd_modified
        _rd_val = _hook_getattr(_rs1_val, _names[_imm])
        _rd_modified = True
    def _h_import_name():
        nonlocal _rd_val, _rd_modified
        _rd_val = _hook_import(_names[_imm])
        _rd_modified = True
    def _h_format_simple():
        nonlocal _rd_val, _rd_modified
        _rd_val = str(_rs1_val)
        _rd_modified = True
    def _h_build_string():
        nonlocal _rd_val, _rd_modified
        _rd_val = ''.join(str(_r_get(_rr(_rs1, _i))) for _i in range(_rs2))
        _rd_modified = True

    # Iteration (70-75)
    def _h_get_iter():
        nonlocal _rd_val, _rd_modified
        _src = _rs1
        _val = _r_get(_src)
        _rd_val = iter(_val) if hasattr(_val, '__iter__') else _val
        _rd_modified = True
    def _h_for_iter():
        nonlocal _rd_val, _rd_modified
        _iter_reg = _rs1
        _it = _r_get(_iter_reg)
        try:
            _rd_val = next(_it)
            _rd_modified = True
        except StopIteration:
            return _imm if _vl_flag else _imm * 8
    def _h_list_extend():
        _rd_val.extend(_rs1_val)
    def _h_list_append():
        _rd_val.append(_rs1_val)

    # Python 3.14+ iteration cleanup (END_FOR=74, POP_ITER=76)
    def _h_end_for():
        pass
    def _h_pop_iter():
        pass

    # Indirect & Virtual Call (80-81) — complex, use _r_get/_r_set
    def _h_call_indirect():
        _fn = _rs1_val
        _argc = _imm & 0xFFFF
        _args = tuple(_r_get(_rr(_rs1, 1 + _i)) for _i in range(_argc))
        _r_set(_rd, _fn(*_args))
    def _h_call_vtable():
        _obj = _rs1_val
        _vtable = _r_get(_rr(_rs1, 1))
        _midx = _imm & 0xFFFF
        _argc = (_imm >> 16) & 0xFFFF
        _method = _vtable[_midx]
        _args = tuple(_r_get(_rr(_rs1, 2 + _i)) for _i in range(_argc))
        _r_set(_rd, _method(_obj, *_args))

    # Exception Handling (90-93) — complex, use _r_get/_r_set
    def _h_try():
        _handler_stack.append({'s': _ip, 'e': _ip + _imm, 'c': None, 't': None})
    def _h_catch():
        if _handler_stack:
            _handler_stack[-1]['t'] = _rd_val
            _handler_stack[-1]['c'] = _ip + _ilen
    def _h_throw():
        _exc = _rs1_val
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
        _t1 = (_rd_val & _rd_val) | _rd_val
        _t2 = (_t1 ^ 0) + 0
        _t3 = _t2 ^ _t2
        if _t3 == 0 and _t2:
            return _imm
        return _S_SAME
    def _h_jmp_if_false_obf():
        _t1 = _rd_val | 0
        _t2 = _t1 & _t1
        if (_t2 ^ _t2) == 0 and not _t2:
            return _imm
        return _S_SAME
    def _h_jmp_eq():
        _d = _rd_val - _rs1_val if isinstance(_rd_val, (int, float)) and isinstance(_rs1_val, (int, float)) else 1
        _o = _rd_val ^ _rd_val if isinstance(_rd_val, int) else 0
        if _o == 0 and _d == 0:
            return _imm
        return _S_SAME
    def _h_jmp_ne():
        _d = _rd_val - _rs1_val if isinstance(_rd_val, (int, float)) and isinstance(_rs1_val, (int, float)) else 1
        _m = _rd_val | 0 if isinstance(_rd_val, int) else 0
        if _m == _m and _d != 0:
            return _imm
        return _S_SAME
    def _h_jmp_lt():
        _d = _rd_val - _rs1_val if isinstance(_rd_val, (int, float)) and isinstance(_rs1_val, (int, float)) else 1
        _t = (_d ^ _d) & 0
        if _t == 0 and _d < 0:
            return _imm
        return _S_SAME
    def _h_jmp_le():
        _d = _rd_val - _rs1_val if isinstance(_rd_val, (int, float)) and isinstance(_rs1_val, (int, float)) else 1
        _o = _rs1_val ^ _rs1_val if isinstance(_rs1_val, int) else 0
        if _o == 0 and _d <= 0:
            return _imm
        return _S_SAME
    def _h_jmp_gt():
        _d = _rd_val - _rs1_val if isinstance(_rd_val, (int, float)) and isinstance(_rs1_val, (int, float)) else 1
        if (_d * 0) == 0 and _d > 0:
            return _imm
        return _S_SAME
    def _h_jmp_ge():
        _d = _rd_val - _rs1_val if isinstance(_rd_val, (int, float)) and isinstance(_rs1_val, (int, float)) else 1
        _v = _rd_val & 0xFFFFFFFF if isinstance(_rd_val, int) else 0
        if (_v ^ _v) == 0 and _d >= 0:
            return _imm
        return _S_SAME
    def _h_jmp_indirect():
        _target = _rd_val
        if isinstance(_target, int) and 0 <= _target < _n:
            return _target
        return 0
    def _h_jmp_table():
        _idx = _rd_val
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

    # Register Spilling (120-123) — complex, use _r_get/_r_set
    def _h_spill():
        # Push paired (reg, val) for consistent stack format with SPILL_MANY.
        _spill_stack.append(_rd)
        _spill_stack.append(_rd_val)
    def _h_restore():
        nonlocal _rd_val, _rd_modified
        if len(_spill_stack) >= 2:
            # Pop paired (value, reg) — SPILL_MANY pushes reg first, then val
            _val = _spill_stack.pop()
            _reg = _spill_stack.pop()
            _r_set(_reg, _val)
            # Don't set _rd_modified = True — _r_set already wrote the value.
            # Setting _rd_modified would cause the main loop to write _rd_val
            # (which is stale) back to _rd via _r_set, corrupting _rd.
        elif _spill_stack:  # legacy: single value without reg number
            _rd_val = _spill_stack.pop()
            _rd_modified = True
    def _h_spill_many():
        _mask = _imm & 0xFFFF
        for _b in range(16):
            if _mask & (1 << _b):
                # CRITICAL: Use _rr() to map through _reg_map instead of _rd + _b.
                _reg = _rr(_rd, _b)
                if _reg < 64:
                    # Push register number BEFORE value for paired restore.
                    # RESTORE_MANY will pop value first, then register number.
                    _spill_stack.append(_reg)
                    _spill_stack.append(_r_get(_reg))
                    _r_set(_reg, None)
    def _h_restore_many():
        _cnt = _imm & 0xFF
        for _ in range(min(_cnt, len(_spill_stack) // 2)):
            # Pop paired (value, reg) in reverse order
            _val = _spill_stack.pop()
            _reg = _spill_stack.pop()
            _r_set(_reg, _val)

    # SMC (130-133) — complex, keep _r_get/_r_set
    def _h_patch_instr():
        _off = _rd_val; _plen = _rs1_val; _key = _rs2_val
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
        _off = _rd_val; _plen = _rs1_val; _key = _rs2_val
        if isinstance(_off, int) and isinstance(_plen, int) and isinstance(_key, int):
            if 0 <= _off and _off + _plen <= _n and abs(_off - _ip) > 16:
                _seed = _key ^ _cycle
                _rng = (_seed * 1103515245 + 12345) & 0x7FFFFFFF
                for _i in range(_plen):
                    _rng = (_rng * 1103515245 + 12345) & 0x7FFFFFFF
                    _code[_off + _i] ^= (_rng >> 16) & 0xFF
    def _h_smc_decrypt():
        _off = _rd_val; _plen = _rs1_val; _key = _rs2_val
        if isinstance(_off, int) and isinstance(_plen, int) and isinstance(_key, int):
            if 0 <= _off and _off + _plen <= _n and abs(_off - _ip) > 16:
                _seed = _key ^ _cycle
                _rng = (_seed * 1103515245 + 12345) & 0x7FFFFFFF
                for _i in range(_plen):
                    _rng = (_rng * 1103515245 + 12345) & 0x7FFFFFFF
                    _code[_off + _i] ^= (_rng >> 16) & 0xFF

    # Data Obfuscation (140-142)
    def _h_obf_move():
        nonlocal _rd_val, _rd_modified
        _rd_val = (_rs1_val ^ _rs1_val) & 0 | _rs1_val
        _rd_modified = True
    def _h_obf_add():
        nonlocal _rd_val, _rd_modified
        _v = _rs1_val + _rs2_val
        _m = _rs1_val ^ _rs2_val
        _rd_val = _v + _m - _m
        _rd_modified = True
    def _h_obf_xor():
        nonlocal _rd_val, _rd_modified
        if isinstance(_rs1_val, int) and isinstance(_rs2_val, int):
            _rd_val = (_rs1_val | _rs2_val) - (_rs1_val & _rs2_val) + (_rs1_val & _rs2_val) - (_rs1_val | _rs2_val) + (_rs1_val ^ _rs2_val)
        else:
            _rd_val = _rs1_val
        _rd_modified = True

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
        nonlocal _rd_val, _rd_modified
        _rd_val = _consts[_imm]
        _rd_modified = True

    # Data structures (161-172) — many complex, use _r_get/_r_set for indirect
    def _h_binary_slice():
        nonlocal _rd_val, _rd_modified
        _obj = _rs1_val; _start = _rs2_val
        # NOTE: _imm stores raw register for stop; decode by mapping through _reg_map
        _stop_raw = _imm & 0x3F
        _stop = _r_get(_reg_map[_stop_raw]) if _stop_raw < 64 else _rd_val
        try:
            _rd_val = _obj[_start:_stop]
        except Exception as _e:
            raise _e
        _rd_modified = True
    def _h_delete_subscr():
        _obj = _rs1_val; _key = _rs2_val
        try:
            del _obj[_key]
        except Exception as _e:
            raise _e
    def _h_store_slice():
        _val = _rd_val; _obj = _rs1_val; _start = _rs2_val
        # NOTE: _imm stores raw register for stop; decode by mapping through _reg_map
        _stop_raw = _imm & 0x3F
        _stop = _r_get(_reg_map[_stop_raw]) if _stop_raw < 64 else None
        try:
            if _stop is not None:
                _obj[_start:_stop] = _val
            else:
                _obj[_start:] = _val
        except Exception as _e:
            raise _e
    def _h_build_map():
        nonlocal _rd_val, _rd_modified
        _cnt = _rs2 & 0xFFFF; _d = {}
        for _i in range(_cnt):
            # Items were moved to sequential raw indices starting at rd+1:
            # [key0, val0, key1, val1, ...] at [rd+1, rd+2, rd+3, rd+4, ...]
            # Use offset 1 (not 0) because offset 0 is the BUILD_MAP dest register itself
            _key_off = _rr(_rd, 1 + _i * 2)
            _val_off = _rr(_rd, 1 + _i * 2 + 1)
            _d[_r_get(_key_off)] = _r_get(_val_off)
        _rd_val = _d
        _rd_modified = True
    def _h_build_set():
        nonlocal _rd_val, _rd_modified
        _cnt = _rs2 & 0xFFFF; _s = set()
        for _i in range(_cnt):
            _s.add(_r_get(_rr(_rd, _i + 1)))
        _rd_val = _s
        _rd_modified = True
    def _h_build_slice():
        nonlocal _rd_val, _rd_modified
        _start = _rs1_val; _stop = _rs2_val
        # _imm[0:6] = step register, _imm[6:8] = arg count
        _step_raw = _imm & 0x3F
        _arg_cnt = (_imm >> 6) & 0x3
        _step = _r_get(_reg_map[_step_raw]) if _step_raw < 64 and _arg_cnt >= 3 else None
        from builtins import slice as _slice
        _rd_val = _slice(_start, _stop, _step)
        _rd_modified = True
    def _h_copy():
        nonlocal _rd_val, _rd_modified
        _v = _rs1_val
        try:
            _rd_val = _v.copy() if hasattr(_v, 'copy') else _v[:] if hasattr(_v, '__getitem__') else _v
        except Exception:
            _rd_val = _v
        _rd_modified = True
    def _h_dict_merge():
        _d = _rd_val; _o = _rs1_val
        if isinstance(_d, dict) and isinstance(_o, dict):
            _d.update(_o)
    def _h_dict_update():
        _d = _rd_val; _o = _rs1_val
        if isinstance(_d, dict):
            _d.update(_o)
    def _h_map_add():
        _d = _rd_val; _k = _rs1_val; _v = _rs2_val
        if isinstance(_d, dict):
            _d[_k] = _v
    def _h_set_add():
        _s = _rd_val; _item = _rs1_val
        if isinstance(_s, set):
            _s.add(_item)
    def _h_set_update():
        _s = _rd_val; _other = _rs1_val
        if isinstance(_s, set):
            _s.update(_other)

    # Iterator / Generator / Async (180-195)
    def _h_get_aiter():
        nonlocal _rd_val, _rd_modified
        _rd_val = _rs1_val.__aiter__()
        _rd_modified = True
    def _h_get_anext():
        nonlocal _rd_val, _rd_modified
        _rd_val = _rs1_val.__anext__()
        _rd_modified = True
    def _h_get_yield_from_iter():
        nonlocal _rd_val, _rd_modified
        _obj = _rs1_val
        try:
            _rd_val = _obj.__iter__()
        except AttributeError:
            _rd_val = iter(_obj)
        _rd_modified = True
    def _h_load_build_class():
        nonlocal _rd_val, _rd_modified
        _rd_val = _b['__build_class__']
        _rd_modified = True
    def _h_return_generator():
        nonlocal _rd_val, _rd_modified
        _fn = _rs1_val
        if callable(_fn):
            _rd_val = _fn()
        else:
            _rd_val = None
        _rd_modified = True
    def _h_delete_deref():
        _nm = _names[_imm] if _imm < len(_names) else None
        if _nm and _nm in _locals:
            del _locals[_nm]
    def _h_get_awaitable():
        nonlocal _rd_val, _rd_modified
        _obj = _rs1_val
        _rd_val = _obj.__await__() if hasattr(_obj, '__await__') else _obj
        _rd_modified = True
    def _h_load_deref():
        nonlocal _rd_val, _rd_modified
        _nm = _names[_imm] if _imm < len(_names) else None
        _v = _locals.get(_nm) if _nm else None
        if _v is None:
            _v = _globals.get(_nm) if _nm else None
        _rd_val = _v
        _rd_modified = True
    def _h_make_cell():
        nonlocal _rd_val, _rd_modified
        _v = _rs1_val
        try:
            _rd_val = (lambda _x: lambda: _x)(_v).__closure__[0]
        except Exception:
            _rd_val = _v
        _rd_modified = True
    def _h_send():
        nonlocal _rd_val, _rd_modified
        _gen = _rs1_val; _val = _rs2_val
        try:
            _rd_val = _gen.send(_val)
            _rd_modified = True
        except StopIteration:
            return _imm if _vl_flag else _imm * 8
    def _h_store_deref():
        _nm = _names[_imm] if _imm < len(_names) else None
        if _nm:
            _locals[_nm] = _rd_val
    def _h_yield_value():
        nonlocal _rd_val, _rd_modified
        _rd_val = _rs1_val
        _rd_modified = True
        return _ip + _ilen
    def _h_load_closure():
        nonlocal _rd_val, _rd_modified
        _nm = _names[_imm] if _imm < len(_names) else None
        _v = _locals.get(_nm) if _nm else _globals.get(_nm) if _nm else None
        _rd_val = _v
        _rd_modified = True

    # Exception handling advanced (200-210) — complex, keep _r_get/_r_set for most
    def _h_check_eg_match():
        nonlocal _rd_val, _rd_modified
        _exc = _rs1_val; _mt = _rs2_val
        try:
            _rd_val = isinstance(_exc, _mt) if isinstance(_mt, type) else False
        except Exception:
            _rd_val = False
        _rd_modified = True
    def _h_check_exc_match():
        nonlocal _rd_val, _rd_modified
        _ev = _rs1_val; _ht = _rd_val
        _m = False
        if isinstance(_ht, type) and isinstance(_ev, BaseException):
            _m = isinstance(_ev, _ht)
        elif isinstance(_ht, tuple):
            _m = isinstance(_ev, _ht)
        _rd_val = _m
        _rd_modified = True
    def _h_pop_except():
        if _exc_stack:
            _exc_stack.pop()
    def _h_push_exc_info():
        _exc_stack.append(_rd_val)
    def _h_with_except_start():
        nonlocal _rd_val, _rd_modified
        _ctx = _rs1_val
        _typ, _val, _tb = sys.exc_info()
        try:
            _rd_val = _ctx.__exit__(_typ, _val, _tb)
        except Exception:
            _rd_val = False
        _rd_modified = True
    def _h_reraise():
        _exc = _rd_val
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
        nonlocal _rd_val, _rd_modified
        _ctx = _rs1_val
        try:
            _handler_stack.append({'s': _ip, 'e': _n, 'c': _imm, 't': BaseException})
            _rd_val = _ctx.__enter__()
        except Exception as _e:
            raise _e
        _rd_modified = True

    # Pattern matching (220-223)
    def _h_match_keys():
        nonlocal _rd_val, _rd_modified
        _sj = _rs1_val; _ks = _rs2_val
        if isinstance(_sj, dict) and hasattr(_ks, '__iter__'):
            if all(_k in _sj for _k in _ks):
                _rd_val = tuple(_sj[_k] for _k in _ks)
            else:
                _rd_val = None
        else:
            _rd_val = None
        _rd_modified = True
    def _h_match_mapping():
        nonlocal _rd_val, _rd_modified
        _sj = _rs1_val
        _rd_val = _hook_isinstance(_sj, dict) or _hook_hasattr(_sj, 'keys')
        _rd_modified = True
    def _h_match_sequence():
        nonlocal _rd_val, _rd_modified
        _sj = _rs1_val; _ml = _imm & 0xFFFF
        _rd_val = _hook_isinstance(_sj, (list, tuple)) and _hook_len(_sj) >= _ml
        _rd_modified = True
    def _h_match_class():
        nonlocal _rd_val, _rd_modified
        _sj = _rs1_val; _cn = _names[_imm] if _imm < len(_names) else None; _na = _rs2 & 0xFF
        _m = False
        if _cn is not None:
            _cls = _globals.get(_cn) or _b.get(_cn)
            if _cls is not None and isinstance(_sj, _cls):
                _m = True
        _rd_val = _m
        _rd_modified = True

    # Control flow 3.14+ (230-235: jump handlers return ip)
    # Uses shared handlers: _h_nop (230), _h_jmp (231,232,235), _h_jmp_if_false (233), _h_jmp_if_true (234)

    # Attribute ops (240-242)
    def _h_delete_attr():
        _obj = _rd_val; _attr = _names[_imm] if _imm < len(_names) else None
        if _obj is not None and _attr is not None:
            try:
                delattr(_obj, _attr)
            except AttributeError as _e:
                raise _e
    def _h_load_super_attr():
        nonlocal _rd_val, _rd_modified
        _attr = _names[_imm] if _imm < len(_names) else None
        try:
            _rd_val = _hookobject_getattribute(_rs2_val, _attr) if _attr else None
        except Exception:
            _rd_val = _hook_getattr(_rs2_val, _attr) if _attr else None
        _rd_modified = True
    def _h_store_attr():
        _val = _rd_val; _obj = _rs1_val; _attr = _names[_imm] if _imm < len(_names) else None
        if _obj is not None and _attr is not None:
            _hook_setattr(_obj, _attr, _val)

    # Call variants (245-248) — complex, use _r_get/_r_set
    def _h_call_function_ex():
        _fn = _rs1_val; _args = _rs2_val if _rs2 < 64 else (); _fl = _imm & 0xFF
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
        nonlocal _rd_val, _rd_modified
        _v = _rs1_val; _ix = _imm & 0xFF
        if _ix == 0: _rd_val = None
        elif _ix == 1: _rd_val = _v is None
        elif _ix == 2: _rd_val = bool(_v) if _v is not None else False
        elif _ix == 3: _rd_val = len(_v)
        elif _ix == 4: _rd_val = str(_v)
        elif _ix == 5: _rd_val = repr(_v)
        elif _ix == 6: _rd_val = ascii(_v)
        elif _ix == 7: _rd_val = bool(_v)
        elif _ix == 8: _rd_val = _v.__order__() if _hook_hasattr(_v, '__order__') else _v
        else: _rd_val = _v
        _rd_modified = True
    def _h_call_intrinsic_2():
        nonlocal _rd_val, _rd_modified
        _v1 = _rs1_val; _v2 = _rs2_val; _ix = _imm & 0xFF
        if _ix == 0: _rd_val = None
        elif _ix == 1: _rd_val = _v1 == _v2
        elif _ix == 2: _rd_val = _v1 != _v2
        elif _ix == 3: _rd_val = _hook_isinstance(_v1, _v2) if _hook_isinstance(_v2, type) else False
        elif _ix == 4: _rd_val = _hook_issubclass(_v1, _v2) if _hook_isinstance(_v1, type) and _hook_isinstance(_v2, type) else False
        elif _ix == 5:
            try: _rd_val = _v2 in _v1
            except Exception: _rd_val = False
        elif _ix == 6:
            try: _rd_val = _v2 not in _v1
            except Exception: _rd_val = True
        elif _ix == 7: _rd_val = _v1 ** _v2
        elif _ix == 8: _rd_val = divmod(_v1, _v2)
        else: _rd_val = None
        _rd_modified = True
    def _h_call_kw():
        nonlocal _vm_t0
        _fn = _rs1_val; _nr = _rs2; _ac = _imm & 0xFFFF
        if not callable(_fn):
            sys.stderr.write(f'[KW FATAL] _fn={repr(_fn)[:60]} type={_hook_type(_fn).__name__} rs1={_rs1} nr={_nr}\n')
            sys.stderr.write(f'[KW FATAL] reg_map={_reg_map}\n')
            # Show write history for the function register
            _hst = _vm_reg_history[_rs1]
            _op_name_h = {1:'LDC',2:'LDN',3:'STN',4:'LDF',5:'STF',6:'MOV',7:'INV',8:'NOT',
                        10:'ADD',11:'SUB',12:'MUL',13:'DIV',30:'JMP',31:'JMT',32:'JMF',
                        33:'SUB',40:'CAL',42:'RET',43:'TUP',44:'LST',50:'SBS',
                        54:'MKF',60:'LDA',61:'IMP',62:'FMT',63:'BST',70:'ITR',
                        71:'FOR',72:'LEX',75:'LAP',110:'CVT',111:'LCC',112:'LSP',
                        114:'TPL',117:'FWS',119:'LEN',125:'BIN',126:'CTN',127:'ISO',
                        128:'LFC',134:'SFL',135:'SFS',136:'UPX',137:'UNP',138:'ENT',
                        139:'SFN',161:'BSL',163:'STS',164:'MAP',165:'SET',166:'SLI',
                        167:'CPY',170:'MAD',171:'SAD',172:'SUP',190:'LDR',191:'MKC',
                        192:'SND',193:'SDR',194:'YLD',195:'LDC',
                        220:'MKY',221:'MMP',222:'MSQ',223:'MCL',
                        240:'DAT',241:'LSA',242:'STA',245:'CFX',246:'CI1',247:'CI2',
                        248:'KW ',250:'DLF',251:'DLG',252:'DLN',253:'LFD',254:'LFG'}.get(_hst[4], f'{_hst[4]:3d}')
            sys.stderr.write(f'[KW FATAL] r{_rs1} last_write: cycle={_hst[0]} op={_op_name_h} rd={_hst[1]} rs1={_hst[2]} rs2={_hst[3]}\n')
            # Also show history for argument registers
            for _hi in range(_ac):
                _raw = _reg_map.index(_rs1)
                _arg_r = _reg_map[_raw + 1 + _hi] if _raw + 1 + _hi < 64 else -1
                if 0 <= _arg_r < 64:
                    _ah = _vm_reg_history[_arg_r]
                    _an = {1:'LDC',2:'LDN',3:'STN',4:'LDF',5:'STF',6:'MOV'}.get(_ah[4], f'{_ah[4]:3d}')
                    sys.stderr.write(f'[KW FATAL] r{_arg_r}(arg{_hi}) last_write: cycle={_ah[0]} op={_an} rd={_ah[1]} rs1={_ah[2]} rs2={_ah[3]}\n')
            sys.stderr.flush()
        _nt = _r_get(_nr) if _nr < 64 else None
        _kwn = _nt if _hook_isinstance(_nt, tuple) else ()
        _num_kw = _hook_len(_kwn)
        _num_pos = _ac - _num_kw
        _pa = []; _ka = {}
        for _i in range(_ac):
            _av = _r_get(_rr(_rs1, 1 + _i))
            if _i >= _num_pos:
                _ka[_kwn[_i - _num_pos]] = _av
            else:
                _pa.append(_av)
        if _vm_debug:
            _fn_name = _hook_getattr(_fn, '__name__', str(_fn))[:40]
            sys.stderr.write(f'[dbg KW REGS] rs1={_rs1}, _rr(rs1,1)={_rr(_rs1,1)} val={repr(_r_get(_rr(_rs1,1)))[:40]}\n')
            sys.stderr.write(f'[dbg KW REGS] _rr(rs1,2)={_rr(_rs1,2)} val={repr(_r_get(_rr(_rs1,2)))[:40]}\n')
            sys.stderr.write(f'[dbg KW REGS] _rr(rs1,3)={_rr(_rs1,3)} val={repr(_r_get(_rr(_rs1,3)))[:40]}\n')
            sys.stderr.write(f'[dbg KW DBG] nr={_nr} val={repr(_nt)[:40]}\n')
            _par = ', '.join(repr(x)[:40] for x in _pa)
            _kar = ', '.join(f'{k}={repr(v)[:30]}' for k, v in _ka.items())
            sys.stderr.write(f'[dbg KW DBG] {_fn_name}({_par}, {_kar})\n')
        try:
            _r_set(_rd, _fn(*_pa, **_ka))
            # Reset timer after native call
            _vm_t0 = _vm_tm.time()
        except Exception as _e:
            if _vm_debug:
                sys.stderr.write(f'[dbg KW ERR] {_e}\n')
                sys.stderr.write(f'[dbg KW ERR] _pa[0] type={_hook_type(_pa[0]).__name__}, len={_hook_len(_pa[0]) if _hook_hasattr(_pa[0], "__len__") else "N/A"}, repr={repr(_pa[0])[:80]}\n')
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
        nonlocal _rd_val, _rd_modified
        _d = _rs1_val; _nm = _names[_imm] if _imm < len(_names) else None
        _v = _locals.get(_nm) if _nm else None
        if _v is None and isinstance(_d, dict) and _nm:
            _v = _d.get(_nm)
        if _v is None and _nm:
            _v = _globals.get(_nm) or _b.get(_nm)
        _rd_val = _v
        _rd_modified = True
    def _h_load_from_dict_or_globals():
        nonlocal _rd_val, _rd_modified
        _d = _rs1_val; _nm = _names[_imm] if _imm < len(_names) else None
        _v = _globals.get(_nm) if _nm else None
        if _v is None and isinstance(_d, dict) and _nm:
            _v = _d.get(_nm)
        if _v is None and _nm:
            _v = _b.get(_nm)
        _rd_val = _v
        _rd_modified = True

    # Misc: Convert, Common Constant, Special, Annotations (110-113)
    def _h_convert_value():
        nonlocal _rd_val, _rd_modified
        _v = _rs1_val; _conv = _imm & 0xFF
        if _conv == 0: _rd_val = str(_v)
        elif _conv == 1: _rd_val = repr(_v)
        elif _conv == 2: _rd_val = ascii(_v)
        elif _conv == 3: _rd_val = bool(_v)
        elif _conv == 4: _rd_val = int(_v) if _v is not None else 0
        elif _conv == 5: _rd_val = float(_v) if _v is not None else 0.0
        else: _rd_val = _v
        _rd_modified = True
    def _h_load_common_constant():
        nonlocal _rd_val, _rd_modified
        _cc = _imm & 0xFF
        if _cc == 0: _rd_val = None
        elif _cc == 1: _rd_val = True
        elif _cc == 2: _rd_val = False
        elif _cc == 3: _rd_val = 0
        elif _cc == 4: _rd_val = 1
        elif _cc == 5: _rd_val = ''
        elif _cc == 6: _rd_val = ()
        elif _cc == 7: _rd_val = 0.0
        elif _cc == 8: _rd_val = Ellipsis
        elif _cc == 9: _rd_val = NotImplemented
        else: _rd_val = None
        _rd_modified = True
    def _h_load_special():
        nonlocal _rd_val, _rd_modified
        _obj = _rs1_val; _attr = _names[_imm] if _imm < len(_names) else None
        if _attr is not None:
            try:
                _rd_val = getattr(_obj, _attr)
            except AttributeError:
                _rd_val = None
        else:
            _rd_val = None
        _rd_modified = True
    def _h_annotations_placeholder():
        nonlocal _rd_val, _rd_modified
        _rd_val = None
        _rd_modified = True

    # Misc ops (114-119, 124-129, 134-139)
    def _h_build_template():
        nonlocal _rd_val, _rd_modified
        _cnt = _rs2 & 0xFFFF; _parts = []
        for _i in range(_cnt):
            _parts.append(str(_r_get(_rr(_rd, 1 + _i))) if _r_get(_rr(_rd, 1 + _i)) is not None else 'None')
        _rd_val = ''.join(_parts)
        _rd_modified = True
    def _h_format_with_spec():
        nonlocal _rd_val, _rd_modified
        _v = _rs1_val; _fmt = _rs2_val
        if isinstance(_fmt, str) and _fmt:
            try:
                _rd_val = format(_v, _fmt)
            except Exception:
                _rd_val = str(_v)
        else:
            _rd_val = format(_v, '') if hasattr(_v, '__format__') else str(_v)
        _rd_modified = True
    def _h_get_len():
        nonlocal _rd_val, _rd_modified
        _v = _rs1_val
        try:
            _rd_val = len(_v)
        except Exception:
            _rd_val = 0
        _rd_modified = True
    def _h_interpreter_exit():
        sys.exit(0)
    def _h_build_interpolation():
        nonlocal _rd_val, _rd_modified
        _cnt = _rs2 & 0xFFFF; _parts = []
        for _i in range(_cnt):
            _parts.append(str(_r_get(_rr(_rd, 1 + _i))) if _r_get(_rr(_rd, 1 + _i)) is not None else 'None')
        _rd_val = ''.join(_parts)
        _rd_modified = True
    def _h_contains_op():
        nonlocal _rd_val, _rd_modified
        _item = _rs1_val; _seq = _rs2_val; _inv = _imm & 0xFF
        try:
            _r = _item in _seq
            _rd_val = not _r if _inv else _r
        except Exception:
            _rd_val = False
        _rd_modified = True
    def _h_is_op():
        nonlocal _rd_val, _rd_modified
        _v1 = _rs1_val; _v2 = _rs2_val; _inv = _imm & 0xFF
        _r = _v1 is _v2
        _rd_val = not _r if _inv else _r
        _rd_modified = True
    def _h_load_fast_check():
        nonlocal _rd_val, _rd_modified
        _nm = _names[_imm] if _imm < len(_names) else None
        _v = _locals.get(_nm) if _nm else None
        if _v is None and _nm is not None and _nm not in _locals:
            raise UnboundLocalError(f"local variable '{_nm}' referenced before assignment")
        _rd_val = _v
        _rd_modified = True
    def _h_raise_varargs():
        _exc = _rd_val; _cause = _rs1_val; _argc = _imm & 0xFF
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
        nonlocal _rd_val, _rd_modified
        _nm = _names[_imm] if _imm < len(_names) else None
        _v = _rs1_val
        if _nm:
            _locals[_nm] = _v
        _rd_val = _v
        _rd_modified = True
    def _h_store_fast_store_fast():
        _nm = _names[_imm] if _imm < len(_names) else None
        if _nm:
            _locals[_nm] = _rd_val
    def _h_unpack_ex():
        _nb = _imm & 0xFFFF; _na = _rs2 & 0xFF; _seq = _rs1_val
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
            _r_set(_rr(_rd, len(_res) - 1 - _i), _v)
    def _h_unpack_sequence():
        _cnt = _imm & 0xFFFF; _seq = _rs1_val
        if len(_seq) != _cnt:
            raise ValueError(f"cannot unpack {len(_seq)} values into {_cnt} targets")
        if _vm_debug:
            import sys
            print(f'[vm UNPACK] seq[0]= {repr(_seq[0])[:60]}', file=sys.stderr)
            print(f'[vm UNPACK] seq[1]= {repr(_seq[1])[:60]}', file=sys.stderr)
            print(f'[vm UNPACK] rd={_rd}, _rr(rd,0)={_rr(_rd,0)}, _rr(rd,1)={_rr(_rd,1)}', file=sys.stderr)
        for _i in range(_cnt):
            _r_set(_rr(_rd, _cnt - 1 - _i), _seq[_i])
        if _vm_debug:
            import sys
            print(f'[vm UNPACK] after: r{_rr(_rd,0)}={repr(_r_get(_rr(_rd,0)))[:60]}', file=sys.stderr)
            print(f'[vm UNPACK] after: r{_rr(_rd,1)}={repr(_r_get(_rr(_rd,1)))[:60]}', file=sys.stderr)
    def _h_enter_executor():
        nonlocal _rd_val, _rd_modified
        _er = _rs1_val
        _rd_val = _er.__enter__() if hasattr(_er, '__enter__') else _er
        _rd_modified = True
    def _h_store_fast_maybe_null():
        _nm = _names[_imm] if _imm < len(_names) else None
        if _nm:
            _locals[_nm] = _rd_val

    # ─── Virtual RAM handlers ───
    def _h_ram_load_b():
        nonlocal _rd_val, _rd_modified
        _rd_val = _vm_ram_read(_rs1_val)
        _rd_modified = True
    def _h_ram_store_b():
        _vm_ram_write(_rs2_val, _rd_val & 0xFF)
    def _h_ram_load_w():
        nonlocal _rd_val, _rd_modified
        _rd_val = _vm_ram_read_w(_rs1_val)
        _rd_modified = True
    def _h_ram_store_w():
        _vm_ram_write_w(_rs2_val, _rd_val & 0xFFFFFFFF)
    def _h_ram_garble():
        nonlocal _VM_RAM_KEY
        _nk = bytes(_vm_os.urandom(16))
        for _pi, _pg in _VM_RAM_PAGES.items():
            _base = _pi * _VM_PAGE_SIZE
            for _vi in range(len(_pg)):
                _a = _base + _vi
                _pg[_vi] ^= (_VM_RAM_KEY[_a & 15] & 0xFF) ^ (_nk[_a & 15] & 0xFF)
        _VM_RAM_KEY = _nk

    # ─── Debug: log CALL (40) and MOVE (6) when env VM_DEBUG=1 ───
    _vm_debug = 'VM_DEBUG' in _vm_os.environ
    _vm_critical_regs = set()  # track specific runtime registers for corruption detection
    # When VM_CRITICAL_REGS is set, comma-separated list of runtime regs to watch
    _vm_crit_env = _vm_os.environ.get('VM_CRITICAL_REGS', '')
    if _vm_crit_env:
        try:
            _vm_critical_regs = set(int(x.strip()) for x in _vm_crit_env.split(',') if x.strip())
        except ValueError:
            _vm_critical_regs = set()
    # ─── Register Write History ───
    # Tracks the last write to each runtime register: (cycle, rd, rs1, op)
    _vm_reg_history = [(-1, -1, -1, -1, 'INIT')] * 64  # (cycle, rd, rs1, rs2, op_name)
    # When VM_TRACE_REG is set, dump all writes to that runtime register to stderr
    _vm_trace_reg = -1
    _vm_trace_env = _vm_os.environ.get('VM_TRACE_REG', '')
    if _vm_trace_env:
        try:
            _vm_trace_reg = int(_vm_trace_env.strip())
        except ValueError:
            _vm_trace_reg = -1

# Security: refuse to run if debug env vars that leak VM internals are detected
    _vm_sec_envs = (
        # VM-specific debug (these directly leak VM internals)
        'VM_DEBUG', 'VM_CRITICAL_REGS', 'VM_TRACE_REG', 'VM_TRACE_ALL',
        # Python debug that exposes internals
        'PYTHONTRACEMAKES', 'PYTHONDUMPREFS', 'PYTHONMALLOCSTATS',
        # System loader debug (can reveal loaded libraries/code)
        'LD_DEBUG', 'LD_AUDIT',
    )
    for _ev in _vm_sec_envs:
        if _ev in _vm_os.environ:
            sys.exit(1)

    # ─── Anti-Hook Integrity Check ───
    # Verify cached builtins weren't replaced after import
    _hook_check_getattr = getattr
    _hook_check_setattr = setattr
    _hook_check_import = __import__
    if (_hook_check_getattr is not _hook_getattr or
        _hook_check_setattr is not _hook_setattr or
        _hook_check_import is not _hook_import):
        sys.exit(1)

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
    _dt[74] = _h_end_for
    _dt[75] = _h_list_append
    _dt[76] = _h_pop_iter
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
    # Virtual RAM opcodes (143-147) — only register if vRAM enabled
    if _vram_flag:
        _dt[143] = _h_ram_load_b
        _dt[144] = _h_ram_store_b
        _dt[145] = _h_ram_load_w
        _dt[146] = _h_ram_store_w
        _dt[147] = _h_ram_garble
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
    for _di in range(len(_dt)):
        if _dt[_di] is None:
            _dt[_di] = _h_nop

    # ═══════════════════════════════════════════════════════════
    # MAIN DISPATCH LOOP
    # ═══════════════════════════════════════════════════════════
    _dispatch_state = 0
    while _ip < _n:
        _cycle += 1

        # Anti-debug: timing check (threshold high enough to avoid false triggers
        # from slow native calls like RSA key generation)
        if _cycle % _vm_timing_interval == 0:
            if _vm_tm.time() - _vm_t0 > 10.0:
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

        # ─── Pre-read cached register values ───
        _rd_val = _r_get(_rd)
        _rs1_val = _r_get(_rs1)
        if _rs2 < 64:
            _rs2_val = _r_get(_rs2)
        else:
            _rs2_val = None
        _rd_modified = False

        # ─── Debug: log ALL opcodes with register values ───
        if _vm_debug:
            import sys
            _rdr = repr(_rd_val)[:30] if _rd_val is not None else 'N'
            _r1r = repr(_rs1_val)[:30] if _rs1_val is not None else 'N'
            _r2r = repr(_rs2_val)[:30] if _rs2_val is not None else 'N'
            _op_name = {1:'LDC',2:'LDN',3:'STN',4:'LDF',5:'STF',6:'MOV',7:'INV',8:'NOT',
                        10:'ADD',11:'SUB',12:'MUL',13:'DIV',30:'JMP',31:'JMT',32:'JMF',
                        33:'SUB',40:'CAL',42:'RET',43:'TUP',44:'LST',50:'SBS',
                        54:'MKF',60:'LDA',61:'IMP',62:'FMT',63:'BST',70:'ITR',
                        71:'FOR',72:'LEX',75:'LAP',110:'CVT',111:'LCC',112:'LSP',
                        114:'TPL',117:'FWS',119:'LEN',125:'BIN',126:'CTN',127:'ISO',
                        128:'LFC',134:'SFL',135:'SFS',136:'UPX',137:'UNP',138:'ENT',
                        139:'SFN',161:'BSL',164:'MAP',165:'SET',166:'SLI',167:'CPY',
                        190:'LDR',191:'MKC',192:'SND',193:'SDR',194:'YLD',195:'LDC',
                        220:'MKY',221:'MMP',222:'MSQ',223:'MCL',
                        240:'DAT',241:'LSA',242:'STA',245:'CFX',246:'CI1',247:'CI2',
                        248:'KW ',250:'DLF',251:'DLG',252:'DLN',253:'LFD',254:'LFG'}.get(_op, f'{_op:3d}')
            if _rd_modified or _op == 3 or _op in (2, 40, 137, 248):
                print(f'[dbg {_cycle:4d}] {_op_name} rd={_rd:2d}({_rdr}) rs1={_rs1:2d}({_r1r}) rs2={_rs2:2d}({_r2r}) imm={_imm}', file=sys.stderr)
            if _op == 40 and _rs1_val is not None:
                _fn_name = getattr(_rs1_val, '__name__', str(_rs1_val))[:35]
                print(f'[dbg {_cycle:4d}]   => CALL {_fn_name} argc={_imm}', file=sys.stderr)
                for _ai in range(_imm & 0xFFFF):
                    _av = _r_get(_rr(_rs1, 1 + _ai))
                    _avr = repr(_av)[:35] if _av is not None else 'N'
                    _ar = _rr(_rs1, 1 + _ai)
                    print(f'[dbg {_cycle:4d}]   => arg[{_ai}] = r{_ar:2d} = {_avr}', file=sys.stderr)
            if _op == 137 and _rs1_val is not None:
                _seq_len = len(_rs1_val) if hasattr(_rs1_val, '__len__') else -1
                print(f'[dbg {_cycle:4d}]   => UNPACK seq(len={_seq_len})={repr(_rs1_val)[:60]}', file=sys.stderr)

        # O(1) dispatch via lookup table (vs O(n) if-elif chain)
        # Handlers return: _S_EXIT (exit), int (new ip for jumps),
        # _S_SAME or None (normal flow — ip += ilen)
        _new_ip = _dt[_op]()

        # ─── Post-writeback: if handler modified rd, write it back ───
        if _rd_modified:
            _r_set(_rd, _rd_val)

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
    _count_ops = frozenset((43, 44, 63, 114, 125, 136, 137, 164, 165))
    _rs2 = _rs2_u if _op in _count_ops else _rm[_rs2_u]
    _imm = _dec[4] | (_dec[5] << 8) | (_dec[6] << 16) | (_dec[7] << 24)
    return _op, _rd, _rs1, _rs2, _imm, 8, _rs2_u

def _vm_deserialize(_data):
    import struct
    _op_key = _data[:32]
    _decrypted = _data[32:]
    _len = len(_decrypted)
    
    # ─── Detect format: check for VM header magic "VM\x01\x00" ───
    _has_hdr = False
    _off_opmap = 0
    _off_consts = 0
    _off_names = 0
    _off_code = 0
    if _len >= 4:
        _magic = int.from_bytes(_decrypted[0:4], 'little')
        if _magic == 0x0001564D:  # "VM\x01\x00"
            _has_hdr = True
            # Parse 32-byte VM header
            _hdr_flags = int.from_bytes(_decrypted[4:8], 'little')
            _ep = int.from_bytes(_decrypted[8:12], 'little')
            _off_consts = int.from_bytes(_decrypted[12:16], 'little')
            _off_names  = int.from_bytes(_decrypted[16:20], 'little')
            _off_code   = int.from_bytes(_decrypted[20:24], 'little')
            _off_opmap  = int.from_bytes(_decrypted[24:28], 'little')
            # _total_sz = int.from_bytes(_decrypted[28:32], 'little')
            _flags = _hdr_flags
        else:
            # Legacy: first 256 bytes = opcode_map, then 4 bytes = flags
            _off_opmap = 0
            _off_consts = 0  # computed below
            _flags = int.from_bytes(_decrypted[256:260], 'little')
    
    _vl_flag = (_flags & 1) != 0
    _poly_flag = (_flags & 8) != 0
    _vram_flag = (_flags & 32) != 0
    _vram_size = ((_flags >> 6) & 0x3FF) * 256
    if _vram_size == 0:
        _vram_size = 4096  # default fallback
    _const_enc = (_flags & 2) != 0
    _cfi_flag = (_flags & 4) != 0
    
    _map = list(_decrypted[_off_opmap:_off_opmap+256])
    
    # Compute section positions based on format
    if _has_hdr:
        # Header already gives offsets. Compute intermediate sections.
        _pos = _off_consts  # start reading consts
    else:
        # Legacy sequential layout after opcode_map
        _pos = 260  # after opcode_map(256) + flags(4)
        _off_consts = _pos
        # Skip const_key if encrypted
        if _const_enc:
            _const_key = _decrypted[_pos:_pos+16]; _pos += 16
        # Skip CFI table if present
        if _cfi_flag:
            _cfi_nb = int.from_bytes(_decrypted[_pos:_pos+4], 'little'); _pos += 4
            for _ in range(_cfi_nb):
                _pos += 12  # skip start(4) + len(4) + csum(4)
        _off_consts = _pos
    
    # Read constant encryption key if present
    _const_key = None
    if _const_enc:
        if _has_hdr:
            # Const key is right before consts (after opmap + flags + CFI if any)
            # Compute: opmap ends, then 4 bytes flags, then const_key(16), then CFI, then consts
            # So const_key = _off_consts - (CFI_size + 16) if CFI present, else _off_consts - 16
            # Simpler: const_key starts at _off_opmap + 256 + 4 (right after opmap+flags)
            _ck_start = _off_opmap + 256 + 4
            if _ck_start + 16 <= _len:
                _const_key = _decrypted[_ck_start:_ck_start+16]
        else:
            # Already read above during sequential scan
            pass
    
    # ─── Constants ───
    _pos = _off_consts
    _cc = int.from_bytes(_decrypted[_pos:_pos+4], 'little'); _pos += 4
    _consts = []
    for _ in range(_cc):
        _t = _decrypted[_pos]; _pos += 1
        _sl = int.from_bytes(_decrypted[_pos:_pos+4], 'little'); _pos += 4
        _s = _decrypted[_pos:_pos+_sl]; _pos += _sl
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
        elif _t == 6 or _t == 8:
            try:
                _v = eval(_s.decode('utf-8'))
            except (SyntaxError, NameError, TypeError, ValueError):
                _v = _s
        else: _v = _s
        _consts.append(_v)
    
    # ─── Names ───
    if _has_hdr:
        _pos = _off_names
    _nc = int.from_bytes(_decrypted[_pos:_pos+4], 'little'); _pos += 4
    _names = []
    for _ in range(_nc):
        _nl = int.from_bytes(_decrypted[_pos:_pos+2], 'little'); _pos += 2
        _names.append(_decrypted[_pos:_pos+_nl].decode('utf-8')); _pos += _nl
    
    # ─── Code ───
    if _has_hdr:
        _pos = _off_code
    if _vl_flag or _poly_flag:
        _code_sz = int.from_bytes(_decrypted[_pos:_pos+4], 'little'); _pos += 4
        _code = _decrypted[_pos:_pos+_code_sz]
    else:
        _ic = int.from_bytes(_decrypted[_pos:_pos+4], 'little'); _pos += 4
        _code = _decrypted[_pos:_pos+_ic*8]
    return _code, _consts, _names, _map, _op_key, _vl_flag, _poly_flag, _vram_flag, _vram_size
