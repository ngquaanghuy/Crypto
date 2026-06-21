#ifndef CRYPTO_VM_PY_H
#define CRYPTO_VM_PY_H

static const char VM_COMPILE_SCRIPT[] = R"vm_compile(
import sys, dis, struct, types, random

BINOP_MAP = {'+':10, '-':11, '*':12, '/':13, '**':14, '|':16, '&':17, '^':18, '<<':19, '>>':34, '//':35, '%':36}
CMPOP_MAP = {'==':20, '!=':21, '<':22, '<=':23, '>':24, '>=':25}

def convert(source, opaque=0):
    import sys as _sys; _sys.stderr.write(f'[vm] VM source:\n{source}\n---\n'); _sys.stderr.flush()
    code = compile(source, '<vm>', 'exec')
    instrs = list(dis.get_instructions(code))

    # Build const pool from co_consts first (maintains order)
    all_consts = []
    const_idx = {}
    for c in code.co_consts:
        if not isinstance(c, types.CodeType):
            k = repr(c)
            if k not in const_idx:
                const_idx[k] = len(all_consts)
                all_consts.append(c)

    name_list = []
    name_set = {}
    def ni(n):
        if n not in name_set:
            name_set[n] = len(name_list)
            name_list.append(n)
        return name_set[n]

    # Register allocator: reuse freed registers
    reg_stack = []
    free_regs = []
    next_reg = 0

    def alloc_reg():
        nonlocal next_reg
        if free_regs:
            return free_regs.pop()
        r = next_reg
        next_reg += 1
        return r

    def free_reg(r):
        free_regs.append(r)

    def ci(v):
        k = repr(v)
        if k not in const_idx:
            const_idx[k] = len(all_consts)
            all_consts.append(v)
        return const_idx[k]

    # Cache for vm_target to avoid repeated linear scans
    vm_target_cache = {}

    def vm_target(off):
        if off in vm_target_cache:
            return vm_target_cache[off]
        o = off
        while o not in off2vm and o < 65536:
            o += 2
        res = off2vm.get(o, len(vm_code) // 8)
        vm_target_cache[off] = res
        return res

    # Map specialized Python 3.14 opcodes to generic equivalents
    SPECIAL_MAP = {}
    for _n in dir(dis):
        if _n.startswith('CALL_'):
            _op = getattr(dis.opmap, _n, None)
            if _op is not None:
                SPECIAL_MAP[_n] = 'CALL'
        elif _n.startswith('BINARY_OP_'):
            _op = getattr(dis.opmap, _n, None)
            if _op is not None:
                SPECIAL_MAP[_n] = 'BINARY_OP'
        elif _n.startswith('UNARY_'):
            _op = getattr(dis.opmap, _n, None)
            if _op is not None:
                SPECIAL_MAP[_n] = 'UNARY_NEGATIVE'
        elif _n.startswith('LOAD_') and _n not in ('LOAD_CONST', 'LOAD_NAME', 'LOAD_GLOBAL', 'LOAD_FAST', 'LOAD_SMALL_INT', 'LOAD_BUILD_CLASS', 'LOAD_FAST_AND_CLEAR', 'LOAD_FAST_BORROW', 'LOAD_FAST_BORROW_LOAD_FAST_BORROW', 'LOAD_FAST_LOAD_FAST', 'LOAD_ATTR', 'LOAD_DEREF', 'LOAD_CLOSURE', 'LOAD_SUPER_ATTR', 'LOAD_FROM_DICT_OR_DEREF', 'LOAD_FROM_DICT_OR_GLOBALS', 'LOAD_COMMON_CONSTANT', 'LOAD_SPECIAL', 'LOAD_FAST_CHECK'):
            _op = getattr(dis.opmap, _n, None)
            if _op is not None:
                SPECIAL_MAP[_n] = 'LOAD_NAME'
        elif _n.startswith('STORE_') and _n not in ('STORE_NAME', 'STORE_GLOBAL', 'STORE_FAST', 'STORE_SUBSCR', 'STORE_ATTR', 'STORE_DEREF', 'STORE_SLICE', 'STORE_FAST_MAYBE_NULL', 'STORE_FAST_LOAD_FAST', 'STORE_FAST_STORE_FAST'):
            _op = getattr(dis.opmap, _n, None)
            if _op is not None:
                SPECIAL_MAP[_n] = 'STORE_NAME'
        elif _n.startswith('BUILD_') and _n not in ('BUILD_TUPLE', 'BUILD_LIST', 'BUILD_MAP', 'BUILD_SET', 'BUILD_STRING', 'BUILD_SLICE', 'BUILD_INTERPOLATION', 'BUILD_TEMPLATE', 'BUILD_INTERPOLATION'):
            if _n == 'LIST_EXTEND':
                pass  # handled separately
            else:
                _op = getattr(dis.opmap, _n, None)
                if _op is not None:
                    SPECIAL_MAP[_n] = 'BUILD_TUPLE'
    
    def insert_junk(code_bytes):
        import random
        res = bytearray()
        i = 0
        while i < len(code_bytes):
            res.extend(code_bytes[i:i+8])
            i += 8
            if random.random() < 0.1: # 10% chance to insert junk
                # Junk: Opcode 0 (pass), random regs, random imm
                res.extend(struct.pack('<BBBBi', 0, random.randint(0,63), random.randint(0,63), random.randint(0,63), random.randint(0, 0x7FFFFFFF)))
        return res

    # Helper: evaluate an IIFE (IImmediately Invoked Function Expression)
    # at compile time. Scans instructions starting at `start` for the pattern:
    # LOAD_CONST(code) → MAKE_FUNCTION → ... → CALL
    # Returns (result_value, call_index) or (None, -1) if not an IIFE.
    def eval_iife(start, instrs_list):
        _ii_skip_set = frozenset(('RESUME', 'PUSH_NULL', 'NOP', 'PRECALL', 'CACHE', 'NOT_TAKEN', 'MAKE_FUNCTION', 'LOAD_CONST', 'LOAD_SMALL_INT'))
        _arg_skip_set = frozenset(('RESUME', 'PUSH_NULL', 'NOP', 'PRECALL', 'CACHE', 'NOT_TAKEN'))
        for j in range(start + 1, min(start + 100, len(instrs_list))):
            n = instrs_list[j].opname
            if n == 'MAKE_FUNCTION':
                for k in range(j + 1, min(j + 100, len(instrs_list))):
                    n2 = instrs_list[k].opname
                    if n2 in ('RESUME', 'PUSH_NULL', 'NOP', 'PRECALL', 'CACHE', 'NOT_TAKEN', 'TO_BOOL', 'LOAD_CONST', 'LOAD_SMALL_INT', 'LOAD_FAST', 'BUILD_LIST', 'BUILD_TUPLE', 'LIST_EXTEND', 'LIST_APPEND'):
                        continue
                    if n2 == 'MAKE_FUNCTION':
                        return None, -1
                    if n2.startswith('CALL') or n2 == 'CALL':
                        fn = types.FunctionType(instrs_list[start].argval, {'__builtins__': __builtins__})
                        vals = []
                        for m in range(j + 1, k):
                            n3 = instrs_list[m].opname
                            a3 = instrs_list[m].argval
                            if n3 in _arg_skip_set:
                                continue
                            if n3 == 'LOAD_CONST':
                                vals.append(a3)
                            elif n3 == 'LOAD_SMALL_INT':
                                vals.append(a3)
                            elif n3 == 'BUILD_LIST':
                                cnt = instrs_list[m].arg or 0
                                if cnt > 0:
                                    items = vals[-cnt:] if cnt <= len(vals) else []
                                    vals = vals[:-cnt] if cnt <= len(vals) else []
                                    vals.append(list(items))
                                else:
                                    vals.append([])
                            elif n3 == 'BUILD_TUPLE':
                                cnt = instrs_list[m].arg or 0
                                items = vals[-cnt:] if cnt <= len(vals) else []
                                vals = vals[:-cnt] if cnt <= len(vals) else []
                                vals.append(tuple(items))
                            elif n3 == 'LIST_EXTEND':
                                if len(vals) >= 2:
                                    item = vals.pop()
                                    lst = vals.pop()
                                    try:
                                        lst.extend(item)
                                    except TypeError:
                                        lst.append(item)
                                    vals.append(lst)
                            elif n3 == 'LIST_APPEND':
                                if len(vals) >= 2:
                                    item = vals.pop()
                                    lst = vals.pop()
                                    lst.append(item)
                                    vals.append(lst)
                                    vals.append(item)
                            elif n3 == 'BINARY_SUBSCR' or (n3 == 'BINARY_OP' and getattr(instrs_list[m], 'argrepr', None) == '[]'):
                                vals.append(vals.pop()[-1] if vals else None)
                            else:
                                return None, -1
                        try:
                            _rv = fn(*vals)
                            return _rv, k
                        except Exception:
                            return None, -1
                    return None, -1
                return None, -1
            if n not in _ii_skip_set:
                return None, -1
        return None, -1

    # Pre-pass: build off2vm map (bytecode offset -> VM instruction index)
    off2vm = {}
    vm_idx = 0
    _prev = None
    _ii = 0
    while _ii < len(instrs):
        instr = instrs[_ii]
        on = instr.opname
        _saved = _prev
        _prev = on
        if on == 'POP_TOP':
            _ii += 1; continue
        if on in ('RESUME', 'PUSH_NULL', 'NOP', 'PRECALL', 'CACHE', 'NOT_TAKEN', 'TO_BOOL'):
            _ii += 1; continue
        if on == 'LOAD_CONST' and isinstance(instr.argval, types.CodeType):
            _result, _call_idx = eval_iife(_ii, instrs)
            if _call_idx >= 0:
                off2vm[instr.offset] = vm_idx
                vm_idx += 1
                _ii = _call_idx + 1
                continue
            # Non-IIFE code object (function definition): include in mapping
        off2vm[instr.offset] = vm_idx
        vm_idx += 1
        _ii += 1

    # Reset state for main compilation pass
    vm_code = bytearray()
    prev_op = None
    _ii = 0
    
    # Track actual VM instruction positions (accounts for extra MOVEs from CALL, BUILD_*, etc.)
    _py_off_to_vm_slot = {}  # Python bytecode offset → actual VM slot at start of that instruction
    _jump_patches = []  # list of (byte_position_of_imm_in_vm_code, target_python_offset)
    
    def _record_target(_off):
        """Instead of vm_target (which uses stale off2vm), record jump for patching after main pass."""
        _jump_patches.append((len(vm_code) + 4, _off))
        return 0  # placeholder; patched after main pass
    
    while _ii < len(instrs):
        instr = instrs[_ii]
        on = instr.opname
        arg = instr.arg if instr.arg is not None else 0
        av = instr.argval
        prev_op_saved = prev_op
        prev_op = on
        _ii += 1

        # IIFE: LOAD_CONST(code) → MAKE_FUNCTION → ... → CALL → evaluate at compile time
        if on == 'LOAD_CONST' and isinstance(av, types.CodeType):
            _result, _call_idx = eval_iife(_ii - 1, instrs)
            if _call_idx >= 0:
                ci(_result)
                rd = alloc_reg()
                reg_stack.append(rd)
                vm_code.extend(struct.pack('<BBBBi', 1, rd, 0, 0, const_idx[repr(_result)]))
                _ii = _call_idx + 1
                continue
            # Non-IIFE: compile code object as constant (function definition)
            ci(av)
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 1, rd, 0, 0, const_idx[repr(av)]))
            continue

        if on == 'POP_TOP':
            if reg_stack:
                free_reg(reg_stack.pop())
            continue
        if on in ('RESUME', 'PUSH_NULL', 'POP_TOP', 'NOP', 'PRECALL', 'CACHE', 'NOT_TAKEN', 'TO_BOOL'):
            continue

        # Handle MAKE_FUNCTION: pop (qualified name, code_object) → push function
        if on == 'MAKE_FUNCTION':
            if reg_stack:
                name_reg = reg_stack.pop()
                free_reg(name_reg)
            else:
                name_reg = 0
            if reg_stack:
                code_reg = reg_stack.pop()
                free_reg(code_reg)
            else:
                code_reg = 0
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 54, rd, code_reg, 0, 0))
            continue

        # Record actual VM slot for this Python instruction BEFORE generating any VM code
        _py_off_to_vm_slot[instr.offset] = len(vm_code) // 8

        # Map specialized opcodes to generic
        if on in SPECIAL_MAP:
            on = SPECIAL_MAP[on]

        if on == 'LOAD_CONST':
            ci(av)
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 1, rd, 0, 0, const_idx[repr(av)]))

        if on == 'LOAD_SMALL_INT':
            ci(av)
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 1, rd, 0, 0, const_idx[repr(av)]))

        if on in ('LOAD_NAME', 'LOAD_GLOBAL'):
            ni(av)
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 2, rd, 0, 0, name_set[av]))

        if on == 'LOAD_ATTR':
            ni(av)
            if reg_stack:
                rs = reg_stack.pop()
                free_reg(rs)
            else:
                rs = 0
            rd = alloc_reg()
            reg_stack.append(rd)
            # Python 3.14+: when instr.arg & 1 == 1, LOAD_ATTR is a method-call
            # that pushes NULL + method (2 items). The VM skips the NULL sentinel
            # because _h_load_attr returns getattr(obj, attr) which is already
            # a bound method (self captured) for methods, or a plain value for
            # regular attributes. CALL uses the returned value directly without
            # needing the NULL/self sentinel from CPython's calling convention.
            vm_code.extend(struct.pack('<BBBBi', 60, rd, rs, 0, name_set[av]))

        if on == 'IMPORT_NAME':
            ni(av)
            # Pop fromlist and level from reg_stack (unused in simple imports)
            for _ in range(2):
                if reg_stack:
                    free_reg(reg_stack.pop())
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 61, rd, 0, 0, name_set[av]))

        if on == 'IMPORT_FROM':
            ni(av)
            mod_reg = reg_stack[-1] if reg_stack else 0
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 60, rd, mod_reg, 0, name_set[av]))

        if on in ('STORE_NAME', 'STORE_GLOBAL'):
            ni(av)
            if reg_stack:
                rs = reg_stack.pop()
                free_reg(rs)
            else:
                rs = 0
            vm_code.extend(struct.pack('<BBBBi', 3, rs, 0, 0, name_set[av]))

        if on == 'LOAD_FAST':
            ni(av)
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 4, rd, 0, 0, name_set[av]))

        if on == 'STORE_FAST':
            ni(av)
            if reg_stack:
                rs = reg_stack.pop()
                free_reg(rs)
            else:
                rs = 0
            vm_code.extend(struct.pack('<BBBBi', 5, rs, 0, 0, name_set[av]))

        if on == 'LOAD_FAST_AND_CLEAR':
            ni(av)
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 4, rd, 0, 0, name_set[av]))

        if on == 'LOAD_FAST_BORROW':
            ni(av)
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 4, rd, 0, 0, name_set[av]))

        if on == 'LOAD_FAST_BORROW_LOAD_FAST_BORROW':
            if arg is not None and code.co_varnames:
                idx1 = arg // 16
                idx2 = arg % 16
                if idx1 < len(code.co_varnames):
                    n1 = code.co_varnames[idx1]
                    ni(n1)
                    rd1 = alloc_reg()
                    reg_stack.append(rd1)
                    vm_code.extend(struct.pack('<BBBBi', 4, rd1, 0, 0, name_set[n1]))
                if idx2 < len(code.co_varnames):
                    n2 = code.co_varnames[idx2]
                    ni(n2)
                    rd2 = alloc_reg()
                    reg_stack.append(rd2)
                    vm_code.extend(struct.pack('<BBBBi', 4, rd2, 0, 0, name_set[n2]))
            else:
                # Fallback: use argval tuple
                if isinstance(av, tuple):
                    for n in av:
                        ni(n)
                        rd = alloc_reg()
                        reg_stack.append(rd)
                        vm_code.extend(struct.pack('<BBBBi', 4, rd, 0, 0, name_set[n]))
                elif av:
                    ni(av)
                    rd = alloc_reg()
                    reg_stack.append(rd)
                    vm_code.extend(struct.pack('<BBBBi', 4, rd, 0, 0, name_set[av]))

        # LOAD_FAST_LOAD_FAST (Python 3.14+): load two local variables at once
        # arg encodes indices as: idx1 = arg // 16, idx2 = arg % 16
        if on == 'LOAD_FAST_LOAD_FAST':
            if isinstance(av, tuple) and len(av) >= 2:
                for n in av:
                    ni(n)
                    rd = alloc_reg()
                    reg_stack.append(rd)
                    vm_code.extend(struct.pack('<BBBBi', 4, rd, 0, 0, name_set[n]))
            elif arg is not None and code.co_varnames:
                idx1 = arg // 16
                idx2 = arg % 16
                if idx1 < len(code.co_varnames):
                    n1 = code.co_varnames[idx1]
                    ni(n1)
                    rd1 = alloc_reg()
                    reg_stack.append(rd1)
                    vm_code.extend(struct.pack('<BBBBi', 4, rd1, 0, 0, name_set[n1]))
                if idx2 < len(code.co_varnames):
                    n2 = code.co_varnames[idx2]
                    ni(n2)
                    rd2 = alloc_reg()
                    reg_stack.append(rd2)
                    vm_code.extend(struct.pack('<BBBBi', 4, rd2, 0, 0, name_set[n2]))

        if on == 'SWAP':
            _swap_n = arg if arg is not None else 2
            if len(reg_stack) >= _swap_n:
                reg_stack[-1], reg_stack[-(_swap_n)] = reg_stack[-(_swap_n)], reg_stack[-1]
            # No VM instruction needed - just reorder the register stack

        if on == 'LIST_APPEND':
            if reg_stack:
                val_reg = reg_stack.pop()
                free_reg(val_reg)
            else:
                val_reg = 0
            # LIST_APPEND i → list is at stack[-i] from current top
            _list_offset = max(arg, 1)
            if _list_offset >= 1 and len(reg_stack) >= _list_offset:
                list_reg = reg_stack[-_list_offset]
            else:
                list_reg = 0
            vm_code.extend(struct.pack('<BBBBi', 75, list_reg, val_reg, 0, 0))

        if on == 'BINARY_OP':
            if instr.argrepr == '[]':
                # Subscript
                if len(reg_stack) >= 2:
                    rs2 = reg_stack.pop()
                    rs1 = reg_stack.pop()
                    free_reg(rs2)
                    free_reg(rs1)
                else:
                    rs1 = rs2 = 0
                rd = alloc_reg()
                reg_stack.append(rd)
                vm_code.extend(struct.pack('<BBBBi', 33, rd, rs1, rs2, 0))
            else:
                opcode = BINOP_MAP.get(instr.argrepr, 10)
                if len(reg_stack) >= 2:
                    rs2 = reg_stack.pop()
                    rs1 = reg_stack.pop()
                    free_reg(rs2)
                    free_reg(rs1)
                else:
                    rs1 = rs2 = 0
                rd = alloc_reg()
                reg_stack.append(rd)
                vm_code.extend(struct.pack('<BBBBi', opcode, rd, rs1, rs2, 0))

        if on == 'COMPARE_OP':
            # argrepr may be 'bool(<)' on Python 3.14+
            _cmp_s = instr.argrepr.replace('bool(', '').rstrip(')')
            opcode = CMPOP_MAP.get(_cmp_s, 20)
            if len(reg_stack) >= 2:
                rs2 = reg_stack.pop()
                rs1 = reg_stack.pop()
                free_reg(rs2)
                free_reg(rs1)
            else:
                rs1 = rs2 = 0
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', opcode, rd, rs1, rs2, 0))

        if on == 'CALL':
            argc = arg
            args = []
            for _ in range(argc):
                if reg_stack:
                    args.insert(0, reg_stack.pop())
            if reg_stack:
                fn_reg = reg_stack.pop()
            else:
                fn_reg = 0
            
            # Move args to consecutive registers after fn_reg.
            # Build list of (target, source) moves
            _moves = []
            for _i, _a in enumerate(args):
                _tgt = fn_reg + 1 + _i
                if _a != _tgt:
                    _moves.append((_tgt, _a))
            # Detect source-target overlap between moves: if a source is also a target
            # of a later move, save it first.
            _move_targets = set(_t for _t, _ in _moves)
            _saved = {}
            for _i, (_tgt, _src) in enumerate(_moves):
                for _j in range(_i):
                    _prev_tgt = _moves[_j][0]
                    if _src == _prev_tgt and _src not in _saved:
                        # Allocate save register, avoiding conflict with move targets
                        _tmp = alloc_reg()
                        if _tmp in _move_targets:
                            free_regs.append(_tmp)
                            _tmp = next_reg
                            next_reg += 1
                        vm_code.extend(struct.pack('<BBBBi', 6, _tmp, _src, 0, 0))
                        _saved[_src] = _tmp
                        if _src in reg_stack:
                            reg_stack[reg_stack.index(_src)] = _tmp
            # Also save any live registers that would be overwritten by MOVE targets.
            _live = set(reg_stack)
            for _tgt, _src in _moves:
                if _tgt in _live and _tgt not in _saved:
                    _tmp = alloc_reg()
                    if _tmp in _move_targets:
                        free_regs.append(_tmp)
                        _tmp = next_reg
                        next_reg += 1
                    vm_code.extend(struct.pack('<BBBBi', 6, _tmp, _tgt, 0, 0))
                    _saved[_tgt] = _tmp
                    reg_stack[reg_stack.index(_tgt)] = _tmp
            # Generate MOVE instructions, using saved copies where needed.
            for _tgt, _src in _moves:
                if _src in _saved:
                    vm_code.extend(struct.pack('<BBBBi', 6, _tgt, _saved[_src], 0, 0))
                elif _tgt in _saved:
                    vm_code.extend(struct.pack('<BBBBi', 6, _tgt, _src, 0, 0))
                else:
                    vm_code.extend(struct.pack('<BBBBi', 6, _tgt, _src, 0, 0))
            for _r in _saved.values():
                free_reg(_r)
            # Now free all used registers
            for a in args:
                free_reg(a)
            free_reg(fn_reg)
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 40, rd, fn_reg, 0, argc))

        if on == 'GET_ITER':
            if reg_stack:
                rs = reg_stack.pop()
                free_reg(rs)
            else:
                rs = 0
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 70, rd, rs, 0, 0))

        if on == 'FOR_ITER':
            if reg_stack:
                iter_reg = reg_stack[-1]  # peek, don't pop — keep for next iterations
            else:
                iter_reg = 0
            target = dis._get_jump_target(instr.opcode, instr.arg, instr.offset)
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 71, rd, iter_reg, 0, _record_target(target)))

        if on == 'RETURN_VALUE':
            if reg_stack:
                rs = reg_stack.pop()
                free_reg(rs)
            else:
                rs = 0
            vm_code.extend(struct.pack('<BBBBi', 42, rs, 0, 0, 0))

        if on == 'STORE_SUBSCR':
            # Pop: value, container, index (top = index)
            idx_reg = reg_stack.pop() if reg_stack else 0
            container_reg = reg_stack.pop() if reg_stack else 0
            val_reg = reg_stack.pop() if reg_stack else 0
            for r in (idx_reg, container_reg, val_reg):
                if r:
                    free_reg(r)
            # Emit: _r[container][index] = value
            vm_code.extend(struct.pack('<BBBBi', 50, val_reg, container_reg, idx_reg, 0))

        if on == 'JUMP_FORWARD':
            target = dis._get_jump_target(instr.opcode, instr.arg, instr.offset)
            vm_code.extend(struct.pack('<BBBBi', 30, 0, 0, 0, _record_target(target)))

        if on in ('POP_JUMP_IF_TRUE', 'POP_JUMP_IF_NOT_NONE'):
            if reg_stack:
                rs = reg_stack.pop()
                free_reg(rs)
            else:
                rs = 0
            target = dis._get_jump_target(instr.opcode, instr.arg, instr.offset)
            vm_code.extend(struct.pack('<BBBBi', 31, rs, 0, 0, _record_target(target)))

        if on in ('POP_JUMP_IF_FALSE', 'POP_JUMP_IF_NONE'):
            if reg_stack:
                rs = reg_stack.pop()
                free_reg(rs)
            else:
                rs = 0
            target = dis._get_jump_target(instr.opcode, instr.arg, instr.offset)
            vm_code.extend(struct.pack('<BBBBi', 32, rs, 0, 0, _record_target(target)))

        if on == 'JUMP_BACKWARD':
            target = dis._get_jump_target(instr.opcode, instr.arg, instr.offset)
            vm_code.extend(struct.pack('<BBBBi', 30, 0, 0, 0, _record_target(target)))

        if on == 'LIST_EXTEND':
            # Pop the tuple/values register, extend the list below it
            vals = []
            for _ in range(arg):
                if reg_stack:
                    vals.insert(0, reg_stack.pop())
            # The list register should now be at top of reg_stack
            if reg_stack:
                list_reg = reg_stack[-1]
            else:
                list_reg = 0
            for v in vals:
                free_reg(v)
            # No new register - list stays on top
            if vals:
                vm_code.extend(struct.pack('<BBBBi', 72, list_reg, vals[0], 0, 0))

        if on == 'BUILD_TUPLE':
            args = []
            for _ in range(arg):
                if reg_stack:
                    args.insert(0, reg_stack.pop())
            for a in args:
                free_reg(a)
            rd = alloc_reg()
            reg_stack.append(rd)
            # Ensure items are in consecutive registers after rd
            for i, a in enumerate(args):
                if a != rd + 1 + i:
                    vm_code.extend(struct.pack('<BBBBi', 6, rd + 1 + i, a, 0, 0))
            vm_code.extend(struct.pack('<BBBBi', 43, rd, rd + 1, arg, 0))

        if on == 'BUILD_LIST':
            args = []
            for _ in range(arg):
                if reg_stack:
                    args.insert(0, reg_stack.pop())
            for a in args:
                free_reg(a)
            rd = alloc_reg()
            reg_stack.append(rd)
            # Ensure items are in consecutive registers after rd
            for i, a in enumerate(args):
                if a != rd + 1 + i:
                    vm_code.extend(struct.pack('<BBBBi', 6, rd + 1 + i, a, 0, 0))
            vm_code.extend(struct.pack('<BBBBi', 44, rd, rd + 1, arg, 0))

        if on == 'FORMAT_SIMPLE':
            if reg_stack:
                rs = reg_stack.pop()
                free_reg(rs)
            else:
                rs = 0
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 62, rd, rs, 0, 0))

        if on == 'BUILD_STRING':
            items = []
            for _ in range(arg):
                if reg_stack:
                    items.insert(0, reg_stack.pop())
            rd = alloc_reg()
            reg_stack.append(rd)
            for i, a in enumerate(items):
                if a != rd + 1 + i:
                    vm_code.extend(struct.pack('<BBBBi', 6, rd + 1 + i, a, 0, 0))
            for a in items:
                free_reg(a)
            vm_code.extend(struct.pack('<BBBBi', 63, rd, rd + 1, arg, 0))

        if on == 'UNARY_NEGATIVE':
            if reg_stack:
                rs = reg_stack.pop()
                free_reg(rs)
            else:
                rs = 0
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 15, rd, rs, 0, 0))

        if on == 'UNARY_INVERT':
            if reg_stack:
                rs = reg_stack.pop()
                free_reg(rs)
            else:
                rs = 0
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 7, rd, rs, 0, 0))

        if on == 'UNARY_NOT':
            if reg_stack:
                rs = reg_stack.pop()
                free_reg(rs)
            else:
                rs = 0
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 8, rd, rs, 0, 0))

        if on == 'BINARY_SLICE':
            # obj[start:stop] — pop obj, start, stop; push result
            stop_reg = reg_stack.pop() if reg_stack else 0
            start_reg = reg_stack.pop() if reg_stack else 0
            obj_reg = reg_stack.pop() if reg_stack else 0
            for r in (stop_reg, start_reg, obj_reg):
                if r: free_reg(r)
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 161, rd, obj_reg, start_reg, 0))

        if on == 'DELETE_SUBSCR':
            key_reg = reg_stack.pop() if reg_stack else 0
            obj_reg = reg_stack.pop() if reg_stack else 0
            for r in (key_reg, obj_reg):
                if r: free_reg(r)
            vm_code.extend(struct.pack('<BBBBi', 162, 0, obj_reg, key_reg, 0))

        if on == 'STORE_SLICE':
            step_reg = reg_stack.pop() if reg_stack else 0
            stop_reg = reg_stack.pop() if reg_stack else 0
            start_reg = reg_stack.pop() if reg_stack else 0
            obj_reg = reg_stack.pop() if reg_stack else 0
            val_reg = reg_stack.pop() if reg_stack else 0
            for r in (step_reg, stop_reg, start_reg, obj_reg, val_reg):
                if r: free_reg(r)
            vm_code.extend(struct.pack('<BBBBi', 163, val_reg, obj_reg, start_reg, 0))

        if on == 'BUILD_MAP':
            items = []
            for _ in range(arg):
                if reg_stack: items.insert(0, reg_stack.pop())
            rd = alloc_reg()
            reg_stack.append(rd)
            for i, a in enumerate(items):
                if a != rd + 1 + i:
                    vm_code.extend(struct.pack('<BBBBi', 6, rd + 1 + i, a, 0, 0))
            for a in items:
                free_reg(a)
            vm_code.extend(struct.pack('<BBBBi', 164, rd, rd + 1, arg // 2, 0))

        if on == 'BUILD_SET':
            items = []
            for _ in range(arg):
                if reg_stack: items.insert(0, reg_stack.pop())
            rd = alloc_reg()
            reg_stack.append(rd)
            for i, a in enumerate(items):
                if a != rd + 1 + i:
                    vm_code.extend(struct.pack('<BBBBi', 6, rd + 1 + i, a, 0, 0))
            for a in items:
                free_reg(a)
            vm_code.extend(struct.pack('<BBBBi', 165, rd, rd + 1, arg, 0))

        if on == 'BUILD_SLICE':
            # Pop start, stop, [step]
            step_reg = reg_stack.pop() if reg_stack and arg == 3 else 0
            stop_reg = reg_stack.pop() if reg_stack else 0
            start_reg = reg_stack.pop() if reg_stack else 0
            for r in (step_reg, stop_reg, start_reg):
                if r: free_reg(r)
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 166, rd, start_reg, stop_reg, arg))

        if on == 'COPY':
            if reg_stack:
                rs = reg_stack[-1]
            else:
                rs = 0
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 167, rd, rs, 0, 0))

        if on == 'DICT_MERGE':
            other_reg = reg_stack.pop() if reg_stack else 0
            dict_reg = reg_stack[-1] if reg_stack else 0
            free_reg(other_reg)
            vm_code.extend(struct.pack('<BBBBi', 168, dict_reg, other_reg, 0, 0))

        if on == 'DICT_UPDATE':
            other_reg = reg_stack.pop() if reg_stack else 0
            dict_reg = reg_stack[-1] if reg_stack else 0
            free_reg(other_reg)
            vm_code.extend(struct.pack('<BBBBi', 169, dict_reg, other_reg, 0, 0))

        if on == 'MAP_ADD':
            val_reg = reg_stack.pop() if reg_stack else 0
            key_reg = reg_stack.pop() if reg_stack else 0
            dict_reg = reg_stack[-1] if reg_stack else 0
            free_reg(val_reg)
            free_reg(key_reg)
            vm_code.extend(struct.pack('<BBBBi', 170, dict_reg, key_reg, val_reg, 0))

        if on == 'SET_ADD':
            item_reg = reg_stack.pop() if reg_stack else 0
            set_reg = reg_stack[-1] if reg_stack else 0
            free_reg(item_reg)
            vm_code.extend(struct.pack('<BBBBi', 171, set_reg, item_reg, 0, 0))

        if on == 'SET_UPDATE':
            other_reg = reg_stack.pop() if reg_stack else 0
            set_reg = reg_stack[-1] if reg_stack else 0
            free_reg(other_reg)
            vm_code.extend(struct.pack('<BBBBi', 172, set_reg, other_reg, 0, 0))

        if on == 'GET_AITER':
            obj_reg = reg_stack.pop() if reg_stack else 0
            free_reg(obj_reg)
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 181, rd, obj_reg, 0, 0))

        if on == 'GET_ANEXT':
            aiter_reg = reg_stack[-1] if reg_stack else 0
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 182, rd, aiter_reg, 0, 0))

        if on == 'GET_YIELD_FROM_ITER':
            iter_reg = reg_stack[-1] if reg_stack else 0
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 183, rd, iter_reg, 0, 0))

        if on == 'LOAD_BUILD_CLASS':
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 184, rd, 0, 0, 0))

        if on == 'RETURN_GENERATOR':
            if reg_stack:
                rs = reg_stack.pop()
                free_reg(rs)
            else:
                rs = 0
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 185, rd, rs, 0, 0))

        if on == 'COPY_FREE_VARS':
            vm_code.extend(struct.pack('<BBBBi', 186, 0, 0, 0, arg))

        if on == 'DELETE_DEREF':
            ni(av)
            vm_code.extend(struct.pack('<BBBBi', 187, 0, 0, 0, name_set[av]))

        if on == 'END_ASYNC_FOR':
            vm_code.extend(struct.pack('<BBBBi', 188, 0, 0, 0, 0))

        if on == 'GET_AWAITABLE':
            if reg_stack:
                rs = reg_stack.pop()
                free_reg(rs)
            else:
                rs = 0
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 189, rd, rs, 0, 0))

        if on == 'LOAD_DEREF':
            ni(av)
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 190, rd, 0, 0, name_set[av]))

        if on == 'MAKE_CELL':
            if reg_stack:
                rs = reg_stack.pop()
                free_reg(rs)
            else:
                rs = 0
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 191, rd, rs, 0, 0))

        if on == 'SEND':
            if len(reg_stack) >= 2:
                gen_reg = reg_stack.pop()
                val_reg = reg_stack.pop()
            elif reg_stack:
                gen_reg = reg_stack.pop()
                val_reg = 0
            else:
                gen_reg = val_reg = 0
            free_reg(val_reg)
            free_reg(gen_reg)
            rd = alloc_reg()
            reg_stack.append(rd)
            target = dis._get_jump_target(instr.opcode, instr.arg, instr.offset)
            vm_code.extend(struct.pack('<BBBBi', 192, rd, gen_reg, val_reg, _record_target(target)))

        if on == 'STORE_DEREF':
            ni(av)
            if reg_stack:
                rs = reg_stack.pop()
                free_reg(rs)
            else:
                rs = 0
            vm_code.extend(struct.pack('<BBBBi', 193, rs, 0, 0, name_set[av]))

        if on == 'YIELD_VALUE':
            if reg_stack:
                rs = reg_stack.pop()
                free_reg(rs)
            else:
                rs = 0
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 194, rd, rs, 0, 0))

        if on == 'LOAD_CLOSURE':
            ni(av)
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 195, rd, 0, 0, name_set[av]))

        if on == 'CHECK_EG_MATCH':
            exc_reg = reg_stack[-1] if reg_stack else 0
            match_reg = reg_stack[-2] if len(reg_stack) >= 2 else 0
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 200, rd, exc_reg, match_reg, 0))

        if on == 'CHECK_EXC_MATCH':
            exc_reg = reg_stack[-1] if reg_stack else 0
            handled = 0
            vm_code.extend(struct.pack('<BBBBi', 201, 0, exc_reg, 0, 0))

        if on == 'CLEANUP_THROW':
            vm_code.extend(struct.pack('<BBBBi', 202, 0, 0, 0, 0))

        if on == 'POP_EXCEPT':
            vm_code.extend(struct.pack('<BBBBi', 203, 0, 0, 0, 0))

        if on == 'PUSH_EXC_INFO':
            if reg_stack:
                rs = reg_stack.pop()
                free_reg(rs)
            else:
                rs = 0
            vm_code.extend(struct.pack('<BBBBi', 204, rs, 0, 0, 0))

        if on == 'WITH_EXCEPT_START':
            exc_reg = reg_stack[-1] if reg_stack else 0
            ctx_reg = reg_stack[-2] if len(reg_stack) >= 2 else 0
            if reg_stack:
                rs = reg_stack.pop()
                free_reg(rs)
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 205, rd, ctx_reg, exc_reg, 0))

        if on == 'RERAISE':
            prev_exc_reg = reg_stack.pop() if reg_stack else 0
            if prev_exc_reg: free_reg(prev_exc_reg)
            vm_code.extend(struct.pack('<BBBBi', 206, prev_exc_reg, 0, 0, 0))

        if on == 'POP_BLOCK':
            vm_code.extend(struct.pack('<BBBBi', 207, 0, 0, 0, 0))

        if on == 'SETUP_CLEANUP':
            target = dis._get_jump_target(instr.opcode, instr.arg, instr.offset)
            vm_code.extend(struct.pack('<BBBBi', 208, 0, 0, 0, _record_target(target)))

        if on == 'SETUP_FINALLY':
            target = dis._get_jump_target(instr.opcode, instr.arg, instr.offset)
            vm_code.extend(struct.pack('<BBBBi', 209, 0, 0, 0, _record_target(target)))

        if on == 'SETUP_WITH':
            ctx_reg = reg_stack[-1] if reg_stack else 0
            target = dis._get_jump_target(instr.opcode, instr.arg, instr.offset)
            vm_code.extend(struct.pack('<BBBBi', 210, 0, ctx_reg, 0, _record_target(target)))

        if on == 'MATCH_KEYS':
            keys_reg = reg_stack.pop() if reg_stack else 0
            subj_reg = reg_stack.pop() if reg_stack else 0
            free_reg(keys_reg)
            free_reg(subj_reg)
            rd = alloc_reg()
            reg_stack.append(rd)
            rd2 = alloc_reg()
            reg_stack.append(rd2)
            vm_code.extend(struct.pack('<BBBBi', 220, rd, subj_reg, keys_reg, 0))

        if on == 'MATCH_MAPPING':
            subj_reg = reg_stack[-1] if reg_stack else 0
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 221, rd, subj_reg, 0, 0))

        if on == 'MATCH_SEQUENCE':
            subj_reg = reg_stack[-1] if reg_stack else 0
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 222, rd, subj_reg, 0, arg))

        if on == 'MATCH_CLASS':
            subj_reg = reg_stack[-1] if reg_stack else 0
            nargs = arg
            args = []
            for _ in range(nargs):
                if reg_stack: args.insert(0, reg_stack.pop())
            for a in args: free_reg(a)
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 223, rd, subj_reg, nargs, name_set[av] if isinstance(av, str) else (av or 0)))

        if on == 'POP_ITER':
            iter_reg = reg_stack.pop() if reg_stack else 0
            if iter_reg: free_reg(iter_reg)
            vm_code.extend(struct.pack('<BBBBi', 230, 0, iter_reg, 0, 0))

        if on == 'JUMP_BACKWARD_NO_INTERRUPT':
            target = dis._get_jump_target(instr.opcode, instr.arg, instr.offset)
            vm_code.extend(struct.pack('<BBBBi', 231, 0, 0, 0, _record_target(target)))

        if on == 'JUMP':
            target = dis._get_jump_target(instr.opcode, instr.arg, instr.offset)
            vm_code.extend(struct.pack('<BBBBi', 232, 0, 0, 0, _record_target(target)))

        if on == 'JUMP_IF_FALSE':
            if reg_stack:
                rs = reg_stack.pop()
                free_reg(rs)
            else:
                rs = 0
            target = dis._get_jump_target(instr.opcode, instr.arg, instr.offset)
            vm_code.extend(struct.pack('<BBBBi', 233, rs, 0, 0, _record_target(target)))

        if on == 'JUMP_IF_TRUE':
            if reg_stack:
                rs = reg_stack.pop()
                free_reg(rs)
            else:
                rs = 0
            target = dis._get_jump_target(instr.opcode, instr.arg, instr.offset)
            vm_code.extend(struct.pack('<BBBBi', 234, rs, 0, 0, _record_target(target)))

        if on == 'JUMP_NO_INTERRUPT':
            target = dis._get_jump_target(instr.opcode, instr.arg, instr.offset)
            vm_code.extend(struct.pack('<BBBBi', 235, 0, 0, 0, _record_target(target)))

        if on == 'DELETE_ATTR':
            ni(av)
            if reg_stack:
                obj_reg = reg_stack.pop()
                free_reg(obj_reg)
            else:
                obj_reg = 0
            vm_code.extend(struct.pack('<BBBBi', 240, obj_reg, 0, 0, name_set[av]))

        if on == 'LOAD_SUPER_ATTR':
            ni(av)
            if reg_stack:
                cls_reg = reg_stack.pop()
                free_reg(cls_reg)
            if reg_stack:
                self_reg = reg_stack.pop()
                free_reg(self_reg)
            if reg_stack:
                global_super = reg_stack.pop()
                free_reg(global_super)
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 241, rd, 0, 0, name_set[av]))

        if on == 'STORE_ATTR':
            ni(av)
            if reg_stack:
                val_reg = reg_stack.pop()
                free_reg(val_reg)
            if reg_stack:
                obj_reg = reg_stack.pop()
                free_reg(obj_reg)
            vm_code.extend(struct.pack('<BBBBi', 242, val_reg, obj_reg, 0, name_set[av]))

        if on == 'CALL_FUNCTION_EX':
            kwargs_reg = reg_stack.pop() if reg_stack else 0
            args_reg = reg_stack.pop() if reg_stack else 0
            fn_reg = reg_stack.pop() if reg_stack else 0
            free_reg(kwargs_reg)
            free_reg(args_reg)
            free_reg(fn_reg)
            rd = alloc_reg()
            reg_stack.append(rd)
            flags = arg & 0xFF  # bit 0: has kwargs
            vm_code.extend(struct.pack('<BBBBi', 245, rd, fn_reg, args_reg, flags))

        if on == 'CALL_INTRINSIC_1':
            av_reg = reg_stack.pop() if reg_stack else 0
            free_reg(av_reg)
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 246, rd, av_reg, 0, arg))

        if on == 'CALL_INTRINSIC_2':
            av2_reg = reg_stack.pop() if reg_stack else 0
            av1_reg = reg_stack.pop() if reg_stack else 0
            free_reg(av2_reg)
            free_reg(av1_reg)
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 247, rd, av1_reg, av2_reg, arg))

        if on == 'CALL_KW':
            argc = arg
            # CPython stack: fn, arg1, ..., argN, names_tuple (names_tuple ON TOP)
            names_idx = reg_stack.pop() if reg_stack else 0  # pop names tuple FIRST
            args = []
            for _ in range(argc):
                if reg_stack: args.insert(0, reg_stack.pop())
            if reg_stack:
                fn_reg = reg_stack.pop()
            else:
                fn_reg = 0
            # Move args to consecutive registers after fn_reg.
            _moves = []
            for _i, _a in enumerate(args):
                _tgt = fn_reg + 1 + _i
                if _a != _tgt:
                    _moves.append((_tgt, _a))
            _move_targets = set(_t for _t, _ in _moves)
            _saved = {}
            for _i, (_tgt, _src) in enumerate(_moves):
                for _j in range(_i):
                    _prev_tgt = _moves[_j][0]
                    if _src == _prev_tgt and _src not in _saved:
                        _tmp = alloc_reg()
                        if _tmp in _move_targets:
                            free_regs.append(_tmp)
                            _tmp = next_reg
                            next_reg += 1
                        vm_code.extend(struct.pack('<BBBBi', 6, _tmp, _src, 0, 0))
                        _saved[_src] = _tmp
                        if _src in reg_stack:
                            reg_stack[reg_stack.index(_src)] = _tmp
            # Save names_idx if it's a MOVE target (already popped from reg_stack)
            if names_idx and names_idx in _move_targets and names_idx not in _saved:
                _tmp = alloc_reg()
                if _tmp in _move_targets:
                    free_regs.append(_tmp)
                    _tmp = next_reg
                    next_reg += 1
                vm_code.extend(struct.pack('<BBBBi', 6, _tmp, names_idx, 0, 0))
                names_idx = _tmp
            _live = set(reg_stack)
            for _tgt, _src in _moves:
                if _tgt in _live and _tgt not in _saved:
                    _tmp = alloc_reg()
                    if _tmp in _move_targets:
                        free_regs.append(_tmp)
                        _tmp = next_reg
                        next_reg += 1
                    vm_code.extend(struct.pack('<BBBBi', 6, _tmp, _tgt, 0, 0))
                    _saved[_tgt] = _tmp
                    reg_stack[reg_stack.index(_tgt)] = _tmp
            for _tgt, _src in _moves:
                if _src in _saved:
                    vm_code.extend(struct.pack('<BBBBi', 6, _tgt, _saved[_src], 0, 0))
                elif _tgt in _saved:
                    vm_code.extend(struct.pack('<BBBBi', 6, _tgt, _src, 0, 0))
                else:
                    vm_code.extend(struct.pack('<BBBBi', 6, _tgt, _src, 0, 0))
            for _r in _saved.values():
                free_reg(_r)
            for a in args: free_reg(a)
            free_reg(names_idx)
            free_reg(fn_reg)
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 248, rd, fn_reg, names_idx, argc))

        if on == 'DELETE_FAST':
            ni(av)
            vm_code.extend(struct.pack('<BBBBi', 250, 0, 0, 0, name_set[av]))

        if on == 'DELETE_GLOBAL':
            ni(av)
            vm_code.extend(struct.pack('<BBBBi', 251, 0, 0, 0, name_set[av]))

        if on == 'DELETE_NAME':
            ni(av)
            vm_code.extend(struct.pack('<BBBBi', 252, 0, 0, 0, name_set[av]))

        if on == 'LOAD_FROM_DICT_OR_DEREF':
            ni(av)
            if reg_stack:
                dict_reg = reg_stack.pop()
                free_reg(dict_reg)
            else:
                dict_reg = 0
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 253, rd, dict_reg, 0, name_set[av]))

        if on == 'LOAD_FROM_DICT_OR_GLOBALS':
            ni(av)
            if reg_stack:
                dict_reg = reg_stack.pop()
                free_reg(dict_reg)
            else:
                dict_reg = 0
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 254, rd, dict_reg, 0, name_set[av]))

        if on == 'SETUP_ANNOTATIONS':
            vm_code.extend(struct.pack('<BBBBi', 9, 0, 0, 0, 0))

        if on == 'CONVERT_VALUE':
            if reg_stack:
                rs = reg_stack.pop()
                free_reg(rs)
            else:
                rs = 0
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 110, rd, rs, 0, arg))

        if on == 'LOAD_COMMON_CONSTANT':
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 111, rd, 0, 0, arg))

        if on == 'LOAD_SPECIAL':
            ni(av)
            if reg_stack:
                rs = reg_stack[-1]
            else:
                rs = 0
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 112, rd, rs, 0, name_set[av]))

        if on == 'ANNOTATIONS_PLACEHOLDER':
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 113, rd, 0, 0, 0))

        if on == 'BUILD_TEMPLATE':
            nparts = arg
            parts = []
            for _ in range(nparts):
                if reg_stack: parts.insert(0, reg_stack.pop())
            rd = alloc_reg()
            reg_stack.append(rd)
            for i, a in enumerate(parts):
                if a != rd + 1 + i:
                    vm_code.extend(struct.pack('<BBBBi', 6, rd + 1 + i, a, 0, 0))
            for a in parts: free_reg(a)
            vm_code.extend(struct.pack('<BBBBi', 114, rd, rd + 1, nparts, 0))

        if on == 'END_FOR':
            iter_reg = reg_stack.pop() if reg_stack else 0
            if iter_reg: free_reg(iter_reg)
            vm_code.extend(struct.pack('<BBBBi', 115, 0, iter_reg, 0, 0))

        if on == 'EXIT_INIT_CHECK':
            vm_code.extend(struct.pack('<BBBBi', 116, 0, 0, 0, 0))

        if on == 'FORMAT_WITH_SPEC':
            fmt_reg = reg_stack.pop() if reg_stack else 0
            val_reg = reg_stack.pop() if reg_stack else 0
            free_reg(fmt_reg)
            free_reg(val_reg)
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 117, rd, val_reg, fmt_reg, 0))

        if on == 'RESERVED':
            vm_code.extend(struct.pack('<BBBBi', 118, 0, 0, 0, 0))

        if on == 'GET_LEN':
            if reg_stack:
                rs = reg_stack.pop()
                free_reg(rs)
            else:
                rs = 0
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 119, rd, rs, 0, 0))

        if on == 'INTERPRETER_EXIT':
            vm_code.extend(struct.pack('<BBBBi', 124, 0, 0, 0, 0))

        if on == 'BUILD_INTERPOLATION':
            nparts = arg
            parts = []
            for _ in range(nparts):
                if reg_stack: parts.insert(0, reg_stack.pop())
            rd = alloc_reg()
            reg_stack.append(rd)
            for i, a in enumerate(parts):
                if a != rd + 1 + i:
                    vm_code.extend(struct.pack('<BBBBi', 6, rd + 1 + i, a, 0, 0))
            for a in parts: free_reg(a)
            vm_code.extend(struct.pack('<BBBBi', 125, rd, rd + 1, nparts, 0))

        if on == 'CONTAINS_OP':
            seq_reg = reg_stack.pop() if reg_stack else 0
            item_reg = reg_stack.pop() if reg_stack else 0
            free_reg(seq_reg)
            free_reg(item_reg)
            rd = alloc_reg()
            reg_stack.append(rd)
            invert = arg  # 0=in, 1=not in
            vm_code.extend(struct.pack('<BBBBi', 126, rd, item_reg, seq_reg, invert))

        if on == 'IS_OP':
            r2 = reg_stack.pop() if reg_stack else 0
            r1 = reg_stack.pop() if reg_stack else 0
            free_reg(r2)
            free_reg(r1)
            rd = alloc_reg()
            reg_stack.append(rd)
            invert = arg  # 0=is, 1=is not
            vm_code.extend(struct.pack('<BBBBi', 127, rd, r1, r2, invert))

        if on == 'LOAD_FAST_CHECK':
            ni(av)
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 128, rd, 0, 0, name_set[av]))

        if on == 'RAISE_VARARGS':
            argc = arg
            exc_reg = reg_stack.pop() if reg_stack and argc > 0 else 0
            cause_reg = reg_stack.pop() if reg_stack and argc > 1 else 0
            if exc_reg: free_reg(exc_reg)
            if cause_reg: free_reg(cause_reg)
            if argc == 0:
                # Re-raise current exception
                pass
            vm_code.extend(struct.pack('<BBBBi', 129, exc_reg, cause_reg, 0, argc))

        if on == 'STORE_FAST_LOAD_FAST':
            if isinstance(av, tuple) and len(av) >= 2:
                ni(av[0])
                ni(av[1])
                # Pop the value to store
                val_reg = reg_stack.pop() if reg_stack else 0
                if val_reg: free_reg(val_reg)
                # STORE_FAST (opcode 5): store val_reg to av[0]
                vm_code.extend(struct.pack('<BBBBi', 5, val_reg, 0, 0, name_set[av[0]]))
                # LOAD_FAST (opcode 4): load av[1] into new register, push to stack
                rd = alloc_reg()
                reg_stack.append(rd)
                vm_code.extend(struct.pack('<BBBBi', 4, rd, 0, 0, name_set[av[1]]))
            else:
                ni(av)
                val_reg = reg_stack.pop() if reg_stack else 0
                if val_reg: free_reg(val_reg)
                rd = alloc_reg()
                reg_stack.append(rd)
                vm_code.extend(struct.pack('<BBBBi', 4, rd, 0, 0, name_set[av]))

        if on == 'STORE_FAST_STORE_FAST':
            if isinstance(av, tuple) and len(av) >= 2:
                ni(av[0])
                ni(av[1])
                # Pop both regs from reg_stack (pushed by UNPACK_SEQUENCE)
                # reg_stack top = seq[0] (first element after unpack), then seq[1]
                reg_first = reg_stack.pop() if reg_stack else 0  # first destructured var
                reg_second = reg_stack.pop() if reg_stack else 0  # second destructured var
                if reg_first: free_reg(reg_first)
                if reg_second: free_reg(reg_second)
                # Generate two STORE_FAST instructions (opcode 5)
                vm_code.extend(struct.pack('<BBBBi', 5, reg_first, 0, 0, name_set[av[0]]))
                vm_code.extend(struct.pack('<BBBBi', 5, reg_second, 0, 0, name_set[av[1]]))
            else:
                ni(av)
                val_reg = reg_stack.pop() if reg_stack else 0
                if val_reg: free_reg(val_reg)
                vm_code.extend(struct.pack('<BBBBi', 5, val_reg, 0, 0, name_set[av]))

        if on == 'UNPACK_EX':
            nbefore = arg & 0xFF
            nafter = (arg >> 8) & 0xFF
            seq_reg = reg_stack.pop() if reg_stack else 0
            free_reg(seq_reg)
            new_regs = []
            for _ in range(nbefore + nafter + 1):
                rd = alloc_reg()
                reg_stack.append(rd)
                new_regs.append(rd)
            base_reg = new_regs[0] if new_regs else 0
            vm_code.extend(struct.pack('<BBBBi', 136, base_reg, seq_reg, nafter, nbefore))

        if on == 'UNPACK_SEQUENCE':
            seq_reg = reg_stack.pop() if reg_stack else 0
            free_reg(seq_reg)
            new_regs = []
            for _ in range(arg):
                rd = alloc_reg()
                reg_stack.append(rd)
                new_regs.append(rd)
            base_reg = new_regs[0] if new_regs else 0
            vm_code.extend(struct.pack('<BBBBi', 137, base_reg, seq_reg, 0, arg))

        if on == 'ENTER_EXECUTOR':
            exc_reg = reg_stack[-1] if reg_stack else 0
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 138, rd, exc_reg, 0, 0))

        if on == 'END_SEND':
            if reg_stack:
                rs = reg_stack.pop()
                free_reg(rs)
            vm_code.extend(struct.pack('<BBBBi', 180, 0, 0, 0, 0))

        if on == 'YIELD_VALUE':
            pass  # Already handled above

        # STORE_FAST_MAYBE_NULL (Py 3.14+) — like STORE_FAST but allows None
        if on == 'STORE_FAST_MAYBE_NULL':
            ni(av)
            if reg_stack:
                rs = reg_stack.pop()
                free_reg(rs)
            else:
                rs = 0
            vm_code.extend(struct.pack('<BBBBi', 139, rs, 0, 0, name_set[av]))

    # ─── Patch all jump targets to use actual VM slots ───
    for _pos, _target_off in _jump_patches:
        _actual_target = _py_off_to_vm_slot.get(_target_off)
        if _actual_target is None:
            # Search forward for next valid offset (same fallback logic as vm_target)
            _o = _target_off
            while _o not in _py_off_to_vm_slot and _o < 65536:
                _o += 2
            _actual_target = _py_off_to_vm_slot.get(_o, len(vm_code) // 8)
        struct.pack_into('<i', vm_code, _pos, _actual_target)

    # Opaque predicates: insert random always-true/always-false dead code
    if opaque and next_reg > 0:
        used = list(range(min(next_reg, 16)))
        for _ in range(random.randint(1, 3)):
            reg = random.choice(used)
            pat = random.randint(0, 2)
            if random.random() < 0.5:
                vm_code.extend(struct.pack('<BBBBi', 52, reg, 0, 0, pat))
            else:
                vm_code.extend(struct.pack('<BBBBi', 53, reg, 0, 0, pat))

    # Serialize
    out = bytearray()
    
    # Apply Junk Insertion to bytecode (only when opaque flag set — otherwise breaks jump targets!)
    if opaque:
        vm_code = insert_junk(vm_code)
    
    # Consts
    out += struct.pack('<I', len(all_consts))
    for v in all_consts:
        if v is None:
            out += struct.pack('<B', 0) + struct.pack('<I', 0)
        elif isinstance(v, bool):
            s = b'1' if v else b'0'
            out += struct.pack('<B', 1) + struct.pack('<I', len(s)) + s
        elif isinstance(v, int):
            s = str(v).encode()
            out += struct.pack('<B', 2) + struct.pack('<I', len(s)) + s
        elif isinstance(v, float):
            s = repr(v).encode()
            out += struct.pack('<B', 3) + struct.pack('<I', len(s)) + s
        elif isinstance(v, str):
            s = v.encode('utf-8')
            out += struct.pack('<B', 4) + struct.pack('<I', len(s)) + s
        elif isinstance(v, tuple):
            s = repr(v).encode()
            out += struct.pack('<B', 6) + struct.pack('<I', len(s)) + s
        elif isinstance(v, bytes):
            s = v
            out += struct.pack('<B', 7) + struct.pack('<I', len(s)) + s
        else:
            s = repr(v).encode()
            out += struct.pack('<B', 8) + struct.pack('<I', len(s)) + s

    # Names
    out += struct.pack('<I', len(name_list))
    for n in name_list:
        s = n.encode('utf-8')
        out += struct.pack('<H', len(s)) + s

    # Instrs
    out += struct.pack('<I', len(vm_code) // 8)
    out += bytes(vm_code)

    sys.stdout.buffer.write(bytes(out))

if __name__ == '__main__':
    src = sys.stdin.read()
    if not src:
        sys.stderr.write("error: no input\n")
        sys.exit(1)
    opaque_flag = 0
    seed_val = -1
    i = 1
    while i < len(sys.argv):
        if sys.argv[i] == '--opaque':
            opaque_flag = 1
        elif sys.argv[i] == '--seed' and i + 1 < len(sys.argv):
            seed_val = int(sys.argv[i + 1])
            i += 1
        i += 1
    if seed_val >= 0:
        random.seed(seed_val)
    try:
        convert(src, opaque_flag)
    except Exception as e:
        sys.stderr.write(f"error: {e}\n")
        sys.exit(1)
)vm_compile";
#endif
