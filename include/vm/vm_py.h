#ifndef CRYPTO_VM_PY_H
#define CRYPTO_VM_PY_H

static const char VM_COMPILE_SCRIPT[] = R"vm_compile(
import sys, dis, struct, types, random

BINOP_MAP = {'+':10, '-':11, '*':12, '/':13, '**':14, '|':16, '&':17, '^':18, '<<':19, '>>':20, '//':21, '%':22}
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
        elif _n.startswith('LOAD_') and _n not in ('LOAD_CONST', 'LOAD_NAME', 'LOAD_GLOBAL', 'LOAD_FAST', 'LOAD_SMALL_INT', 'LOAD_BUILD_CLASS', 'LOAD_FAST_AND_CLEAR', 'LOAD_FAST_BORROW', 'LOAD_FAST_BORROW_LOAD_FAST_BORROW'):
            _op = getattr(dis.opmap, _n, None)
            if _op is not None:
                SPECIAL_MAP[_n] = 'LOAD_NAME'
        elif _n.startswith('STORE_') and _n not in ('STORE_NAME', 'STORE_GLOBAL', 'STORE_FAST', 'STORE_SUBSCR'):
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
            _ii += 1; continue
        if on == 'STORE_NAME' and _saved == 'MAKE_FUNCTION':
            _ii += 1; continue
        if on == 'MAKE_FUNCTION':
            _ii += 1; continue
        off2vm[instr.offset] = vm_idx
        vm_idx += 1
        _ii += 1

    # Reset state for main compilation pass
    vm_code = bytearray()
    prev_op = None
    _ii = 0
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
            continue  # skip non-IIFE code object (function definition)

        if on == 'POP_TOP':
            if reg_stack:
                free_reg(reg_stack.pop())
            continue
        if on in ('RESUME', 'PUSH_NULL', 'POP_TOP', 'NOP', 'PRECALL', 'CACHE', 'NOT_TAKEN', 'MAKE_FUNCTION', 'TO_BOOL'):
            continue
        if on == 'STORE_NAME' and prev_op_saved == 'MAKE_FUNCTION':
            continue

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

        if on == 'SWAP':
            if len(reg_stack) >= 2:
                reg_stack[-1], reg_stack[-2] = reg_stack[-2], reg_stack[-1]
            # No VM instruction needed - just reorder the register stack

        if on == 'LIST_APPEND':
            if reg_stack:
                val_reg = reg_stack.pop()
                free_reg(val_reg)
            else:
                val_reg = 0
            list_reg = reg_stack[-1] if reg_stack else 0
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
            # First, save any live registers that would be overwritten by MOVE targets.
            _live = set(reg_stack)
            _saved = {}
            for _i, _a in enumerate(args):
                _tgt = fn_reg + 1 + _i
                if _tgt in _live and _tgt not in _saved:
                    _tmp = alloc_reg()
                    vm_code.extend(struct.pack('<BBBBi', 6, _tmp, _tgt, 0, 0))
                    _saved[_tgt] = _tmp
                    reg_stack[reg_stack.index(_tgt)] = _tmp
            # Now generate MOVE instructions for each arg (source → target).
            # Handle source/target overlap: if a source reg is also a target, use the saved copy.
            for _i, _a in enumerate(args):
                _tgt = fn_reg + 1 + _i
                if _a == _tgt:
                    continue
                if _a in _saved:
                    vm_code.extend(struct.pack('<BBBBi', 6, _tgt, _saved[_a], 0, 0))
                elif _tgt in _saved:
                    vm_code.extend(struct.pack('<BBBBi', 6, _tgt, _a, 0, 0))
                else:
                    vm_code.extend(struct.pack('<BBBBi', 6, _tgt, _a, 0, 0))
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
                iter_reg = reg_stack.pop()
                # Don't free iter_reg — keep it alive for next iterations
            else:
                iter_reg = 0
            target = dis._get_jump_target(instr.opcode, instr.arg, instr.offset)
            vm_idx_target = vm_target(target)
            rd = alloc_reg()
            reg_stack.append(rd)
            vm_code.extend(struct.pack('<BBBBi', 71, rd, iter_reg, 0, vm_idx_target))

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
            vm_idx_target = vm_target(target)
            vm_code.extend(struct.pack('<BBBBi', 30, 0, 0, 0, vm_idx_target))

        if on in ('POP_JUMP_IF_TRUE', 'POP_JUMP_IF_NOT_NONE'):
            if reg_stack:
                rs = reg_stack.pop()
                free_reg(rs)
            else:
                rs = 0
            target = dis._get_jump_target(instr.opcode, instr.arg, instr.offset)
            vm_idx_target = vm_target(target)
            vm_code.extend(struct.pack('<BBBBi', 31, rs, 0, 0, vm_idx_target))

        if on in ('POP_JUMP_IF_FALSE', 'POP_JUMP_IF_NONE'):
            if reg_stack:
                rs = reg_stack.pop()
                free_reg(rs)
            else:
                rs = 0
            target = dis._get_jump_target(instr.opcode, instr.arg, instr.offset)
            vm_idx_target = vm_target(target)
            vm_code.extend(struct.pack('<BBBBi', 32, rs, 0, 0, vm_idx_target))

        if on == 'JUMP_BACKWARD':
            target = dis._get_jump_target(instr.opcode, instr.arg, instr.offset)
            vm_idx_target = vm_target(target)
            vm_code.extend(struct.pack('<BBBBi', 30, 0, 0, 0, vm_idx_target))

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

    # Use original source for hot path (already valid Python)
    hot_bytes = source.encode('utf-8')

    # Serialize
    out = bytearray()

    # Hot source
    out += struct.pack('<I', len(hot_bytes))
    out += hot_bytes

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
    if len(sys.argv) > 1 and sys.argv[1] == '--opaque':
        opaque_flag = 1
    try:
        convert(src, opaque_flag)
    except Exception as e:
        sys.stderr.write(f"error: {e}\n")
        sys.exit(1)
)vm_compile";
#endif
