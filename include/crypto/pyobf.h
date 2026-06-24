#ifndef CRYPTO_PYOBF_H
#define CRYPTO_PYOBF_H

/*
 * THIS FILE IS AUTO-GENERATED from include/crypto/pyobf_core.py
 * by tools/generate_pyobf_h.py.  Do NOT edit directly.
 *
 * To regenerate:
 *     python3 tools/generate_pyobf_h.py
 */

static const char PYOBF_SCRIPT[] = R"pyobf_script(
#!/usr/bin/env python3
"""Core obfuscation logic for Crypto Python Script Protector."""

import ast
import random
import base64
import hashlib
import sys
import re as _re


def _rand_name(prefix='_'):
    length = random.randint(6, 12)
    return prefix + ''.join(random.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(length))


def _rand_int(lo=1, hi=999999):
    return random.randint(lo, hi)


def obfuscate(techniques, source, seed=None):
    if seed is not None:
        random.seed(seed)
    techs = [t.strip() for t in techniques.split(',')]
    has_all = 'all' in techs
    pipeline = [
        ('cleanup', cleanup_code),
        ('rename', rename_code),
        ('vstrings', virtualize_strings),
        ('strings', encrypt_strings),
        ('aflow', flatten_advanced),
        ('flow', flatten_control_flow),
        ('opaque', encode_state),
        ('mutate', mutate_expressions),
        ('mba', mba_obfuscate),
        ('junk', inject_junk),
        ('apihash', apihash_obfuscate),
        ('funcenc', funcenc_obfuscate),
    ]
    for name, func in pipeline:
        if has_all or name in techs:
            if name == 'strings' and ('vstrings' in techs or has_all):
                continue  # vstrings supersedes strings
            source = func(source)
    return source


def cleanup_code(source):
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source

    class Cleaner(ast.NodeTransformer):
        def visit_Module(self, node):
            node.body = [n for n in node.body if not self._is_removable(n)]
            self.generic_visit(node)
            return node

        def visit_FunctionDef(self, node):
            if (node.body and isinstance(node.body[0], ast.Expr)
                    and isinstance(node.body[0].value, ast.Constant)
                    and isinstance(node.body[0].value.value, str)):
                node.body.pop(0)
            self.generic_visit(node)
            return node

        def _is_removable(self, node):
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
                return isinstance(node.value.value, (str, bytes, int, float, complex))
            return False

    tree = Cleaner().visit(tree)
    ast.fix_missing_locations(tree)
    return ast.unparse(tree)


def rename_code(source):
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source

    names_seen = set()
    imported_names = set()

    class NameCollector(ast.NodeVisitor):
        def visit_Name(self, node):
            names_seen.add(node.id)
            self.generic_visit(node)
        def visit_FunctionDef(self, node):
            names_seen.add(node.name)
            self.generic_visit(node)
        def visit_AsyncFunctionDef(self, node):
            names_seen.add(node.name)
            self.generic_visit(node)
        def visit_ClassDef(self, node):
            names_seen.add(node.name)
            self.generic_visit(node)
        def visit_arg(self, node):
            names_seen.add(node.arg)
            self.generic_visit(node)
        def visit_Import(self, node):
            for alias in node.names:
                local = alias.asname or alias.name
                imported_names.add(local)
        def visit_ImportFrom(self, node):
            for alias in node.names:
                local = alias.asname or alias.name
                imported_names.add(local)

    NameCollector().visit(tree)

    skip_words = {
        'True','False','None','self','cls','super','import','from','as',
        'def','class','return','if','elif','else','for','while','try',
        'except','finally','with','pass','break','continue','raise','yield',
        'lambda','and','or','not','in','is','del','global','nonlocal',
        'assert','async','await','print','range','len','str','int','float',
        'list','dict','tuple','set','type','Exception','BaseException',
        'StopIteration','ValueError','TypeError','KeyError','IndexError',
        'AttributeError','ImportError','RuntimeError','NameError',
        'UnboundLocalError','OSError','IOError','FileNotFoundError',
        'PermissionError','NotImplementedError',
        'min','max','sum','abs','all','any','sorted','reversed',
        'enumerate','zip','map','filter','eval','exec','compile','open',
        'property','staticmethod','classmethod','memoryview','bytearray',
        'bytes','chr','ord','bin','oct','hex','callable','delattr',
        'getattr','setattr','hasattr','isinstance','issubclass',
        'id','repr','ascii','format','vars','dir','locals','globals',
        'hash','divmod','pow','round','iter','next','slice','object',
        'super','copyright','credits','license',
        '__name__','__main__','__file__','__doc__','__builtins__',
        'state',  # Python async generator internal state variable
    }

    name_map = {}
    for n in names_seen:
        if n not in skip_words and n not in imported_names \
                and not (n.startswith('__') and n.endswith('__')):
            name_map[n] = _rand_name()

    if not name_map:
        return source

    class Renamer(ast.NodeTransformer):
        def __init__(self):
            # Track if we're inside top-level of a class body to avoid
            # renaming method names within classes.
            self._in_class = 0

        def visit_ClassDef(self, node):
            self._in_class += 1
            if node.name in name_map:
                node.name = name_map[node.name]
            self.generic_visit(node)
            self._in_class -= 1
            return node

        def visit_Name(self, node):
            if node.id in name_map:
                node.id = name_map[node.id]
            return node

        def visit_Attribute(self, node):
            # NEVER rename attributes — self.value / node.value / obj.attr
            # access sites may not all be visible from the class definition.
            # Renaming only self.attr would create inconsistency with
            # instance.attr (not renamed) and break the code.
            self.generic_visit(node)
            return node

        def visit_FunctionDef(self, node):
            # Rename function names only outside class bodies (standalone functions)
            if node.name in name_map and self._in_class == 0:
                node.name = name_map[node.name]
            self.generic_visit(node)
            return node

        def visit_AsyncFunctionDef(self, node):
            if node.name in name_map and self._in_class == 0:
                node.name = name_map[node.name]
            self.generic_visit(node)
            return node

        def visit_arg(self, node):
            if node.arg in name_map:
                node.arg = name_map[node.arg]
            self.generic_visit(node)
            return node

        def visit_keyword(self, node):
            if node.arg is not None and node.arg in name_map:
                node.arg = name_map[node.arg]
            self.generic_visit(node)
            return node

    tree = Renamer().visit(tree)
    ast.fix_missing_locations(tree)
    return ast.unparse(tree)


def encrypt_strings(source):
    key = bytes([random.randint(1, 255) for _ in range(32)])
    key_b64 = base64.b64encode(key).decode('ascii')
    func_name = _rand_name('_es')
    stub = (
        f"def {func_name}(_s):\n"
        f"    _k = base64.b64decode('{key_b64}')\n"
        f"    _d = base64.b64decode(_s)\n"
        f"    _e = bytes(_d[i] ^ _k[i % len(_k)] for i in range(len(_d)))\n"
        f"    return _e.decode('utf-8')\n"
    )
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source

    class StringEncryptor(ast.NodeTransformer):
        def visit_JoinedStr(self, node):
            # Don't transform string constants inside f-strings
            # (Call nodes inside JoinedStr break ast.unparse in Python 3.14+)
            return node

        def visit_Constant(self, node):
            if isinstance(node.value, str) and len(node.value) > 3:
                s = node.value.encode('utf-8')
                enc = bytes(s[i] ^ key[i % len(key)] for i in range(len(s)))
                b64_s = base64.b64encode(enc).decode('ascii')
                return ast.Call(
                    func=ast.Name(id=func_name, ctx=ast.Load()),
                    args=[ast.Constant(value=b64_s)],
                    keywords=[]
                )
            return node

    tree = StringEncryptor().visit(tree)
    ast.fix_missing_locations(tree)
    return 'import base64\n' + stub + ast.unparse(tree)


def virtualize_strings(source):
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source

    stubs = []

    class StringVirtualizer(ast.NodeTransformer):
        def visit_JoinedStr(self, node):
            # Don't transform string constants inside f-strings
            # (Call nodes inside JoinedStr break ast.unparse in Python 3.14+)
            return node

        def visit_Constant(self, node):
            if isinstance(node.value, str) and len(node.value) > 2:
                s = node.value.encode('utf-8')
                xor_key = random.randint(1, 255)
                hex_chunks = []
                for i in range(0, len(s), 8):
                    chunk = s[i:i+8]
                    hex_chunks.append(chunk.hex())
                encoded_chunks = []
                for ch in hex_chunks:
                    xored = ''.join(chr(ord(c) ^ xor_key) if ord(c) < 256 else c for c in ch)
                    encoded_chunks.append(base64.b64encode(xored.encode('latin-1')).decode())
                func_name = _rand_name('_s')
                chunks_repr = ', '.join(repr(c) for c in encoded_chunks)
                stub_code = (
                    f"def {func_name}():\n"
                    f"    _k = {xor_key}\n"
                    f"    _c = [{chunks_repr}]\n"
                    f"    _r = []\n"
                    f"    for _x in _c:\n"
                    f"        _d = base64.b64decode(_x).decode('latin-1')\n"
                    f"        _h = ''.join(chr(ord(c) ^ _k) for c in _d)\n"
                    f"        _r.append(bytes.fromhex(_h).decode('utf-8'))\n"
                    f"    return ''.join(_r)\n"
                )
                stubs.append(stub_code)
                return ast.Call(
                    func=ast.Name(id=func_name, ctx=ast.Load()),
                    args=[], keywords=[]
                )
            return node

    tree = StringVirtualizer().visit(tree)
    ast.fix_missing_locations(tree)
    return '\n'.join(stubs) + '\nimport base64\n' + ast.unparse(tree)


def flatten_control_flow(source):
    return flatten_advanced(source)


def flatten_advanced(source):
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source

    class AdvancedFlattener(ast.NodeTransformer):
        def __init__(self):
            self.state_var = _rand_name('_st')

        def visit_FunctionDef(self, node):
            self.generic_visit(node)
            has_if = any(isinstance(stmt, ast.If) for stmt in node.body)
            if not has_if:
                return node

            # Pass 1: count how many states each statement contributes.
            # Each If stmt produces:
            #   1 preamble (evaluates stmt.test → branches to true/else label)
            #   1 true-body block
            #   +1 else-body block if orelse is non-empty
            # Each non-If stmt produces 1 state block.
            state_counts = []
            for stmt in node.body:
                if isinstance(stmt, ast.If):
                    n = 2  # preamble + true-body
                    if stmt.orelse:
                        n += 1  # else-body
                    state_counts.append(n)
                else:
                    state_counts.append(1)

            # Derive starting label for each statement
            start_labels = []
            cur = 0
            for c in state_counts:
                start_labels.append(cur)
                cur += c
            state_end = cur

            sv = self.state_var
            blocks = []  # (label, body_list) in label order

            # Pass 2: build preamble + true/else-body state blocks per statement
            for i, stmt in enumerate(node.body):
                if isinstance(stmt, ast.If):
                    preamble_label = start_labels[i]
                    true_label = start_labels[i] + 1
                    next_label = start_labels[i] + state_counts[i]
                    if next_label > state_end:
                        next_label = state_end

                    # --- Preamble: evaluate condition and jump ---
                    if stmt.orelse:
                        else_label = start_labels[i] + 2
                        preamble_body = [ast.If(
                            test=stmt.test,
                            body=[ast.Assign(
                                targets=[ast.Name(id=sv, ctx=ast.Store())],
                                value=ast.Constant(value=true_label)
                            )],
                            orelse=[ast.Assign(
                                targets=[ast.Name(id=sv, ctx=ast.Store())],
                                value=ast.Constant(value=else_label)
                            )]
                        )]
                    else:
                        preamble_body = [ast.If(
                            test=stmt.test,
                            body=[ast.Assign(
                                targets=[ast.Name(id=sv, ctx=ast.Store())],
                                value=ast.Constant(value=true_label)
                            )],
                            orelse=[ast.Assign(
                                targets=[ast.Name(id=sv, ctx=ast.Store())],
                                value=ast.Constant(value=next_label)
                            )]
                        )]

                    blocks.append((preamble_label, preamble_body))

                    # --- True-body block ---
                    blocks.append((true_label, stmt.body + [ast.Assign(
                        targets=[ast.Name(id=sv, ctx=ast.Store())],
                        value=ast.Constant(value=next_label)
                    )]))

                    # --- Else-body block (if any; may contain elif as nested If) ---
                    if stmt.orelse:
                        else_label = start_labels[i] + 2
                        blocks.append((else_label, stmt.orelse + [ast.Assign(
                            targets=[ast.Name(id=sv, ctx=ast.Store())],
                            value=ast.Constant(value=next_label)
                        )]))

                else:
                    stmt_label = start_labels[i]
                    nxt = start_labels[i] + 1
                    if nxt > state_end:
                        nxt = state_end
                    blocks.append((stmt_label, [stmt] + [ast.Assign(
                        targets=[ast.Name(id=sv, ctx=ast.Store())],
                        value=ast.Constant(value=nxt)
                    )]))

            # --- Build the while loop body ---
            while_body = []
            for label_val, body in blocks:
                cond = ast.Compare(
                    left=ast.Name(id=sv, ctx=ast.Load()),
                    ops=[ast.Eq()],
                    comparators=[ast.Constant(value=label_val)]
                )
                while_body.append(ast.If(test=cond, body=body, orelse=[]))

            # Exit guard
            while_body.append(ast.If(
                test=ast.Compare(
                    left=ast.Name(id=sv, ctx=ast.Load()),
                    ops=[ast.GtE()],
                    comparators=[ast.Constant(value=state_end)]
                ),
                body=[ast.Break()],
                orelse=[]
            ))

            state_assign = ast.Assign(
                targets=[ast.Name(id=sv, ctx=ast.Store())],
                value=ast.Constant(value=0)
            )

            node.body = [state_assign, ast.While(
                test=ast.Constant(value=True),
                body=while_body,
                orelse=[]
            )]
            return node

    tree = AdvancedFlattener().visit(tree)
    ast.fix_missing_locations(tree)
    return ast.unparse(tree)


def encode_state(source):
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source

    class OpaqueInserter(ast.NodeTransformer):
        def __init__(self):
            self.count = 0

        def visit_FunctionDef(self, node):
            self.generic_visit(node)
            new_body = []
            for stmt in node.body:
                new_body.append(stmt)
                if random.random() < 0.15 and self.count < 10:
                    x = _rand_int(1, 1000)
                    p = _rand_name('_p')
                    q = _rand_name('_q')
                    lines = [
                        f"{p} = {x}",
                        f"{q} = ({p} * ({p} + 1)) % 2",
                        f"if {q}:",
                        f"    pass",
                    ]
                    try:
                        new_body.extend(ast.parse('\n'.join(lines)).body)
                    except SyntaxError:
                        pass
                    self.count += 1
            node.body = new_body
            return node

    tree = OpaqueInserter().visit(tree)
    ast.fix_missing_locations(tree)
    return ast.unparse(tree)


def mutate_expressions(source):
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source

    class Mutator(ast.NodeTransformer):
        def _is_int_const(self, node):
            return isinstance(node, ast.Constant) and isinstance(node.value, int)

        def _both_int(self, node):
            return self._is_int_const(node.left) and self._is_int_const(node.right)

        def visit_BinOp(self, node):
            self.generic_visit(node)
            if not self._both_int(node):
                return node
            if isinstance(node.op, ast.Add) and random.random() < 0.3:
                return ast.BinOp(
                    left=ast.BinOp(left=node.left, op=ast.BitXor(), right=node.right),
                    op=ast.Add(),
                    right=ast.BinOp(
                        left=ast.Constant(value=2), op=ast.Mult(),
                        right=ast.BinOp(left=node.left, op=ast.BitAnd(), right=node.right)
                    )
                )
            elif isinstance(node.op, ast.Sub) and random.random() < 0.3:
                return ast.BinOp(
                    left=ast.BinOp(left=node.left, op=ast.Add(),
                                   right=ast.UnaryOp(op=ast.Invert(), operand=node.right)),
                    op=ast.Add(),
                    right=ast.Constant(value=1)
                )
            return node

    tree = Mutator().visit(tree)
    ast.fix_missing_locations(tree)
    return ast.unparse(tree)


def mba_obfuscate(source):
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source

    class MBAT(ast.NodeTransformer):
        def _is_int_const(self, node):
            return isinstance(node, ast.Constant) and isinstance(node.value, int)

        def _both_int(self, node):
            return self._is_int_const(node.left) and self._is_int_const(node.right)

        def visit_BinOp(self, node):
            self.generic_visit(node)
            # Only apply MBA to operations with integer constant operands.
            # XOR on floats is unsupported in Python, so we skip MBA when
            # operands could be floats (variables, function calls, etc).
            if not self._both_int(node):
                return node
            if isinstance(node.op, ast.Add) and random.random() < 0.3:
                return ast.BinOp(
                    left=ast.BinOp(left=node.left, op=ast.BitXor(), right=node.right),
                    op=ast.Add(),
                    right=ast.BinOp(left=ast.Constant(value=2), op=ast.Mult(),
                                   right=ast.BinOp(left=node.left, op=ast.BitAnd(), right=node.right))
                )
            elif isinstance(node.op, ast.Sub) and random.random() < 0.3:
                return ast.BinOp(
                    left=ast.BinOp(left=node.left, op=ast.BitXor(), right=node.right),
                    op=ast.Sub(),
                    right=ast.BinOp(left=ast.Constant(value=2), op=ast.Mult(),
                                   right=ast.BinOp(
                                       left=ast.UnaryOp(op=ast.Invert(), operand=node.left),
                                       op=ast.BitAnd(), right=node.right))
                )
            elif isinstance(node.op, ast.BitXor) and random.random() < 0.3:
                return ast.BinOp(
                    left=ast.BinOp(left=node.left, op=ast.BitOr(), right=node.right),
                    op=ast.Sub(),
                    right=ast.BinOp(left=node.left, op=ast.BitAnd(), right=node.right)
                )
            return node

    tree = MBAT().visit(tree)
    ast.fix_missing_locations(tree)
    return ast.unparse(tree)


def inject_junk(source):
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source

    class JunkInjector(ast.NodeTransformer):
        def __init__(self):
            self.count = 0

        def visit_FunctionDef(self, node):
            self.generic_visit(node)
            new_body = []
            for stmt in node.body:
                new_body.append(stmt)
                if random.random() < 0.1 and self.count < 10:
                    x = _rand_int()
                    y = _rand_int()
                    lines = [
                        f"_x = {x}",
                        f"_y = {y}",
                        f"_z = (_x * _y) ^ (_x + _y)",
                    ]
                    try:
                        new_body.extend(ast.parse('\n'.join(lines)).body)
                    except SyntaxError:
                        pass
                    self.count += 1
            node.body = new_body
            return node

    tree = JunkInjector().visit(tree)
    ast.fix_missing_locations(tree)
    return ast.unparse(tree)


def apihash_obfuscate(source):
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source

    replacements = []

    class ApiHashTransformer(ast.NodeTransformer):
        def visit_Import(self, node):
            for alias in node.names:
                newname = _rand_name('_m')
                localname = alias.asname or alias.name
                # Add dynamic import with hashed name
                replacements.append(f"{newname} = __import__('{alias.name}')")
                # Create alias so original name still works
                if localname != newname:
                    replacements.append(f"{localname} = {newname}")
            # Keep the original import as well for compatibility
            return node

        def visit_ImportFrom(self, node):
            for alias in node.names:
                newname = _rand_name('_m')
                localname = alias.asname or alias.name
                modname = f"{node.module}.{alias.name}" if node.module else alias.name
                replacements.append(f"{newname} = __import__('{node.module}', fromlist=['{alias.name}']).{alias.name}")
                if localname != newname:
                    replacements.append(f"{localname} = {newname}")
            # Keep the original import as well
            return node

        def visit_Module(self, node):
            self.generic_visit(node)
            if replacements:
                try:
                    prefix = ast.parse('\n'.join(replacements))
                    node.body = prefix.body + node.body
                except Exception:
                    pass
            return node

    tree = ApiHashTransformer().visit(tree)
    ast.fix_missing_locations(tree)
    return ast.unparse(tree)


# funcenc DISABLED - Python's exec() fundamentally cannot preserve function scope chains.
# When a function body is encrypted and decrypted via exec(compile(...), globals()),
# enclosing locals/nonlocals are NOT visible to the executed code.
# This is a Python language limitation, not a code bug. So funcenc is disabled.
def funcenc_obfuscate(source):
    """DISABLED: funcenc breaks closures, nonlocal, and global scoping in Python."""
    return source  # No-op



if __name__ == '__main__':
    techniques = [t.strip() for t in sys.argv[1].split(',')] \
        if len(sys.argv) > 1 else ['all']
    seed = int(sys.argv[2]) if len(sys.argv) > 2 else None

    source = sys.stdin.read()
    has_all = 'all' in techniques

    if seed is not None:
        random.seed(seed)

    if has_all or 'cleanup' in techniques:
        source = cleanup_code(source)
    if has_all or 'rename' in techniques:
        source = rename_code(source)
    if has_all or 'vstrings' in techniques:
        source = virtualize_strings(source)
    elif 'strings' in techniques:
        source = encrypt_strings(source)
    if has_all or 'aflow' in techniques:
        source = flatten_advanced(source)
    elif 'flow' in techniques:
        source = flatten_control_flow(source)
    if has_all or 'opaque' in techniques:
        source = encode_state(source)
    if has_all or 'mutate' in techniques:
        source = mutate_expressions(source)
    if has_all or 'mba' in techniques:
        source = mba_obfuscate(source)
    if has_all or 'junk' in techniques:
        source = inject_junk(source)
    if has_all or 'apihash' in techniques:
        source = apihash_obfuscate(source)

    if has_all or 'funcenc' in techniques:
        source = funcenc_obfuscate(source)

    sys.stdout.write(source)

)pyobf_script";

#endif /* CRYPTO_PYOBF_H */
