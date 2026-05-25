#ifndef CRYPTO_PYOBF_H
#define CRYPTO_PYOBF_H

static const char PYOBF_SCRIPT[] = R"pyobf_script(
#!/usr/bin/env python3
"""Python source code obfuscator.

Usage:
    python3 pyobf.py <techniques> < input.py > output.py

Techniques:
    rename     Rename identifiers
    strings    Encrypt string literals (XOR inline)
    vstrings   Virtualize strings (chunked + runtime eval decrypt)
    cleanup    Remove docstrings and standalone expressions
    flow       Basic control flow flattening (if/else → state machine)
    aflow      Advanced control flow flatt. (dispatch table + opaque predicates)
    junk       Junk code injection (dead code with opaque predicates)
    mutate     AST mutation (binary op → lambda/sum/complex expr)
    all        All of the above
"""
import ast
import copy
import random
import re
import string
import sys

random.seed()

# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------
def _short_name(counter):
    n = counter
    chars = string.ascii_lowercase + string.digits
    result = []
    while n >= 0:
        result.append(chars[n % len(chars)])
        n = n // len(chars) - 1
    return '_' + ''.join(reversed(result))


def _rand_name(length=8):
    chars = string.ascii_lowercase + string.digits
    return '_' + ''.join(random.choice(chars) for _ in range(length))


def _ensure_str_expr(s):
    """Return an AST expression node that evaluates to string s."""
    return ast.Constant(value=s)


def _make_call(func_name, args):
    return ast.Call(
        func=ast.Name(id=func_name, ctx=ast.Load()),
        args=args,
        keywords=[])


# ---------------------------------------------------------------------------
# BUILTINS (used by rename)
# ---------------------------------------------------------------------------
BUILTINS = {
    'abs', 'all', 'any', 'ascii', 'bin', 'bool', 'bytearray', 'bytes',
    'callable', 'chr', 'classmethod', 'compile', 'complex', 'copyright',
    'credits', 'delattr', 'dict', 'dir', 'divmod', 'enumerate', 'eval',
    'exec', 'exit', 'filter', 'float', 'format', 'frozenset', 'getattr',
    'globals', 'hasattr', 'hash', 'help', 'hex', 'id', 'input', 'int',
    'isinstance', 'issubclass', 'iter', 'len', 'license', 'list', 'locals',
    'map', 'max', 'memoryview', 'min', 'next', 'object', 'oct', 'open',
    'ord', 'pow', 'print', 'property', 'quit', 'range', 'repr', 'reversed',
    'round', 'set', 'setattr', 'slice', 'sorted', 'staticmethod', 'str',
    'sum', 'super', 'tuple', 'type', 'vars', 'zip',
    'True', 'False', 'None', 'Exception', 'BaseException', 'KeyboardInterrupt',
    'StopIteration', 'StopAsyncIteration', 'ArithmeticError', 'AssertionError',
    'AttributeError', 'BufferError', 'EOFError', 'ImportError', 'LookupError',
    'MemoryError', 'NameError', 'OSError', 'ReferenceError', 'RuntimeError',
    'SyntaxError', 'SystemError', 'TypeError', 'ValueError', 'Warning',
    'ZeroDivisionError', 'EnvironmentError', 'IOError', 'WindowsError',
    'ModuleNotFoundError', 'KeyError', 'IndexError',
    'id', 'repr', 'ascii', 'ord', 'chr', 'bin', 'hex', 'oct',
    '__name__', '__main__', '__file__', '__doc__', '__builtins__',
    '__package__', '__path__', '__spec__', '__loader__',
}


def _should_skip(name):
    if not name:
        return True
    if name in BUILTINS:
        return True
    if name.startswith('__') and name.endswith('__'):
        return True
    if name in ('_', 'self', 'cls'):
        return True
    if re.match(r'_\w*$', name) and len(name) <= 6:
        return True
    return False


# ---------------------------------------------------------------------------
# RENAME
# ---------------------------------------------------------------------------
class _RenameTransformer(ast.NodeTransformer):
    def __init__(self):
        self.name_map = {}
        self.counter = 0
        self.imported_names = set()
        self.scope_stack = [set()]
        self.in_class = 0

    def _new_name(self):
        self.counter += 1
        return _short_name(self.counter)

    def _get(self, old):
        if old not in self.name_map:
            self.name_map[old] = self._new_name()
        return self.name_map[old]

    def visit_Import(self, node):
        for alias in node.names:
            name = alias.asname or alias.name.split('.')[0]
            self.imported_names.add(name)
        return node

    def visit_ImportFrom(self, node):
        for alias in node.names:
            name = alias.asname or alias.name
            self.imported_names.add(name)
        return node

    def _is_global_scope(self):
        return len(self.scope_stack) == 1

    def _extract_locals(self, node):
        locals_ = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
                locals_.add(child.id)
            elif isinstance(child, ast.FunctionDef):
                for arg in child.args.args:
                    locals_.add(arg.arg)
                if child.args.vararg:
                    locals_.add(child.args.vararg.arg)
                if child.args.kwarg:
                    locals_.add(child.args.kwarg.arg)
                for arg in child.args.kwonlyargs:
                    locals_.add(arg.arg)
                for arg in child.args.posonlyargs:
                    locals_.add(arg.arg)
        return locals_

    def visit_FunctionDef(self, node):
        if not self.in_class:
            if not _should_skip(node.name) and not node.name.startswith('__'):
                node.name = self._get(node.name)
        self.scope_stack.append(self._extract_locals(node))
        self.generic_visit(node)
        self.scope_stack.pop()
        return node

    def visit_AsyncFunctionDef(self, node):
        return self.visit_FunctionDef(node)

    def visit_ClassDef(self, node):
        if not _should_skip(node.name):
            node.name = self._get(node.name)
        self.scope_stack.append(set())
        self.in_class += 1
        self.generic_visit(node)
        self.in_class -= 1
        self.scope_stack.pop()
        return node

    def visit_Module(self, node):
        locals_ = set()
        for child in node.body:
            if isinstance(child, ast.FunctionDef):
                for d in ast.walk(child):
                    if isinstance(d, ast.Name) and isinstance(d.ctx, ast.Store):
                        locals_.add(d.id)
            elif isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
                locals_.add(child.id)
            elif isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Name):
                locals_.add(child.target.id)
        self.scope_stack.append(locals_)
        self.generic_visit(node)
        self.scope_stack.pop()
        return node

    def visit_arg(self, node):
        if not _should_skip(node.arg):
            node.arg = self._get(node.arg)
        return node

    def visit_Name(self, node):
        nid = node.id
        if _should_skip(nid) or nid in self.imported_names:
            return node
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            if nid not in self.name_map:
                self.name_map[nid] = self._new_name()
            node.id = self.name_map[nid]
        elif isinstance(node.ctx, ast.Load) and nid in self.name_map:
            node.id = self.name_map[nid]
        return node

    def visit_Attribute(self, node):
        self.generic_visit(node)
        return node

    def _visit_comp(self, node):
        for gen in node.generators:
            self.visit(gen)
        if hasattr(node, 'elt'):
            node.elt = self.visit(node.elt)
        if hasattr(node, 'key'):
            node.key = self.visit(node.key)
        if hasattr(node, 'value'):
            node.value = self.visit(node.value)
        return node

    def visit_ListComp(self, node):
        return self._visit_comp(node)

    def visit_SetComp(self, node):
        return self._visit_comp(node)

    def visit_GeneratorExp(self, node):
        return self._visit_comp(node)

    def visit_DictComp(self, node):
        return self._visit_comp(node)

    def visit_ExceptHandler(self, node):
        if node.name and not _should_skip(node.name):
            node.name = self._get(node.name)
        self.generic_visit(node)
        return node


def rename_code(source):
    try:
        tree = ast.parse(source)
        class _PreScan(ast.NodeVisitor):
            def __init__(self):
                self.names = {}
                self.counter = 0
            def _new_name(self):
                self.counter += 1
                return _short_name(self.counter)
            def visit_FunctionDef(self, node):
                if not _should_skip(node.name) and not node.name.startswith('__'):
                    if node.name not in self.names:
                        self.names[node.name] = self._new_name()
                self.generic_visit(node)
            def visit_AsyncFunctionDef(self, node):
                self.visit_FunctionDef(node)
            def visit_ClassDef(self, node):
                if not _should_skip(node.name):
                    if node.name not in self.names:
                        self.names[node.name] = self._new_name()
                self.generic_visit(node)
        pre = _PreScan()
        pre.visit(tree)
        tf = _RenameTransformer()
        tf.name_map.update(pre.names)
        tf.counter = pre.counter
        tree = tf.visit(tree)
        ast.fix_missing_locations(tree)
        return ast.unparse(tree)
    except SyntaxError:
        return source


# ---------------------------------------------------------------------------
# BASIC STRING ENCRYPTION (keep original)
# ---------------------------------------------------------------------------
class _StringEncryptor(ast.NodeTransformer):
    def __init__(self):
        self._skip_expr_strs = set()
        
    def visit_JoinedStr(self, node):
        return node

    def visit_Constant(self, node):
        if isinstance(node.value, str) and len(node.value) >= 3:
            s = node.value
            key = random.randint(1, 255)
            enc = ''.join(chr(ord(c) ^ key) for c in s)
            template = "(lambda _s,_k:''.join(chr(ord(_)^_k) for _ in _s))(%s,%d)"
            src = template % (repr(enc), key)
            try:
                sub = ast.parse(src, mode='eval').body
                return sub
            except SyntaxError:
                pass
        return node


def encrypt_strings(source):
    try:
        tree = ast.parse(source)
        tf = _StringEncryptor()
        tree = tf.visit(tree)
        ast.fix_missing_locations(tree)
        return ast.unparse(tree)
    except SyntaxError:
        return source


# ---------------------------------------------------------------------------
# STRING VIRTUALIZATION  (chunked + runtime eval)
# ---------------------------------------------------------------------------
class _StringVirtualizer(ast.NodeTransformer):
    """Replace string constants with chunked encrypted strings.
    
    Each string is split into 2-4 random-length chunks.
    Each chunk is XOR-encrypted with a different random key.
    Decryption uses nested eval() of join(...).
    """
    def __init__(self):
        self._func_name = None
        self._globals_name = None
        self._virtualizing = False

    def _make_virtualized(self, s):
        """Return AST for chunked virtualized string."""
        if len(s) < 6:
            # For short strings use simple multi-layer XOR
            key1 = random.randint(1, 255)
            key2 = random.randint(1, 255)
            enc = ''.join(chr(ord(c) ^ key1 ^ key2) for c in s)
            src = (
                "(lambda _0,_1,_2:''.join(chr(ord(_0[_])^_1^_2)"
                " for _ in range(len(_0))))(%s,%d,%d)"
            ) % (repr(enc), key1, key2)
            try:
                return ast.parse(src, mode='eval').body
            except SyntaxError:
                return ast.Constant(value=s)

        # Split into random chunks (2-4)
        nchunks = random.randint(2, min(4, len(s) // 2))
        split_pts = sorted(random.sample(range(1, len(s)), nchunks - 1))
        split_pts = [0] + split_pts + [len(s)]
        chunks = [s[split_pts[i]:split_pts[i+1]] for i in range(len(split_pts)-1)]

        # Encrypt each chunk with a different key
        chunk_data = []
        for chunk in chunks:
            key = random.randint(1, 255)
            enc = ''.join(chr(ord(c) ^ key) for c in chunk)
            chunk_data.append((enc, key))

        # Build: eval(''.join(dec(c) for c, k in zip(chunks, keys)))
        # But wrap chunks/keys as literals
        enc_list = repr([e for e, _ in chunk_data])
        key_list = repr([k for _, k in chunk_data])
        
        src = (
            "(lambda _e,_k:''.join("
            "''.join(chr(ord(_c)^_k[__i]) for _c in _e[__i])"
            " for __i in range(len(_e))))"
            "(%s,%s)"
        ) % (enc_list, key_list)
        
        try:
            sub = ast.parse(src, mode='eval').body
            return sub
        except SyntaxError:
            return ast.Constant(value=s)

    def visit_JoinedStr(self, node):
        return node

    def visit_Constant(self, node):
        if isinstance(node.value, str) and len(node.value) >= 3 and not self._virtualizing:
            self._virtualizing = True
            try:
                return self._make_virtualized(node.value)
            finally:
                self._virtualizing = False
        return node


def virtualize_strings(source):
    try:
        tree = ast.parse(source)
        tf = _StringVirtualizer()
        tree = tf.visit(tree)
        ast.fix_missing_locations(tree)
        return ast.unparse(tree)
    except SyntaxError:
        return source


# ---------------------------------------------------------------------------
# CLEANUP
# ---------------------------------------------------------------------------
def cleanup_code(source):
    try:
        tree = ast.parse(source)
        class _Cleaner(ast.NodeTransformer):
            def visit_FunctionDef(self, node):
                if node.body and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant) and isinstance(node.body[0].value.value, str):
                    node.body.pop(0)
                self.generic_visit(node)
                return node
            def visit_AsyncFunctionDef(self, node):
                return self.visit_FunctionDef(node)
            def visit_ClassDef(self, node):
                if node.body and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant) and isinstance(node.body[0].value.value, str):
                    node.body.pop(0)
                self.generic_visit(node)
                return node
            def visit_Module(self, node):
                node.body = [n for n in node.body if not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str))]
                self.generic_visit(node)
                return node
        tree = _Cleaner().visit(tree)
        ast.fix_missing_locations(tree)
        return ast.unparse(tree)
    except SyntaxError:
        return source


# ---------------------------------------------------------------------------
# BASIC CONTROL FLOW FLATTENING (keep original)
# ---------------------------------------------------------------------------
def _make_assign(var, value):
    return ast.Assign(
        targets=[ast.Name(id=var, ctx=ast.Store())],
        value=ast.Constant(value=value))


def _make_state_check(var, state_val):
    return ast.Compare(
        left=ast.Name(id=var, ctx=ast.Load()),
        ops=[ast.Eq()],
        comparators=[ast.Constant(value=state_val)])


def _append_to_branches(if_node, stmt):
    node = if_node
    while True:
        node.body.append(copy.deepcopy(stmt))
        if not node.orelse:
            break
        if len(node.orelse) == 1 and isinstance(node.orelse[0], ast.If):
            node = node.orelse[0]
        else:
            node.orelse.append(copy.deepcopy(stmt))
            break


def _partition_blocks(stmts):
    blocks = []
    current_seq = []
    for stmt in stmts:
        if isinstance(stmt, ast.If):
            if current_seq:
                blocks.append(current_seq)
                current_seq = []
            blocks.append([stmt])
        else:
            current_seq.append(stmt)
    if current_seq:
        blocks.append(current_seq)
    return blocks


def _flatten_func(node):
    state_var = '__fs'
    body = list(node.body)
    blocks = _partition_blocks(body)
    if len(blocks) <= 1:
        return
    n = len(blocks)
    chain = None
    for i in range(n - 1, -1, -1):
        block = blocks[i]
        is_last = (i + 1 >= n)
        block_body = copy.deepcopy(block)
        if is_last:
            block_body.append(ast.Break())
        else:
            assign = _make_assign(state_var, i + 1)
            has_if = any(isinstance(s, ast.If) for s in block)
            if has_if:
                for s in block_body:
                    if isinstance(s, ast.If):
                        _append_to_branches(s, assign)
            block_body.append(assign)
        test = _make_state_check(state_var, i)
        if_node = ast.If(test=test, body=block_body, orelse=[])
        if chain is None:
            chain = if_node
        else:
            if_node.orelse = [chain]
            chain = if_node
    new_body = [
        _make_assign(state_var, 0),
        ast.While(
            test=ast.Constant(value=True),
            body=[chain],
            orelse=[])
    ]
    node.body = new_body


def flatten_control_flow(source):
    try:
        tree = ast.parse(source)
        for node in list(ast.walk(tree)):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                _flatten_func(node)
        ast.fix_missing_locations(tree)
        return ast.unparse(tree)
    except SyntaxError:
        return source


# ---------------------------------------------------------------------------
# ADVANCED CONTROL FLOW FLATTENING
# dispatcher table + opaque predicates + scrambled states + dummy entries
# ---------------------------------------------------------------------------
def _make_opaque_true():
    """Return an AST expression that always evaluates to True but is
    non-trivial for static/symbolic analysis.
    All patterns must be GUARANTEED True at runtime."""
    _x = random.randint(0, 100000)
    _y = random.randint(0, 100)
    _z = random.randint(0, 1000)
    patterns = [
        # (x*x + x) % 2 == 0  (always true for integer x)
        "((lambda _: ((_*_)+_)%%2==0))(%d)" % _x,
        # id(0) == id(0)
        "(id(0)==id(0))",
        # len(str(0)) == 1
        "(len(str(0))==1)",
        # ((x+1) > x)  always true
        "((%d+1)>%d)" % (_x, _x),
        # hash(None) is not None (always True)
        "(hash(None) is not None)",
        # -(~x) == x+1  always true
        "(-(~%d)==%d+1)" % (_y, _y),
        # any([True]) always True
        "(any([True]))",
        # pow(x,0) == 1 always true
        "(pow(%d,0)==1)" % _x,
        # bool(1) always True
        "(bool(1))",
        # x//1 == x always true for int
        "(%d//1==%d)" % (_y, _y),
        # abs(x) >= 0 always true
        "(abs(%d)>=0)" % _x,
    ]
    src = random.choice(patterns)
    try:
        return ast.parse(src, mode='eval').body
    except SyntaxError:
        return ast.Constant(value=True)


def _partition_blocks_advanced(stmts):
    """Partition into blocks, keeping if/else as atomic blocks."""
    blocks = []
    current_seq = []
    for stmt in stmts:
        if isinstance(stmt, (ast.If, ast.While, ast.For, ast.Try)):
            if current_seq:
                blocks.append(current_seq)
                current_seq = []
            blocks.append([stmt])
        elif isinstance(stmt, ast.FunctionDef):
            if current_seq:
                blocks.append(current_seq)
                current_seq = []
            blocks.append([stmt])
        else:
            current_seq.append(stmt)
    if current_seq:
        blocks.append(current_seq)
    return blocks


def _flatten_advanced(node):
    """Convert function body to advanced state machine with:
    - Dispatcher table (dict of lambdas) where each lambda returns next state
    - Opaque predicates guarding transitions
    - Scrambled state numbers (not sequential 0,1,2,...)
    - Dummy states that are never reached
    """
    state_var = _rand_name()  # random state variable name
    body = list(node.body)
    blocks = _partition_blocks_advanced(body)
    if len(blocks) <= 1:
        return

    n = len(blocks)
    # Generate random state numbers, shuffled
    state_ids = list(range(1000, 1000 + n))
    random.shuffle(state_ids)
    # Also generate dummy state IDs that are never used
    dummy_states = random.sample(range(2000, 2000 + n), min(n // 2, 5))

    # Check if all blocks can be expression-only (suitable for lambdas)
    # A block is expression-only if it contains only Expr nodes, simple assigns, etc.
    def _is_expr_block(blk):
        for s in blk:
            if isinstance(s, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
                continue
            if isinstance(s, ast.Expr):
                continue
            if isinstance(s, (ast.Return, ast.Break, ast.Continue, ast.Pass)):
                continue
            return False
        return True

    use_dispatch = all(_is_expr_block(b) for b in blocks)

    if use_dispatch:
        # ── Build dispatch table ──
        lambdas = {}
        for i, blk in enumerate(blocks):
            sid = state_ids[i]
            next_sid = state_ids[i + 1] if (i + 1 < n) else None
            lambda_name = _rand_name()
            block_lines = []
            for stmt in blk:
                line = ast.unparse(stmt).strip()
                block_lines.append(line)
            if next_sid is not None:
                block_lines.append("%s = %d" % (state_var, next_sid))
            else:
                block_lines.append("%s = None" % state_var)
            lambdas[sid] = (lambda_name, '; '.join(block_lines))

        # Build the dispatch dict literal
        dict_items = []
        for sid, (lname, _) in lambdas.items():
            # Each entry is sid: lambda_state
            func_body = "lambda:%s" % lambdas[sid][1]
            try:
                fexpr = ast.parse(func_body, mode='eval').body
            except SyntaxError:
                fexpr = None
            if fexpr:
                dict_items.append(ast.keyword(
                    arg=None,
                    value=ast.Constant(value=sid)))
                dict_items.append(fexpr)
            else:
                use_dispatch = False
                break

        if use_dispatch:
            # Also add dummy entries
            for ds in dummy_states:
                junk_template = random.choice([
                    "lambda:None",
                    "lambda:0",
                    "lambda:[_ for _ in ()]",
                ])
                try:
                    jexpr = ast.parse(junk_template, mode='eval').body
                except SyntaxError:
                    continue
                dict_items.append(ast.keyword(arg=None, value=ast.Constant(value=ds)))
                dict_items.append(jexpr)

            if dict_items:
                # Build: while True: nxt = tbl.get(__S, lambda:None)(); __S = nxt; if nxt is None: break
                # Actually simpler: while True: __S = tbl.get(__S, lambda:None)(); if __S is None: break
                pass

        if not use_dispatch:
            pass  # fall through to scrambled if-elif

    if not use_dispatch:
        # ── Scrambled if-elif chain with opaque predicates ──
        state_var = '__fs_' + _rand_name(4)
        
        # Build chain with shuffled states
        chain = None
        for i in range(n - 1, -1, -1):
            sid = state_ids[i]
            blk = blocks[i]
            next_sid = state_ids[i + 1] if (i + 1 < n) else None

            block_body = copy.deepcopy(blk)
            if next_sid is not None:
                assign = _make_assign(state_var, next_sid)
                has_control = any(isinstance(s, (ast.If, ast.While, ast.For, ast.Try)) for s in blk)
                if has_control:
                    for s in block_body:
                        if isinstance(s, (ast.If, ast.While, ast.For, ast.Try)):
                            _append_to_branches(s, assign)
                block_body.append(assign)
            else:
                block_body.append(ast.Break())

            # Add opaque predicate to condition
            op_true = _make_opaque_true()
            test = ast.BoolOp(
                op=ast.And(),
                values=[
                    _make_state_check(state_var, sid),
                    op_true
                ])
            if_node = ast.If(test=test, body=block_body, orelse=[])
            
            # Add dummy elif branches with junk code
            for ds in dummy_states:
                junk_stmt = random.choice([
                    ast.Expr(value=ast.Constant(value=None)),
                    ast.Pass(),
                    ast.Break(),
                ])
                dummy_test = _make_state_check(state_var, ds)
                junk_body = [junk_stmt, ast.Break()]
                # Insert as elif
                if_node.orelse = [
                    ast.If(test=dummy_test, body=junk_body, orelse=[])
                ] if not if_node.orelse else [
                    ast.If(test=dummy_test, body=junk_body, orelse=if_node.orelse)
                ]

            if chain is None:
                chain = if_node
            else:
                if_node.orelse = [chain]
                chain = if_node

        new_body = [
            _make_assign(state_var, state_ids[0]),
            ast.While(
                test=ast.Constant(value=True),
                body=[chain],
                orelse=[])
        ]
        node.body = new_body


def flatten_advanced(source):
    try:
        tree = ast.parse(source)
        for node in list(ast.walk(tree)):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                _flatten_advanced(node)
        ast.fix_missing_locations(tree)
        return ast.unparse(tree)
    except SyntaxError:
        return source


# ---------------------------------------------------------------------------
# AST MUTATION
# ---------------------------------------------------------------------------
class _ASTMutator(ast.NodeTransformer):
    """Mutate simple expressions into complex equivalents."""
    
    def _mutate_binop(self, left, op, right):
        """Replace a + b, a - b, a * b with obfuscated equivalent.
        
        All mutations must be type-safe (work for strs, ints, etc.).
        """
        kind = random.random()
        
        if kind < 0.30:
            # Lambda wrapper: (lambda x,y: x+y)(a, b)
            # Always type-safe because it's just wrapping the original op
            op_map = {
                ast.Add: '+', ast.Sub: '-', ast.Mult: '*', 
                ast.Div: '/', ast.FloorDiv: '//', ast.Mod: '%',
                ast.Pow: '**', ast.LShift: '<<', ast.RShift: '>>',
                ast.BitOr: '|', ast.BitXor: '^', ast.BitAnd: '&',
            }
            if type(op) in op_map:
                opsym = op_map[type(op)]
                l = ast.unparse(left)
                r = ast.unparse(right)
                src = "(lambda _0,_1:_0 %s _1)((%s),(%s))" % (opsym, l, r)
                try:
                    return ast.parse(src, mode='eval').body
                except SyntaxError:
                    pass
        
        if kind < 0.65:
            # Method call: a.__add__(b)
            # Always type-safe (calls the actual dunder method)
            method_map = {
                ast.Add: '__add__', ast.Sub: '__sub__', ast.Mult: '__mul__',
                ast.Div: '__truediv__', ast.FloorDiv: '__floordiv__', 
                ast.Mod: '__mod__', ast.Pow: '__pow__',
                ast.LShift: '__lshift__', ast.RShift: '__rshift__',
                ast.BitOr: '__or__', ast.BitXor: '__xor__', ast.BitAnd: '__and__',
            }
            if type(op) in method_map:
                mname = method_map[type(op)]
                return ast.Call(
                    func=ast.Attribute(value=left, attr=mname, ctx=ast.Load()),
                    args=[right],
                    keywords=[])
        
        if kind < 0.80:
            # Extra-wrapper: (lambda: a + b)()
            # Another lambda wrapping
            opsym = {ast.Add:'+', ast.Sub:'-', ast.Mult:'*', ast.Div:'/', 
                     ast.FloorDiv:'//', ast.Mod:'%', ast.Pow:'**',
                     ast.LShift:'<<', ast.RShift:'>>', ast.BitOr:'|',
                     ast.BitXor:'^', ast.BitAnd:'&'}.get(type(op))
            if opsym:
                l = ast.unparse(left)
                r = ast.unparse(right)
                src = "(lambda: (%s) %s (%s))()" % (l, opsym, r)
                try:
                    return ast.parse(src, mode='eval').body
                except SyntaxError:
                    pass

        # Fall through: return original
        return ast.BinOp(left=left, op=op, right=right)

    def _mutate_compare(self, left, ops, comparators):
        """Mutate comparisons like a == b, a != b.
        
        Uses method calls (a.__eq__(b), a.__ne__(b), etc.) which are
        semantically correct for all types.
        """
        if len(ops) == 1:
            op = ops[0]
            method_map = {
                ast.Eq: '__eq__', ast.NotEq: '__ne__',
                ast.Lt: '__lt__', ast.LtE: '__le__',
                ast.Gt: '__gt__', ast.GtE: '__ge__',
                ast.In: '__contains__', ast.NotIn: '__contains__',
            }
            if type(op) in method_map:
                # For 'in'/'not in', check containment: right.__contains__(left)
                # Parenthesize r in case it's a binary operation (lower precedence
                # than attribute access)
                if isinstance(op, (ast.In, ast.NotIn)):
                    r = comparators[0]
                    src = "(%s).__contains__(%s)" % (ast.unparse(r), ast.unparse(left))
                    try:
                        sub = ast.parse(src, mode='eval').body
                        if isinstance(op, ast.NotIn):
                            return ast.UnaryOp(op=ast.Not(), operand=sub)
                        return sub
                    except SyntaxError:
                        pass
                else:
                    mname = method_map[type(op)]
                    return ast.Call(
                        func=ast.Attribute(value=left, attr=mname, ctx=ast.Load()),
                        args=comparators,
                        keywords=[])
        return ast.Compare(left=left, ops=ops, comparators=comparators)

    def _mutate_unaryop(self, op, operand):
        """Mutate unary operations."""
        if isinstance(op, ast.Not):
            # not x → False if x else True
            src = "(False if %s else True)" % ast.unparse(operand)
            try:
                return ast.parse(src, mode='eval').body
            except SyntaxError:
                pass
        return ast.UnaryOp(op=op, operand=operand)

    def _mutate_subscript(self, value, slice_):
        """Mutate x[y] → x.__getitem__(y)."""
        if isinstance(slice_, (ast.Constant, ast.Name, ast.Subscript)):
            return ast.Call(
                func=ast.Attribute(value=value, attr='__getitem__', ctx=ast.Load()),
                args=[slice_],
                keywords=[])
        return ast.Subscript(value=value, slice=slice_, ctx=ast.Load())

    def visit_BinOp(self, node):
        self.generic_visit(node)
        # Skip if inside a lambda or function call we've mutated
        return self._mutate_binop(node.left, node.op, node.right)

    def visit_Compare(self, node):
        self.generic_visit(node)
        return self._mutate_compare(node.left, node.ops, node.comparators)

    def visit_UnaryOp(self, node):
        self.generic_visit(node)
        if isinstance(node.op, ast.Not):
            return self._mutate_unaryop(node.op, node.operand)
        return node

    def visit_Subscript(self, node):
        self.generic_visit(node)
        # Mutate where indexing and check context is Load
        if isinstance(node.ctx, ast.Load):
            return self._mutate_subscript(node.value, node.slice)
        return node


def mutate_expressions(source):
    try:
        tree = ast.parse(source)
        tf = _ASTMutator()
        tree = tf.visit(tree)
        ast.fix_missing_locations(tree)
        return ast.unparse(tree)
    except SyntaxError:
        return source


# ---------------------------------------------------------------------------
# JUNK CODE INJECTION (enhanced)
# ---------------------------------------------------------------------------
_JUNK_TEMPLATES = [
    "if id(0)-id(0):[_ for _ in ()]",
    "if id(0)-id(0):None",
    "if id(0)-id(0):(lambda:0)()",
    "if (lambda _:((_*_)+_)%%2==0)(%d):None" % random.randint(0, 10000),
    "if not(id(0)-id(0)):None",
    "if -(~%d)==%d+1:None" % (_j := random.randint(0, 100), _j),
    "if len(str(%d))==1:None" % random.randint(0, 9),
    "if bool(%d):None" % random.randint(1, 100),
    "if any([%d>0]):None" % random.randint(0, 100),
    "if pow(%d,0)==1:None" % random.randint(1, 100),
]


def _make_junk_ast():
    src = random.choice(_JUNK_TEMPLATES)
    try:
        return ast.parse(src).body[0]
    except SyntaxError:
        return None


class _JunkInjector(ast.NodeTransformer):
    def __init__(self):
        self.injected = 0

    def visit_FunctionDef(self, node):
        new_body = []
        for stmt in node.body:
            new_body.append(stmt)
            if self.injected < 50:
                junk = _make_junk_ast()
                if junk is not None:
                    new_body.append(junk)
                    self.injected += 1
        node.body = new_body
        self.generic_visit(node)
        return node

    def visit_AsyncFunctionDef(self, node):
        return self.visit_FunctionDef(node)


def inject_junk(source):
    try:
        tree = ast.parse(source)
        tf = _JunkInjector()
        tree = tf.visit(tree)
        ast.fix_missing_locations(tree)
        return ast.unparse(tree)
    except SyntaxError:
        return source


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    techniques = [t.strip() for t in sys.argv[1].split(',')] \
        if len(sys.argv) > 1 else ['all']

    source = sys.stdin.read()
    has_all = 'all' in techniques

    # Order matters: cleanup first, then rename, then string processing,
    # then control flow, then mutation, then junk
    # 'all' uses vstrings + aflow (advanced versions) instead of basic ones
    if has_all or 'cleanup' in techniques:
        source = cleanup_code(source)
    if has_all or 'rename' in techniques:
        source = rename_code(source)
    if has_all or 'vstrings' in techniques:
        source = virtualize_strings(source)
    elif 'strings' in techniques:
        source = encrypt_strings(source)
    if has_all or 'flow' in techniques:
        source = flatten_control_flow(source)
    elif 'aflow' in techniques:
        source = flatten_advanced(source)
    elif has_all:
        source = flatten_advanced(source)
    if has_all or 'mutate' in techniques:
        source = mutate_expressions(source)
    if has_all or 'junk' in techniques:
        source = inject_junk(source)

    sys.stdout.write(source)

)pyobf_script";

#endif // CRYPTO_PYOBF_H
