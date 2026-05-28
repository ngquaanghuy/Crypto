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
    flow       Basic control flow flattening (if/else -> state machine)
    aflow      Advanced control flow flatt. (dispatch table + opaque predicates)
    opaque     Encode state variable with non-linear transformations
    mutate     AST mutation (binary op -> lambda/sum/complex expr)
    mba        Mixed Boolean-Arithmetic (math identity replacements)
    junk       Junk code injection (dead code with opaque predicates)
    apihash    Replace static imports with FNV-1a hash dynamic resolution
    funcenc    Encrypt function bodies (SHA-256-CTR, on-the-fly decryption)
    all        All of the above
"""
import ast
import copy
import hashlib
import os
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

    def visit_keyword(self, node):
        if node.arg is not None and not _should_skip(node.arg) and node.arg not in self.imported_names:
            if node.arg in self.name_map:
                node.arg = self.name_map[node.arg]
        self.generic_visit(node)
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
                # Pre-scan parameter names so keyword args at call sites
                # can be renamed to match (see visit_keyword).
                for arg in node.args.args:
                    if not _should_skip(arg.arg) and arg.arg not in self.names:
                        self.names[arg.arg] = self._new_name()
                if node.args.vararg:
                    if not _should_skip(node.args.vararg.arg) and node.args.vararg.arg not in self.names:
                        self.names[node.args.vararg.arg] = self._new_name()
                if node.args.kwarg:
                    if not _should_skip(node.args.kwarg.arg) and node.args.kwarg.arg not in self.names:
                        self.names[node.args.kwarg.arg] = self._new_name()
                for arg in node.args.kwonlyargs:
                    if not _should_skip(arg.arg) and arg.arg not in self.names:
                        self.names[arg.arg] = self._new_name()
                for arg in node.args.posonlyargs:
                    if not _should_skip(arg.arg) and arg.arg not in self.names:
                        self.names[arg.arg] = self._new_name()
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
# STATE-VARIABLE ENCODING & OPAQUE CONSTANTS
# ---------------------------------------------------------------------------
class _StateEncoder(ast.NodeTransformer):
    """Encode the state variable in flattened state machines using a
    mathematical transformation.  All state values are stored and compared
    in encoded space — raw state values never appear in the source.

    Encoding: F(x) = (A * x + B) % M   (affine, bijective on [0, M-1]).
    
    Must run AFTER flow/aflow, BEFORE mutate/mba/junk.
    """

    def __init__(self):
        self._M = 65536
        self._A = random.randrange(1, self._M, 2)   # odd → coprime with M
        self._B = random.randint(0, self._M - 1)
        self._F_name = _rand_name()
        self._state_var = None
        self._state_vals = None

    def _F(self, x):
        return (self._A * x + self._B) % self._M

    def _is_state_machine(self, node):
        """Check if *node* is a flattened state-machine while-loop.
        Returns (*state_var_name*, [*state_values*]) or None."""
        if not isinstance(node, ast.While):
            return None
        if not (isinstance(node.test, ast.Constant) and node.test.value is True):
            return None
        body = node.body
        if not body or not isinstance(body[0], ast.If):
            return None

        var_name = None
        vals = []
        cur = body[0]
        while isinstance(cur, ast.If):
            test = cur.test
            compares = []
            if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And):
                for v in test.values:
                    if _is_state_cmp(v):
                        compares.append(v)
            elif _is_state_cmp(test):
                compares.append(test)

            if not compares:
                return None
            cmp = compares[0]
            if not isinstance(cmp.left, ast.Name):
                return None
            if var_name is None:
                var_name = cmp.left.id
            elif cmp.left.id != var_name:
                return None

            val = None
            for c in cmp.comparators:
                if isinstance(c, ast.Constant) and isinstance(c.value, int):
                    val = c.value
                    break
            if val is None:
                return None
            vals.append(val)

            cur = cur.orelse[0] if cur.orelse and len(cur.orelse) == 1 and isinstance(cur.orelse[0], ast.If) else None

        if var_name is None or len(vals) < 2:
            return None
        return var_name, vals

    def _encode_state_refs(self, node):
        """Walk a statement and replace __fs == N / __fs = N with __F forms."""
        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                for t in child.targets:
                    if isinstance(t, ast.Name) and t.id == self._state_var:
                        if isinstance(child.value, ast.Constant) and isinstance(child.value.value, int):
                            enc = self._F(child.value.value)
                            child.value = _make_call(self._F_name, [ast.Constant(value=enc)])
                            break
            if isinstance(child, ast.If):
                self._encode_if_conds(child)

    def _encode_if_conds(self, if_node):
        """Walk if-elif chain and encode state comparisons."""
        cur = if_node
        while isinstance(cur, ast.If):
            test = cur.test
            if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And):
                new_vals = []
                for v in test.values:
                    if _is_state_cmp(v, self._state_var):
                        v = self._rewrite_cmp(v)
                    new_vals.append(v)
                cur.test = ast.BoolOp(op=ast.And(), values=new_vals)
            elif _is_state_cmp(test, self._state_var):
                cur.test = self._rewrite_cmp(test)
            self.generic_visit(cur)
            cur = cur.orelse[0] if cur.orelse and len(cur.orelse) == 1 and isinstance(cur.orelse[0], ast.If) else None

    def _rewrite_cmp(self, cmp_node):
        """Rewrite __fs == N  →  __fs == _F(N)."""
        val = None
        for c in cmp_node.comparators:
            if isinstance(c, ast.Constant) and isinstance(c.value, int):
                val = c.value
                break
        if val is not None:
            new_comparators = []
            for c in cmp_node.comparators:
                if isinstance(c, ast.Constant) and isinstance(c.value, int):
                    new_comparators.append(ast.Constant(value=self._F(val)))
                else:
                    new_comparators.append(c)
            cmp_node.comparators = new_comparators
        return cmp_node

    def visit_While(self, node):
        self.generic_visit(node)
        sm = self._is_state_machine(node)
        if sm is None:
            return node
        self._state_var, self._state_vals = sm
        self._encode_state_refs(node)
        return node


def _is_state_cmp(node, state_var=None):
    """Check if *node* is a comparison like __fs == N."""
    if not isinstance(node, ast.Compare):
        return False
    if not isinstance(node.left, ast.Name):
        return False
    if state_var is not None and node.left.id != state_var:
        return False
    if not (len(node.ops) == 1 and isinstance(node.ops[0], ast.Eq)):
        return False
    for c in node.comparators:
        if isinstance(c, ast.Constant) and isinstance(c.value, int):
            return True
    return False


def encode_state(source):
    """Apply state-variable encoding to all flattened functions."""
    try:
        tree = ast.parse(source)

        func_encoders = {}
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for stmt in node.body:
                if isinstance(stmt, ast.While):
                    cand = _StateEncoder()
                    sm = cand._is_state_machine(stmt)
                    if sm is not None:
                        enc = _StateEncoder()
                        enc._F_name = _rand_name()
                        enc._state_var = sm[0]
                        func_encoders[id(node)] = enc
                        break

        class _EncodePass(ast.NodeTransformer):
            def __init__(self):
                self._cur_enc = None

            def visit_FunctionDef(self, node):
                self.generic_visit(node)
                enc = func_encoders.get(id(node))
                if enc is None:
                    return node
                self._cur_enc = enc
                F_name = enc._F_name
                src = "lambda _x: (%d * _x + %d) %% %d" % (enc._A, enc._B, enc._M)
                flam = ast.parse(src, mode='eval').body
                f_stmt = ast.Assign(
                    targets=[ast.Name(id=F_name, ctx=ast.Store())],
                    value=flam)
                new_body = [f_stmt]
                for stmt in node.body:
                    if isinstance(stmt, ast.While):
                        sm = enc._is_state_machine(stmt)
                        if sm is not None:
                            for child in ast.walk(stmt):
                                if isinstance(child, ast.Assign):
                                    for t in child.targets:
                                        if (isinstance(t, ast.Name) and
                                            t.id == enc._state_var and
                                            isinstance(child.value, ast.Constant) and
                                            isinstance(child.value.value, int)):
                                            child.value = ast.Call(
                                                func=ast.Name(id=F_name, ctx=ast.Load()),
                                                args=[ast.Constant(value=child.value.value)],
                                                keywords=[])
                                if isinstance(child, ast.If):
                                    _encode_if_conds(child, enc._state_var, F_name)
                            for prev in new_body:
                                if isinstance(prev, ast.Assign):
                                    for t in prev.targets:
                                        if (isinstance(t, ast.Name) and
                                            t.id == enc._state_var and
                                            isinstance(prev.value, ast.Constant) and
                                            isinstance(prev.value.value, int)):
                                            prev.value = ast.Call(
                                                func=ast.Name(id=F_name, ctx=ast.Load()),
                                                args=[ast.Constant(value=prev.value.value)],
                                                keywords=[])
                    new_body.append(stmt)
                node.body = new_body
                return node

            def visit_AsyncFunctionDef(self, node):
                return self.visit_FunctionDef(node)

        def _encode_if_conds(if_node, state_var, F_name):
            cur = if_node
            while isinstance(cur, ast.If):
                test = cur.test
                if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And):
                    new_vals = []
                    for v in test.values:
                        if _is_state_cmp(v, state_var):
                            v = _rewrite_cmp(v, state_var, F_name)
                        new_vals.append(v)
                    cur.test = ast.BoolOp(op=ast.And(), values=new_vals)
                elif _is_state_cmp(test, state_var):
                    cur.test = _rewrite_cmp(test, state_var, F_name)
                for child in ast.iter_child_nodes(cur):
                    if isinstance(child, ast.If):
                        _encode_if_conds(child, state_var, F_name)
                cur = (cur.orelse[0] if cur.orelse and
                       len(cur.orelse) == 1 and
                       isinstance(cur.orelse[0], ast.If) else None)

        def _rewrite_cmp(cmp_node, state_var, F_name):
            val = None
            for c in cmp_node.comparators:
                if isinstance(c, ast.Constant) and isinstance(c.value, int):
                    val = c.value
                    break
            if val is not None:
                new_comparators = []
                for c in cmp_node.comparators:
                    if (isinstance(c, ast.Constant) and
                        isinstance(c.value, int)):
                        new_comparators.append(
                            ast.Call(
                                func=ast.Name(id=F_name, ctx=ast.Load()),
                                args=[ast.Constant(value=c.value)],
                                keywords=[]))
                    else:
                        new_comparators.append(c)
                cmp_node.comparators = new_comparators
            return cmp_node

        tree = _EncodePass().visit(tree)
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
            # Lambda wrapper (second chunk): (lambda x,y: x+y)(a, b)
            # Type-safe because it wraps the original operator preserving
            # Python's __radd__ / reflected operator fallback.
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
# MIXED BOOLEAN-ARITHMETIC (MBA)
# ---------------------------------------------------------------------------
class _MBAMutator(ast.NodeTransformer):
    """Replace simple arithmetic/bitwise ops with MBA equivalent expressions."""

    def _safe_wrap(self, mba_expr, fallback_op, left, right):
        l = ast.unparse(left)
        r = ast.unparse(right)
        src = "(lambda _m0,_m1: %s if isinstance(_m0, int) and isinstance(_m1, int) else _m0 %s _m1)(%s, %s)" % (
            mba_expr, fallback_op, l, r)
        try:
            return ast.parse(src, mode='eval').body
        except SyntaxError:
            return None

    def _wrap(self, fmt, *args):
        src = fmt % args
        try:
            return ast.parse(src, mode='eval').body
        except SyntaxError:
            return None

    def _mba_add(self, left, right):
        kind = random.random()
        l = ast.unparse(left)
        r = ast.unparse(right)
        if kind < 0.40:
            mba = "(%s ^ %s) + 2 * (%s & %s)" % (l, r, l, r)
        elif kind < 0.70:
            mba = "(%s | %s) + (%s & %s)" % (l, r, l, r)
        else:
            mba = "(%s ^ %s) + ((%s & %s) << 1)" % (l, r, l, r)
        return self._safe_wrap(mba, '+', left, right)

    def _mba_sub(self, left, right):
        kind = random.random()
        l = ast.unparse(left)
        r = ast.unparse(right)
        if kind < 0.40:
            mba = "%s + ~%s + 1" % (l, r)
        elif kind < 0.70:
            mba = "(%s ^ %s) - 2 * (~%s & %s)" % (l, r, l, r)
        else:
            mba = "~(~%s + %s)" % (l, r)
        return self._safe_wrap(mba, '-', left, right)

    def _mba_mul(self, left, right):
        kind = random.random()
        l = ast.unparse(left)
        r = ast.unparse(right)
        if kind < 0.50:
            mba = "(%s & %s) * (%s | %s) + (%s & ~%s) * (%s & ~%s)" % (
                l, r, l, r, l, r, r, l)
        else:
            mba = "(%s + %s) ** 2 // 4 - (%s - %s) ** 2 // 4" % (l, r, l, r)
        return self._safe_wrap(mba, '*', left, right)

    def _mba_xor(self, left, right):
        kind = random.random()
        l = ast.unparse(left)
        r = ast.unparse(right)
        if kind < 0.50:
            return self._safe_wrap("(%s | %s) - (%s & %s)" % (l, r, l, r), '^', left, right)
        else:
            return self._safe_wrap("(%s + %s) - 2 * (%s & %s)" % (l, r, l, r), '^', left, right)

    def _mba_and(self, left, right):
        l = ast.unparse(left)
        r = ast.unparse(right)
        return self._safe_wrap("(%s + %s) - (%s | %s)" % (l, r, l, r), '&', left, right)

    def _mba_or(self, left, right):
        l = ast.unparse(left)
        r = ast.unparse(right)
        return self._safe_wrap("(%s & %s) + (%s ^ %s)" % (l, r, l, r), '|', left, right)

    def _mba_invert(self, operand):
        kind = random.random()
        o = ast.unparse(operand)
        if kind < 0.50:
            return self._wrap("-%s - 1" % o)
        else:
            return self._wrap("%s ^ -1" % o)

    def visit_BinOp(self, node):
        self.generic_visit(node)
        if isinstance(node.op, ast.Add):
            result = self._mba_add(node.left, node.right)
            return result if result is not None else node
        elif isinstance(node.op, ast.Sub):
            result = self._mba_sub(node.left, node.right)
            return result if result is not None else node
        elif isinstance(node.op, ast.Mult):
            result = self._mba_mul(node.left, node.right)
            return result if result is not None else node
        elif isinstance(node.op, ast.BitXor):
            result = self._mba_xor(node.left, node.right)
            return result if result is not None else node
        elif isinstance(node.op, ast.BitAnd):
            result = self._mba_and(node.left, node.right)
            return result if result is not None else node
        elif isinstance(node.op, ast.BitOr):
            result = self._mba_or(node.left, node.right)
            return result if result is not None else node
        return node

    def visit_UnaryOp(self, node):
        self.generic_visit(node)
        if isinstance(node.op, ast.Invert):
            result = self._mba_invert(node.operand)
            return result if result is not None else node
        return node


def mba_obfuscate(source):
    try:
        tree = ast.parse(source)
        tf = _MBAMutator()
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
# API HASHING & DYNAMIC IMPORT OBFUSCATION
# ---------------------------------------------------------------------------

def _fnv1a(s):
    h = 2166136261
    for c in s.encode('utf-8'):
        h ^= c
        h = (h * 16777619) & 0xFFFFFFFF
    return h


class _ApiHasher(ast.NodeTransformer):
    def __init__(self):
        self._imports = {}
        self._attrs = {}

    def _xor_encrypt(self, s):
        key = random.randint(1, 255)
        enc = bytes(ord(c) ^ key for c in s)
        return enc, key

    def visit_Import(self, node):
        for alias in node.names:
            mod = alias.name
            asname = alias.asname or mod.split('.')[0]
            if asname not in self._imports:
                enc, key = self._xor_encrypt(mod)
                mod_hash = _fnv1a(mod)
                self._imports[asname] = (enc, key, mod_hash, set())
            if '.' in mod:
                parts = mod.split('.')
                mod_hash = _fnv1a(parts[0])
                for p in parts[1:]:
                    h = _fnv1a(p)
                    if (mod_hash, p) not in self._attrs:
                        e, k = self._xor_encrypt(p)
                        self._attrs[(mod_hash, p)] = (e, k)
        return None

    def visit_ImportFrom(self, node):
        mod = node.module or ''
        mod_hash = _fnv1a(mod)
        enc, key = self._xor_encrypt(mod)
        asname = '__mod_' + str(len(self._imports))
        self._imports[asname] = (enc, key, mod_hash, set())
        for alias in node.names:
            aname = alias.asname or alias.name
            attr_hash = _fnv1a(aname)
            if (mod_hash, aname) not in self._attrs:
                e, k = self._xor_encrypt(aname)
                self._attrs[(mod_hash, aname)] = (e, k)
            self._imports[asname][3].add(aname)
        return None

    def _gen_runtime(self):
        lines = []
        lines.append('import importlib, functools')
        lines.append('')
        lines.append('_FNV1A = lambda _s: functools.reduce('
                     'lambda _h,_c: (_h ^ _c) * 16777619 & 4294967295, '
                     '[ord(_) for _ in _s], 2166136261)')
        lines.append('')
        lines.append('_XD = lambda _b,_k: \'\'.join(chr(_c ^ _k) for _c in _b)')
        lines.append('')
        hash_pairs = []
        for alias, (enc, key, mod_hash, attrs) in self._imports.items():
            hash_pairs.append((mod_hash, enc, key))
        for (mod_hash, attr_name), (enc, key) in self._attrs.items():
            attr_hash = _fnv1a(attr_name)
            hash_pairs.append((attr_hash, enc, key))
        seen_hash = {}
        for h, enc, key in hash_pairs:
            if h not in seen_hash:
                seen_hash[h] = (enc, key)
        lines.append('_HM = {')
        for h, (enc, key) in sorted(seen_hash.items()):
            enc_repr = repr(bytes(enc))
            lines.append('    %d: (%s, %d),' % (h, enc_repr, key))
        lines.append('}')
        lines.append('')
        lines.append('_HG = lambda _h: __import__(_XD(*_HM[_h]))')
        lines.append('_HD = lambda _h: _XD(*_HM[_h])')
        return '\n'.join(lines)

    def visit_Module(self, node):
        self.generic_visit(node)
        if not self._imports:
            return node
        runtime = self._gen_runtime()
        try:
            rt_tree = ast.parse(runtime)
            node.body = rt_tree.body + [n for n in node.body if n is not None]
        except SyntaxError:
            pass
        return node

    def visit_Attribute(self, node):
        self.generic_visit(node)
        if isinstance(node.value, ast.Name) and node.value.id in self._imports:
            enc, key, mod_hash, attrs = self._imports[node.value.id]
            attr_hash = _fnv1a(node.attr)
            if (mod_hash, node.attr) not in self._attrs:
                e, k = self._xor_encrypt(node.attr)
                self._attrs[(mod_hash, node.attr)] = (e, k)
            return ast.Call(
                func=ast.Name(id='getattr', ctx=ast.Load()),
                args=[
                    ast.Call(
                        func=ast.Name(id='_HG', ctx=ast.Load()),
                        args=[ast.Constant(value=mod_hash)],
                        keywords=[]),
                    ast.Call(
                        func=ast.Name(id='_HD', ctx=ast.Load()),
                        args=[ast.Constant(value=attr_hash)],
                        keywords=[]),
                ],
                keywords=[])
        return node


def apihash_obfuscate(source):
    try:
        tree = ast.parse(source)
        tf = _ApiHasher()
        tree = tf.visit(tree)
        ast.fix_missing_locations(tree)
        return ast.unparse(tree)
    except SyntaxError:
        return source


# ---------------------------------------------------------------------------
# FUNCTION ENCRYPTION (on-the-fly decryption at call time)
# ---------------------------------------------------------------------------

def _build_func_sig(args):
    parts = []
    n_pos = len(args.args)
    n_defaults = len(args.defaults)
    for i, arg in enumerate(args.args):
        s = arg.arg
        if i >= n_pos - n_defaults:
            s += '=' + ast.unparse(args.defaults[i - (n_pos - n_defaults)])
        parts.append(s)
    if args.vararg:
        parts.append('*' + args.vararg.arg)
    if not args.vararg and args.kwonlyargs:
        parts.append('*')
    for i, arg in enumerate(args.kwonlyargs):
        s = arg.arg
        if i < len(args.kw_defaults) and args.kw_defaults[i] is not None:
            s += '=' + ast.unparse(args.kw_defaults[i])
        parts.append(s)
    if args.kwarg:
        parts.append('**' + args.kwarg.arg)
    return ', '.join(parts)


def _hash_encrypt(key, plaintext):
    nonce = os.urandom(16)
    enc_key = hashlib.sha256(b'encv1:' + key + nonce).digest()
    ciphertext = _xor_stream(enc_key, plaintext)
    auth_key = hashlib.sha256(b'authv1:' + key + nonce).digest()
    tag = hashlib.sha256(auth_key + ciphertext).digest()[:16]
    return nonce + ciphertext + tag


def _xor_stream(key, data):
    result = bytearray()
    counter = 0
    while len(result) < len(data):
        ks = hashlib.sha256(key + counter.to_bytes(8, 'big')).digest()
        chunk = data[len(result):len(result) + 32]
        for a, b in zip(chunk, ks):
            result.append(a ^ b)
        counter += 1
    return bytes(result)


class _FuncEncRecord:
    __slots__ = ('idx', 'name', 'is_async', 'blob')

    def __init__(self, idx, name, is_async, blob):
        self.idx = idx
        self.name = name
        self.is_async = is_async
        self.blob = blob


class _FuncEncCollector(ast.NodeVisitor):
    def __init__(self, key):
        self.key = key
        self.funcs = []
        self._idx = 0

    def _encrypt_body(self, node):
        body_src = ast.unparse(node.body)
        sig = _build_func_sig(node.args)
        wrapped = 'def _f(%s):\n    ' % sig + body_src.replace('\n', '\n    ')
        blob = _hash_encrypt(self.key, wrapped.encode('utf-8'))
        self.funcs.append(_FuncEncRecord(
            idx=self._idx, name=node.name,
            is_async=isinstance(node, ast.AsyncFunctionDef),
            blob=blob,
        ))
        self._idx += 1

    def visit_FunctionDef(self, node):
        self.generic_visit(node)
        self._encrypt_body(node)

    def visit_AsyncFunctionDef(self, node):
        self.generic_visit(node)
        self._encrypt_body(node)

    def visit_ClassDef(self, node):
        self.generic_visit(node)


class _FuncEncReplacer(ast.NodeTransformer):
    def __init__(self, funcs):
        self._lookup = {f.name: f for f in funcs}

    def visit_FunctionDef(self, node):
        self.generic_visit(node)
        rec = self._lookup.get(node.name)
        if rec is None:
            return node
        if rec.is_async:
            src = ("async def %s(*args, **kwargs):\n"
                   "    return await _exec_enc_async(%d, _FUNC_KEY, '%s', args, kwargs)"
                   % (rec.name, rec.idx, rec.name))
        else:
            src = ("def %s(*args, **kwargs):\n"
                   "    return _exec_enc(%d, _FUNC_KEY, '%s', args, kwargs)"
                   % (rec.name, rec.idx, rec.name))
        stub = ast.parse(src).body[0]
        if hasattr(node, 'decorator_list'):
            stub.decorator_list = node.decorator_list[:]
        return stub

    def visit_AsyncFunctionDef(self, node):
        self.generic_visit(node)
        rec = self._lookup.get(node.name)
        if rec is None:
            return node
        if rec.is_async:
            src = ("async def %s(*args, **kwargs):\n"
                   "    return await _exec_enc_async(%d, _FUNC_KEY, '%s', args, kwargs)"
                   % (rec.name, rec.idx, rec.name))
        else:
            src = ("def %s(*args, **kwargs):\n"
                   "    return _exec_enc(%d, _FUNC_KEY, '%s', args, kwargs)"
                   % (rec.name, rec.idx, rec.name))
        stub = ast.parse(src).body[0]
        if hasattr(node, 'decorator_list'):
            stub.decorator_list = node.decorator_list[:]
        return stub

    def visit_ClassDef(self, node):
        self.generic_visit(node)
        return node


def funcenc_obfuscate(source):
    import base64

    key = os.urandom(32)

    tree = ast.parse(source)
    collector = _FuncEncCollector(key)
    collector.visit(tree)

    if not collector.funcs:
        return source

    key_b64 = base64.b64encode(key).decode('ascii')
    blob_lines = []
    for rec in collector.funcs:
        b64 = base64.b64encode(rec.blob).decode('ascii')
        blob_lines.append("    base64.b64decode('%s')," % b64)
    blobs_joined = '\n'.join(blob_lines)

    runtime = '''\
import base64
import hashlib
import ctypes

_FUNC_KEY = base64.b64decode("%(key)s")
_FENC_DATA = [
%(blobs)s
]
_FUNC_CACHE = {}

def _exec_enc(idx, key, name, args, kwargs):
    if name in _FUNC_CACHE:
        return _FUNC_CACHE[name](*args, **kwargs)
    raw = _FENC_DATA[idx]
    nonce, tag = raw[:16], raw[-16:]
    ct = raw[16:-16]
    auth_key = hashlib.sha256(b'authv1:' + key + nonce).digest()
    if hashlib.sha256(auth_key + ct).digest()[:16] != tag:
        raise RuntimeError("[funcenc] integrity check failed")
    enc_key = hashlib.sha256(b'encv1:' + key + nonce).digest()
    plain_bytes = _xor_stream(enc_key, ct)
    plain_str = plain_bytes.decode('utf-8')
    ns = {}
    exec(plain_str, globals(), ns)
    func = ns['_f']
    _FUNC_CACHE[name] = func
    result = func(*args, **kwargs)
    return result

async def _exec_enc_async(idx, key, name, args, kwargs):
    if name in _FUNC_CACHE:
        return await _FUNC_CACHE[name](*args, **kwargs)
    raw = _FENC_DATA[idx]
    nonce, tag = raw[:16], raw[-16:]
    ct = raw[16:-16]
    auth_key = hashlib.sha256(b'authv1:' + key + nonce).digest()
    if hashlib.sha256(auth_key + ct).digest()[:16] != tag:
        raise RuntimeError("[funcenc] integrity check failed")
    enc_key = hashlib.sha256(b'encv1:' + key + nonce).digest()
    plain_bytes = _xor_stream(enc_key, ct)
    plain_str = plain_bytes.decode('utf-8')
    ns = {}
    exec(plain_str, globals(), ns)
    func = ns['_f']
    _FUNC_CACHE[name] = func
    result = await func(*args, **kwargs)
    return result

def _xor_stream(key, data):
    result = bytearray()
    counter = 0
    while len(result) < len(data):
        ks = hashlib.sha256(key + counter.to_bytes(8, 'big')).digest()
        chunk = data[len(result):len(result) + 32]
        for a, b in zip(chunk, ks):
            result.append(a ^ b)
        counter += 1
    return bytes(result)

''' % {'key': key_b64, 'blobs': blobs_joined}

    new_tree = ast.parse(source)
    replacer = _FuncEncReplacer(collector.funcs)
    new_tree = replacer.visit(new_tree)
    ast.fix_missing_locations(new_tree)

    return runtime + '\n' + ast.unparse(new_tree)


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    techniques = [t.strip() for t in sys.argv[1].split(',')] \
        if len(sys.argv) > 1 else ['all']

    source = sys.stdin.read()
    has_all = 'all' in techniques

    # Order matters: cleanup → rename → strings → flow → opaque →
    # mutate → mba → junk → apihash → funcenc
    # 'all' uses vstrings + aflow (advanced versions) instead of basic ones
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

    # funcenc must run LAST — it encrypts already-obfuscated bodies
    if has_all or 'funcenc' in techniques:
        source = funcenc_obfuscate(source)

    sys.stdout.write(source)

)pyobf_script";

#endif // CRYPTO_PYOBF_H
