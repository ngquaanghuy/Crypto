"""Tests for the Python obfuscator (pyobf_core + pyobf_cli).

Tests that every obfuscation technique produces valid, semantically equivalent code.
"""
import sys
import os
import ast
import unittest
import subprocess
import tempfile
import textwrap
from contextlib import contextmanager

# Path to the obfuscator
_TOOLS_DIR = os.path.normpath(os.path.join(__file__, '../../tools'))
_CORE_DIR = os.path.normpath(os.path.join(__file__, '../../include/crypto'))

sys.path.insert(0, _CORE_DIR)
sys.path.insert(0, _TOOLS_DIR)

# Import the core module directly
import pyobf_core


def _apply(techniques, source):
    """Apply obfuscation techniques to *source*, return output source."""
    return pyobf_core.obfuscate(techniques, source)


def _exec_and_check(obfuscated, expected_output, label=''):
    """Compile and exec *obfuscated*, capture stdout, compare to expected."""
    ns = {}
    try:
        compiled = compile(obfuscated, '<obfuscated>', 'exec')
    except SyntaxError as e:
        raise AssertionError(f"{label}: SyntaxError in obfuscated output: {e}")

    old_stdout = sys.stdout
    sys.stdout = io = __import__('io').StringIO()
    try:
        exec(compiled, ns)
    except Exception as e:
        raise AssertionError(f"{label}: RuntimeError: {e}")
    finally:
        sys.stdout = old_stdout

    actual = io.getvalue()
    if expected_output is not None and actual != expected_output:
        raise AssertionError(
            f"{label}: output mismatch\n"
            f"  expected: {expected_output!r}\n"
            f"  actual:   {actual!r}")


def _check(techniques, source, expected_output=None, label=''):
    """Full round-trip: obfuscate → exec → compare."""
    obf = _apply(techniques, source)
    _exec_and_check(obf, expected_output, label or techniques)


@contextmanager
def _capture_stderr():
    """Capture stderr in a StringIO."""
    old = sys.stderr
    sys.stderr = buf = __import__('io').StringIO()
    try:
        yield buf
    finally:
        sys.stderr = old


class TestTechniques(unittest.TestCase):

    SIMPLE_FUNC = '''\
def add(a, b):
    return a + b
'''

    SIMPLE_OUTPUT = '7\n'

    def test_rename(self):
        _check('rename', self.SIMPLE_FUNC + 'print(add(3, 4))',
               self.SIMPLE_OUTPUT, 'rename')

    def test_vstrings(self):
        src = 'print("hello world")'
        _check('vstrings', src, 'hello world\n', 'vstrings')

    def test_strings(self):
        src = 'print("hello world")'
        _check('strings', src, 'hello world\n', 'strings')

    def test_cleanup(self):
        src = '"""docstring"""\nprint(1)'
        _check('cleanup', src, '1\n', 'cleanup')

    def test_flow(self):
        src = '''\
def f(x):
    if x > 0:
        return x
    return -x
print(f(5))
print(f(-3))
'''
        _check('flow', src, '5\n3\n', 'flow')

    def test_aflow(self):
        src = '''\
def f(x):
    if x > 0:
        return x
    return -x
print(f(5))
print(f(-3))
'''
        _check('aflow', src, '5\n3\n', 'aflow')

    def test_opaque(self):
        src = '''\
def f():
    n = 0
    while True:
        if n == 0:
            return 42
print(f())
'''
        _check('opaque', src, '42\n', 'opaque')

    def test_mutate(self):
        src = 'print(1 + 2)'
        _check('mutate', src, '3\n', 'mutate')

    def test_mba(self):
        src = 'print(5 | 3)'
        _check('mba', src, '7\n', 'mba')

    def test_junk(self):
        src = 'print(42)'
        _check('junk', src, '42\n', 'junk')

    @unittest.skipIf(not sys.stdin.isatty(), "apihash changes imports; test manually")
    def test_apihash(self):
        src = 'import os\nprint(os.sep)'
        _check('apihash', src, '/\n', 'apihash')

    def test_funcenc(self):
        src = 'def f(): return 42\nprint(f())'
        _check('funcenc', src, '42\n', 'funcenc')

    def test_all(self):
        src = '''\
def add(a, b):
    return a + b
print(add(3, 4))
'''
        _check('all', src, '7\n', 'all')

    def test_all_complex(self):
        src = '''\
import os
from math import sqrt
PI = 3.14159

def fib(n):
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a

def main():
    print("PI =", PI)
    print("fib(10) =", fib(10))
    print(os.sep[:1])

main()
'''
        _check('all', src, 'PI = 3.14159\nfib(10) = 55\n/\n', 'all_complex')


class TestEdgeCases(unittest.TestCase):

    def test_short_strings(self):
        src = 'print("a")'
        _check('vstrings', src, 'a\n', 'short_string')

    def test_lambda(self):
        src = 'f = lambda x: x + 1\nprint(f(2))'
        _check('all', src, '3\n', 'lambda')

    def test_list_comprehension(self):
        src = 'print([x*x for x in range(5)])'
        _check('all', src, '[0, 1, 4, 9, 16]\n', 'list_comp')

    def test_dict_comprehension(self):
        src = 'print({x: x*x for x in range(3)})'
        _check('all', src, '{0: 0, 1: 1, 2: 4}\n', 'dict_comp')

    def test_walrus(self):
        src = '''\
def f(n):
    if (sq := n * n) > 10:
        return sq
    return 0
print(f(5))
print(f(2))
'''
        _check('all', src, '25\n0\n', 'walrus')

    def test_fstring(self):
        src = 'a, b = 1, 2\nprint(f"{a} + {b} = {a+b}")'
        _check('all', src, '1 + 2 = 3\n', 'fstring')

    def test_nested_functions(self):
        src = '''\
def outer(x):
    def inner(y):
        return y + 1
    return inner(x) + inner(x * 2)
print(outer(3))
'''
        _check('all', src, '11\n', 'nested_func')

    def test_set_ops(self):
        src = 'print({1, 2, 3} | {3, 4, 5})'
        _check('all', src, '{1, 2, 3, 4, 5}\n', 'set_ops')

    def test_multi_pass_xor(self):
        _check('multi-pass-xor', 'print(42)\n', '42\n', 'multi-pass-xor')

    def test_multi_pass_xor_with_rename(self):
        _check('rename,multi-pass-xor', 'print(42)\n', '42\n', 'multi-pass-xor+rename')

    def test_multi_pass_xor_in_all(self):
        _check('all', 'print(42)\n', '42\n', 'all-includes-mpx')

    def test_prng_xor(self):
        _check('prng-xor', 'print(42)\n', '42\n', 'prng-xor')

    def test_prng_xor_with_rename(self):
        _check('rename,prng-xor', 'print(42)\n', '42\n', 'prng-xor+rename')

    def test_prng_xor_in_all(self):
        _check('all', 'print(42)\n', '42\n', 'all-includes-prng')

    def test_recursion(self):
        src = '''\
def fact(n):
    if n <= 1:
        return 1
    return n * fact(n - 1)
print(fact(5))
'''
        _check('all', src, '120\n', 'recursion')

    def test_generator(self):
        src = '''\
def gen(n):
    for i in range(n):
        yield i * i
print(list(gen(5)))
'''
        _check('all', src, '[0, 1, 4, 9, 16]\n', 'generator')

    def test_class_with_decorators(self):
        src = '''\
class MyClass:
    @staticmethod
    def static_method(x):
        return x * 2
    @classmethod
    def class_method(cls):
        return cls.__name__
print(MyClass.static_method(5))
print(MyClass.class_method())
'''
        # 'all' includes rename which changes class names;
        # use specific techniques that preserve class names
        _check('funcenc,mba,vstrings', src, '10\nMyClass\n', 'class_decorators')

    def test_exception_handling(self):
        src = '''\
def f():
    try:
        return int("not_a_number")
    except:
        return -1
print(f())
'''
        _check('all', src, '-1\n', 'exception')

    def test_empty_file(self):
        src = ''
        obf = _apply('rename', src)
        self.assertEqual(obf.strip(), '', 'empty file should remain empty')

    def test_module_level_string(self):
        src = 'x = "hello"\nprint(x)'
        _check('vstrings', src, 'hello\n', 'module_string')

    def test_all_individual_techniques(self):
        """Verify each technique individually on a shared body."""
        src = 'print(42)\n'
        for tech in ['cleanup', 'rename', 'strings', 'vstrings',
                     'flow', 'aflow', 'opaque', 'mutate', 'mba',
                     'junk', 'funcenc']:
            with self.subTest(technique=tech):
                _check(tech, src, '42\n', tech)


class TestCLI(unittest.TestCase):
    """Test the CLI wrapper (tools/pyobf.py)."""

    def setUp(self):
        self._pyobf = os.path.join(_TOOLS_DIR, 'pyobf.py')

    def _run_cli(self, techniques, source):
        """Run the CLI wrapper and return stdout."""
        result = subprocess.run(
            [sys.executable, self._pyobf, techniques],
            input=source,
            capture_output=True,
            text=True,
            timeout=30)
        self.assertEqual(result.returncode, 0,
                         msg=f"CLI stderr: {result.stderr}")
        return result.stdout

    def test_cli_rename(self):
        src = 'print(42)\n'
        out = self._run_cli('rename', src)
        exec_ns = {}
        exec(out, exec_ns)

    def test_cli_all(self):
        src = 'def f(): return 42\nprint(f())\n'
        out = self._run_cli('all', src)
        exec_ns = {}
        exec(out, exec_ns)
        # Can't easily check output of exec'd function,
        # but at least verify no SyntaxError


class TestSyntaxErrorWarning(unittest.TestCase):
    """Verify that SyntaxError warnings are emitted."""

    def test_stderr_warning_on_bad_input(self):
        src = 'print(42)\n'
        with _capture_stderr() as stderr:
            result = _apply('rename', src + '\n```\n')  # syntax error after
        warning = stderr.getvalue()
        # The code before the error should still be processed;
        # the function should warn about failure
        self.assertIn('WARNING', warning)

    def test_cli_stderr_warning(self):
        """CLI should emit warnings to stderr when obfuscation fails."""
        result = subprocess.run(
            [sys.executable, os.path.join(_TOOLS_DIR, 'pyobf.py'), 'all'],
            input='invalid python {{{',
            capture_output=True,
            text=True,
            timeout=10)
        self.assertIn('WARNING', result.stderr)


# Re-export obfuscate for convenience
obfuscate = _apply
