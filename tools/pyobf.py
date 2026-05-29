#!/usr/bin/env python3
"""Python source code obfuscator — CLI wrapper.

Usage:
    python3 pyobf.py <techniques> < input.py > output.py

Techniques:
    rename     Rename identifiers
    strings    Encrypt string literals (XOR inline)
    vstrings   Virtualize strings (chunked + runtime eval decrypt)
    cleanup    Remove docstrings and standalone expressions
    flow       Basic control flow flattening (if/else → state machine)
    aflow      Advanced control flow flatt. (dispatch table + opaque predicates)
    opaque     Encode state variable with non-linear transformations
    mutate     AST mutation (binary op → lambda/sum/complex expr)
    mba        Mixed Boolean-Arithmetic (math identity replacements)
    junk       Junk code injection (dead code with opaque predicates)
    apihash    Replace static imports with FNV-1a hash dynamic resolution
    funcenc    Encrypt function bodies (SHA-256-CTR, on-the-fly decryption)
    all        All of the above
"""
import sys
import os

# Import core obfuscation logic from the shared location
_core_dir = os.path.normpath(os.path.join(__file__ and os.path.dirname(__file__) or '.', 
                                          '../include/crypto'))
if _core_dir not in sys.path:
    sys.path.insert(0, _core_dir)

# Expose all public symbols from pyobf_core
# The core handles its own imports (ast, random, etc.)
import pyobf_core as _pyobf_core
# Pull all names from the core into this module's globals
_globals = globals()
for _name in dir(_pyobf_core):
    if not _name.startswith('_') or _name in ('__all__',):
        _globals[_name] = getattr(_pyobf_core, _name)

del _globals, _name, _core_dir

if __name__ == '__main__':
    seed = None
    techniques_arg = 'all'
    i = 1
    while i < len(sys.argv):
        if sys.argv[i] == '--seed':
            i += 1
            seed = int(sys.argv[i]) if i < len(sys.argv) else None
        elif sys.argv[i].startswith('-'):
            sys.stderr.write(f'error: unknown option {sys.argv[i]}\\n')
            sys.exit(1)
        else:
            techniques_arg = sys.argv[i]
        i += 1

    source = sys.stdin.read()
    source = obfuscate(techniques_arg, source, seed=seed)
    sys.stdout.write(source)
