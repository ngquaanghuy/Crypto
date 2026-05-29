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
