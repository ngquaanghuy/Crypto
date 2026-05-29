#!/usr/bin/env python3
"""Generate include/crypto/pyobf.h from include/crypto/pyobf_core.py.

Usage: python3 tools/generate_pyobf_h.py
"""
import os
import sys

_TOOLS_DIR = os.path.dirname(__file__ or '.')
_PROJECT_DIR = os.path.normpath(os.path.join(_TOOLS_DIR, '..'))
_CORE_PATH = os.path.join(_PROJECT_DIR, 'include/crypto/pyobf_core.py')
_HEADER_PATH = os.path.join(_PROJECT_DIR, 'include/crypto/pyobf.h')


def _cli_code():
    """Return the CLI main block that wraps the core logic."""
    return '''
if __name__ == '__main__':
    techniques = [t.strip() for t in sys.argv[1].split(',')] \\
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
'''


def generate():
    with open(_CORE_PATH) as f:
        core_code = f.read()

    script = core_code + _cli_code()

    header = '''\
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
''' + script + '''
)pyobf_script";

#endif /* CRYPTO_PYOBF_H */
'''
    with open(_HEADER_PATH, 'w') as f:
        f.write(header)

    print(f"Generated {_HEADER_PATH} ({len(script)} bytes)")


if __name__ == '__main__':
    generate()
