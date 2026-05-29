#!/usr/bin/env python3
"""Generate include/crypto/compress_script.h from tools/compress.py.

Usage: python3 tools/generate_compress_h.py
"""
import os
import sys

_TOOLS_DIR = os.path.dirname(__file__ or '.')
_PROJECT_DIR = os.path.normpath(os.path.join(_TOOLS_DIR, '..'))
_SCRIPT_PATH = os.path.join(_TOOLS_DIR, 'compress.py')
_HEADER_PATH = os.path.join(_PROJECT_DIR, 'include/crypto/compress_script.h')


def generate():
    with open(_SCRIPT_PATH) as f:
        script = f.read()

    header = '''\
#ifndef CRYPTO_COMPRESS_SCRIPT_H
#define CRYPTO_COMPRESS_SCRIPT_H

/*
 * THIS FILE IS AUTO-GENERATED from tools/compress.py
 * by tools/generate_compress_h.py.  Do NOT edit directly.
 *
 * To regenerate:
 *     python3 tools/generate_compress_h.py
 */

static const char COMPRESS_SCRIPT[] = R"compress_script(
''' + script + '''\
)compress_script";

#endif /* CRYPTO_COMPRESS_SCRIPT_H */
'''

    with open(_HEADER_PATH, 'w') as f:
        f.write(header)

    print(f"Generated {_HEADER_PATH} ({len(script)} bytes)")


if __name__ == '__main__':
    generate()
