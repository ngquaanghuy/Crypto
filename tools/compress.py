#!/usr/bin/env python3
"""Compress/decompress script for Crypto tool.

Usage: python3 compress.py <algo_id> <mode> [<level>] < input > output

Mode: 'c' = compress, 'd' = decompress
Level: 1-9 (default 6, for algorithms that support it)
"""
import sys

algo_id = int(sys.argv[1])
mode = sys.argv[2]
level = int(sys.argv[3]) if len(sys.argv) > 3 else 6
data = sys.stdin.buffer.read()

try:
    if mode == 'c':
        if algo_id == 0:
            sys.stdout.buffer.write(data)
        elif algo_id == 1:
            import zlib
            sys.stdout.buffer.write(zlib.compress(data, level))
        elif algo_id == 2:
            import lzma
            sys.stdout.buffer.write(lzma.compress(data, preset=level))
        elif algo_id == 3:
            import bz2
            sys.stdout.buffer.write(bz2.compress(data, level))
        elif algo_id == 4:
            import brotli
            sys.stdout.buffer.write(brotli.compress(data, quality=level))
        elif algo_id == 5:
            import zstandard
            sys.stdout.buffer.write(zstandard.compress(data, level))
        elif algo_id == 6:
            import gzip
            sys.stdout.buffer.write(gzip.compress(data, level))
        elif algo_id == 7:
            import lz4.frame
            sys.stdout.buffer.write(lz4.frame.compress(data))
        elif algo_id == 8:
            import snappy
            sys.stdout.buffer.write(snappy.compress(data))
        elif algo_id == 9:
            import zopfli.gzip
            sys.stdout.buffer.write(zopfli.gzip.compress(data))
        elif algo_id == 10:
            import blosc
            sys.stdout.buffer.write(blosc.compress(data, level))
        else:
            sys.stdout.buffer.write(data)
    else:
        if algo_id == 0:
            sys.stdout.buffer.write(data)
        elif algo_id == 1:
            import zlib
            sys.stdout.buffer.write(zlib.decompress(data))
        elif algo_id == 2:
            import lzma
            sys.stdout.buffer.write(lzma.decompress(data))
        elif algo_id == 3:
            import bz2
            sys.stdout.buffer.write(bz2.decompress(data))
        elif algo_id == 4:
            import brotli
            sys.stdout.buffer.write(brotli.decompress(data))
        elif algo_id == 5:
            import zstandard
            sys.stdout.buffer.write(zstandard.decompress(data))
        elif algo_id == 6:
            import gzip
            sys.stdout.buffer.write(gzip.decompress(data))
        elif algo_id == 7:
            import lz4.frame
            sys.stdout.buffer.write(lz4.frame.decompress(data))
        elif algo_id == 8:
            import snappy
            sys.stdout.buffer.write(snappy.decompress(data))
        elif algo_id == 9:
            import zopfli.gzip
            sys.stdout.buffer.write(zopfli.gzip.decompress(data))
        elif algo_id == 10:
            import blosc
            sys.stdout.buffer.write(blosc.decompress(data))
        else:
            sys.stdout.buffer.write(data)
except Exception as e:
    sys.stdout.buffer.write(b'ERROR:' + str(e).encode())
