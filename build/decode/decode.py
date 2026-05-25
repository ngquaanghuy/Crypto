#!/usr/bin/env python3

import re
import ast
import zlib
import base64
import hashlib
import hmac
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

TARGET = "a1.py"


def extract_var(name, src):
    m = re.search(
        rf"{name}\s*=\s*(.+)",
        src
    )

    if not m:
        raise Exception(f"cannot find {name}")

    return ast.literal_eval(m.group(1))


def recover_key(src):
    m = re.search(
        r'bytes\.fromhex\("([0-9a-fA-F]+)"\)',
        src
    )

    if not m:
        raise Exception("cannot find key")

    raw = bytes.fromhex(m.group(1))

    return bytes(b ^ 0x55 for b in raw).decode()


def main():
    src = Path(TARGET).read_text(
        encoding="utf-8",
        errors="ignore"
    )

    print("[+] loaded")

    payload_b64 = extract_var("_P", src)
    algo = extract_var("_A", src)

    print(f"[+] algo = {algo}")

    if algo != 3:
        raise Exception("only AES-GCM supported")

    password = recover_key(src)

    print("[+] recovered key")
    print(f"[+] key = {password}")

    blob = base64.b64decode(payload_b64)

    salt = blob[:16]
    mac = blob[-32:]
    encrypted = blob[16:-32]

    ciphertext = encrypted[:-16]
    tag = encrypted[-16:]

    print("[+] parsed payload")

    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        100000,
        dklen=76
    )

    aes_key = derived[:32]
    nonce = derived[32:44]
    hmac_key = derived[44:76]

    calc = hmac.new(
        hmac_key,
        encrypted,
        hashlib.sha256
    ).digest()

    if not hmac.compare_digest(mac, calc):
        raise Exception("HMAC failed")

    print("[+] HMAC OK")

    decrypted = AESGCM(aes_key).decrypt(
        nonce,
        ciphertext + tag,
        None
    )

    print("[+] AES decrypted")

    # compression flag
    if decrypted[1] & 1:
        print("[+] zlib compressed")

        final = zlib.decompress(
            decrypted[4:]
        )
    else:
        final = decrypted[4:]

    out = "decoded_a1.py"

    Path(out).write_bytes(final)

    print(f"[+] dumped -> {out}")


if __name__ == "__main__":
    main()