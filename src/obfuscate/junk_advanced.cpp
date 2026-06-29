#include "crypto/obfuscate.h"
#include <cstdint>
#include <string>
#include <format>
#include <openssl/rand.h>

/* ── MBA-style junk (Mixed Boolean-Arithmetic) ── */
std::string junk_gen_mba(void) {
    unsigned char r[8];
    RAND_bytes(r, sizeof(r));

    int style = r[0] % 5;
    int v = (int)r[1] % 100 + 10;
    int m1 = (int)r[2] % 50 + 5;
    int m2 = (int)r[3] % 50 + 5;

    switch (style) {
        case 0:
            return std::format("_j{} = (({}|{})^({}&{})) ^ ({}|{}) ^ ({}&{})\n",
                r[4] % 10 + 1, v, m1, v, m1, v, m2, v, m2);
        case 1:
            return std::format("_j{} = (1 if {} > 0 else 0) - (1 if {} < 0 else 0) + abs({})\n",
                r[5] % 20 + 1, v, v, v);
        case 2:
            return std::format("_j{} = (({} | {}) ^ ({} & {}) ^ {}) ^ {}\n",
                r[6] % 15 + 1, v, m1, v, m1, m2, v);
        case 3:
            return std::format("_j{} = ({} * {}) % {} % {} % {}\n",
                r[7] % 25 + 1, v, m1, m1, m2, m1 + m2);
        case 4:
        default:
            return std::format("_j{} = (({} << {}) & 0xFF) >> {} & 0xFF\n",
                v % 30 + 1, v, m1 % 4, m1 % 4);
    }
}

/* ── Opaque jump junk ── */
std::string junk_gen_opaque_jump(void) {
    unsigned char r[8];
    RAND_bytes(r, sizeof(r));

    int style = r[0] % 4;
    int v = (int)r[1] % 100 + 10;
    int m1 = (int)r[5] % 50 + 5;
    int m2 = (int)r[6] % 50 + 5;

    switch (style) {
        case 0:
            return std::format(
                "_j{} = {}\n"
                "while _j{} > 0:\n"
                "    if {} ^ ({} & 0xFF) == 0:\n"
                "        _j{} = _j{} - 1\n"
                "    else:\n"
                "        break\n",
                r[2] % 20 + 1, v,
                r[2] % 20 + 1,
                v, v,
                r[2] % 20 + 1,
                r[2] % 20 + 1);
        case 1:
            return std::format(
                "_j{} = [0]\n"
                "def _f(_n):\n"
                "    if _n > 0:\n"
                "        _j{}.append(_j{}[-1] + 1)\n"
                "        return _f(_n - 1)\n"
                "    return _j{}[-1]\n"
                "_ = _f({})\n",
                r[3] % 15 + 1,
                r[3] % 15 + 1, r[3] % 15 + 1,
                r[3] % 15 + 1,
                v % 10 + 1);
        case 2:
            return std::format(
                "try:\n"
                "    _j{} = {}\n"
                "    _j{} = [_j{} for _ in range({})]\n"
                "    _j{} = _j{}[_j{} // {}]\n"
                "except (IndexError, ZeroDivisionError):\n"
                "    _j{} = None\n",
                r[4] % 25 + 1, v,
                r[4] % 25 + 1, r[4] % 25 + 1, v % 10 + 2,
                r[4] % 25 + 1, r[4] % 25 + 1, r[4] % 25 + 1, v % 5 + 1,
                r[4] % 25 + 1);
        case 3:
        default:
            return std::format(
                "_j{} = (lambda _x: (_x + {}) * {} - {})(0)\n"
                "_j{} = list(filter(lambda _y: _y > 0, range(-{}, {})))\n"
                "_j{} = sum(_j{}) if _j{} else 0\n",
                r[5] % 18 + 1, v, m1, m2,
                r[5] % 18 + 1, v, v * 2,
                r[5] % 18 + 1, r[5] % 18 + 1, v % 2);
    }
}

/* ── Encode/decode junk ── */
std::string junk_gen_codec(void) {
    unsigned char r[8];
    RAND_bytes(r, sizeof(r));

    int style = r[0] % 4;
    int key = (int)r[1] % 26 + 1;
    char var = 'a' + (r[2] % 26);

    switch (style) {
        case 0:
            return std::format(
                "_j{} = ''.join(chr((ord(c) - ord('a') + {}) % 26 + ord('a')) "
                "if c.isalpha() else c for c in '{}')\n",
                r[3] % 20 + 1, key, var);
        case 1:
            return std::format(
                "_j{} = bytes.fromhex('{:02x}'.format(_)) if isinstance(_, int) else None\n",
                r[4] % 15 + 1, key * 0x9B % 256);
        case 2:
            return std::format(
                "_j{} = ''.join(chr(ord(c) ^ {}) for c in '{}')\n",
                r[5] % 22 + 1, key, var);
        case 3:
        default:
            return std::format(
                "_j{} = ''.join(chr((ord(c) - {} - 97) % 26 + 97) for c in '{}' if c.isalpha())\n",
                r[6] % 18 + 1, key, var);
    }
}
