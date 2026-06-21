#include "crypto/obfuscate.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <algorithm>
#include <openssl/rand.h>

/* ── Random helpers ── */
static int rand_range(int lo, int hi) {
    unsigned char buf[4];
    RAND_bytes(buf, 4);
    uint32_t r = (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) |
                 ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24);
    return lo + (int)(r % (uint32_t)(hi - lo + 1));
}

static std::string rand_var(void) {
    int len = rand_range(5, 10);
    std::string r;
    r += '_';
    for (int i = 1; i < len; i++) {
        unsigned char c;
        RAND_bytes(&c, 1);
        int set = c % 3;
        if (set == 0) r += 'a' + (c % 26);
        else if (set == 1) r += 'A' + (c % 26);
        else r += '0' + (c % 10);
    }
    return r;
}

/* ── Side-effect junk pool ── */
/* Format: %s=var, %d=int (number of items, range bound, etc.) */

static const char *side_effect_pool[] = {
    "%s = [None for _ in range(%d)]\n%s = %s.pop() if %s else None\n",
    "%s = list(range(%d))\nimport random as %s\n%s.shuffle(%s)\n%s = %s.pop()\n",
    "%s = {str(_): _ for _ in range(%d)}\n%s = %s.get('0', None)\n",
    "%s = bytearray(%d)\nfor _i in range(len(%s)): %s[_i] = (_i * 7 + 3) & 0xFF\n%s = bytes(%s)\n",
    "%s = [x*x for x in range(%d) if x%%2==0]\n%s = sum(%s) - sum(%s)\n",
    "%s = (lambda _x: [_.upper() for _ in dir(_x) if not _.startswith('_')])(%d)\n%s = len(%s)\n",
    "%s = frozenset(range(%d))\n%s = %s.union(%s)\n",
    "%s = memoryview(bytearray(range(%d))).tolist()\n%s = sum(%s)\n",
    "%s = tuple(reversed(range(%d)))\n%s = %s.index(%d)\n",
    "%s = [_ for _ in range(%d) if bin(_).count('1')%%2==0]\n%s = len(%s)\n",
    "%s = [[x,y] for x in range(%d) for y in range(2) if x+y>0]\n%s = len(%s)\n",
    "%s = [x*x for x in range(%d)]\n%s = list(filter(lambda _:_>%d,%s))\n%s = len(%s)\n",
    "%s = map(str, range(%d))\n%s = list(%s)\n%s = len(%s)\n",
    "%s = zip(range(%d), range(%d))\n%s = dict(%s)\n%s = list(%s.keys())\n",
    "%s = enumerate(range(%d))\n%s = [%d+1 for _,%s in %s]\n%s = len(%s)\n",
    "%s = bytes(%d).hex()\n%s = bytes.fromhex(%s)\n",
    "%s = bytearray()\n%s.extend(b'\\x00'*%d)\n%s = bytes(%s)\n",
    "%s = (lambda _x: _x * (_x + 1) // 2)(%d)\n%s = %s %% %d\n",
    "%s = [%d*i for i in range(%d)]\n%s = sum(%s) - sum(%s) + sum(%s)\n",
    "%s = list(%d for _ in range(%d))\n%s = %s.count(%d)\n",
};
static const int SIDE_POOL_COUNT = sizeof(side_effect_pool) / sizeof(side_effect_pool[0]);

/* ── Simple junk pool ── */
static const char *simple_junk_pool[] = {
    "%s = (lambda _x: _x and not _x)(None)\n",
    "%s = [x for x in ()] == []\n",
    "%s = (lambda: sorted([3,1,2]) == [1,2,3])()\n",
    "%s = all([]) and not any([False])\n",
    "%s = str(bin(42)) == '0b101010'\n",
    "%s = bytes.fromhex('deadbeef') != b'\\xde\\xad\\xbe\\xef' or True\n",
    "%s = ' '.join(repr(range(3))) == '[0] [1] [2]'\n",
    "%s = sorted([None]) == [None]\n",
    "%s = type(type) is type\n",
    "%s = sum([[x] for x in range(3)], []) == [0,1,2]\n",
    "%s = ~(~42) == 42\n",
    "%s = (1<<8) == 256\n",
    "%s = divmod(100,7)[1] == 100 %% 7\n",
    "%s = pow(2,10,1000) > 0\n",
    "%s = isinstance(hash, type(lambda:0))\n",
};
static const int SIMPLE_POOL_COUNT = sizeof(simple_junk_pool) / sizeof(simple_junk_pool[0]);

/* ── Try/except junk pool ── */
static const char *try_except_pool[] = {
    "try:\n    %s\nexcept:\n    %s = None\n",
    "try:\n    %s = [%s for _ in range(%d)]\n    %s = %s.pop(0)\nexcept (IndexError, ValueError):\n    %s = None\n",
    "try:\n    %s = (lambda _x: _x // _x)(%d)\nexcept ZeroDivisionError:\n    %s = 0\n",
    "try:\n    %s = %s[%d]\nexcept (IndexError, KeyError, TypeError):\n    %s = None\n",
};
static const int TRY_POOL_COUNT = sizeof(try_except_pool) / sizeof(try_except_pool[0]);

/* ── If/else junk pool ── */
/* Each template is handled separately in junk_generate_ifelse_block */
static const char *if_else_pool[] = {
    "if %s >= %d:\n    %s = [x for x in range(%d, %d)]\n    %s = [x*x for x in range(%d, %d)]\nelse:\n    %s = %s + %s\n",
    "if hasattr(%s, '%s'):\n    %s = %s.%s(%d)\n    %s = %s\nelse:\n    %s = %s.%s(%d)\n    %s = %s + %s\n    %s = %s\n",
    "if %s > %d:\n    %s = list(filter(lambda _: _ > %d, range(%d)))\nelse:\n    %s = [x for x in range(%d)]\n    %s = %s + %s\n    %s = %s\n",
};
static const int IF_ELSE_COUNT = sizeof(if_else_pool) / sizeof(if_else_pool[0]);

/* ── Default config ── */
void junk_config_default(JunkConfig *cfg) {
    if (!cfg) return;
    cfg->variable_names = nullptr;
    cfg->num_variables = 0;
    cfg->include_side_effects = 1;
    cfg->include_both_branches = 1;
}

/* ── Generate junk statement ── */
char *junk_generate_statement(const JunkConfig *cfg) {
    if (!cfg) return nullptr;
    unsigned char sel;
    RAND_bytes(&sel, 1);

    char buf[1024];
    std::string v1 = rand_var(), v2 = rand_var(), v3 = rand_var();
    int size = rand_range(4, 128);

    if (cfg->include_side_effects && (sel & 1)) {
        int idx = rand_range(0, SIDE_POOL_COUNT - 1);
        int sz = rand_range(2, 64);
        int guard = rand_range(0, 999);
        int vx = rand_range(1, 100);
        /* Each side_effect template may have different format specifier positions;
           use switch to pass exactly the right number and types of arguments. */
        switch (idx) {
            case 0:
                /* %s = [None ... range(%d)]  %s = %s.pop() if %s else None */
                snprintf(buf, sizeof(buf), side_effect_pool[0],
                         v1.c_str(), size, v2.c_str(), v2.c_str(), v1.c_str());
                break;
            case 1:
                /* %s = list(range(%d))  import random as %s  %s.shuffle(%s)  %s = %s.pop() */
                snprintf(buf, sizeof(buf), side_effect_pool[1],
                         v1.c_str(), size, v2.c_str(), v2.c_str(), v1.c_str(),
                         v3.c_str(), v2.c_str());
                break;
            case 2:
                /* %s = {str(_): _ for _ in range(%d)}  %s = %s.get('0', None) */
                snprintf(buf, sizeof(buf), side_effect_pool[2],
                         v1.c_str(), size, v2.c_str(), v1.c_str());
                break;
            case 3:
                /* %s = bytearray(%d)  for _i ... len(%s) ... %s[_i] ...  %s = bytes(%s) */
                snprintf(buf, sizeof(buf), side_effect_pool[3],
                         v1.c_str(), size, v1.c_str(), v1.c_str(),
                         v2.c_str(), v1.c_str());
                break;
            case 4:
                /* %s = [x*x for x in range(%d) if x%%2==0]  %s = sum(%s) - sum(%s) */
                snprintf(buf, sizeof(buf), side_effect_pool[4],
                         v1.c_str(), size, v2.c_str(), v2.c_str(), v1.c_str());
                break;
            case 5:
                /* %s = (lambda _x: ...)(%d)  %s = len(%s) */
                snprintf(buf, sizeof(buf), side_effect_pool[5],
                         v1.c_str(), size, v2.c_str(), v2.c_str());
                break;
            case 6:
                /* %s = frozenset(range(%d))  %s = %s.union(%s) */
                snprintf(buf, sizeof(buf), side_effect_pool[6],
                         v1.c_str(), size, v2.c_str(), v1.c_str(), v3.c_str());
                break;
            case 7:
                /* %s = memoryview(bytearray(range(%d))).tolist()  %s = sum(%s) */
                snprintf(buf, sizeof(buf), side_effect_pool[7],
                         v1.c_str(), size, v2.c_str(), v2.c_str());
                break;
            case 8:
                /* %s = tuple(reversed(range(%d)))  %s = %s.index(%d) */
                snprintf(buf, sizeof(buf), side_effect_pool[8],
                         v1.c_str(), size, v2.c_str(), v1.c_str(), guard);
                break;
            case 9:
                /* %s = [... range(%d) ...]  %s = len(%s) */
                snprintf(buf, sizeof(buf), side_effect_pool[9],
                         v1.c_str(), size, v2.c_str(), v2.c_str());
                break;
            case 10:
                /* %s = [[x,y] ... range(%d) ...]  %s = len(%s) */
                snprintf(buf, sizeof(buf), side_effect_pool[10],
                         v1.c_str(), size, v2.c_str(), v2.c_str());
                break;
            case 11:
                /* %s = [x*x ... range(%d)]  %s = list(filter(..., %d, %s))  %s = len(%s) */
                snprintf(buf, sizeof(buf), side_effect_pool[11],
                         v1.c_str(), size, v2.c_str(), vx, v1.c_str(),
                         v3.c_str(), v3.c_str());
                break;
            case 12:
                /* %s = map(str, range(%d))  %s = list(%s)  %s = len(%s) */
                snprintf(buf, sizeof(buf), side_effect_pool[12],
                         v1.c_str(), size, v2.c_str(), v1.c_str(),
                         v3.c_str(), v3.c_str());
                break;
            case 13:
                /* %s = zip(range(%d), range(%d))  %s = dict(%s)  %s = list(%s.keys()) */
                snprintf(buf, sizeof(buf), side_effect_pool[13],
                         v1.c_str(), sz, size, v2.c_str(), v1.c_str(),
                         v3.c_str(), v1.c_str());
                break;
            case 14:
                /* %s = enumerate(range(%d))  %s = [%d+1 for _,%s in %s]  %s = len(%s) */
                snprintf(buf, sizeof(buf), side_effect_pool[14],
                         v1.c_str(), size, v2.c_str(), guard, v3.c_str(), v1.c_str(),
                         v2.c_str(), v2.c_str());
                break;
            case 15:
                /* %s = bytes(%d).hex()  %s = bytes.fromhex(%s) */
                snprintf(buf, sizeof(buf), side_effect_pool[15],
                         v1.c_str(), size, v2.c_str(), v1.c_str());
                break;
            case 16:
                /* %s = bytearray()  %s.extend(...%d)  %s = bytes(%s) */
                snprintf(buf, sizeof(buf), side_effect_pool[16],
                         v1.c_str(), v2.c_str(), size, v3.c_str(), v1.c_str());
                break;
            case 17:
                /* %s = (lambda _x: ...)(%d)  %s = %s %% %d */
                snprintf(buf, sizeof(buf), side_effect_pool[17],
                         v1.c_str(), size, v2.c_str(), v3.c_str(), guard);
                break;
            case 18:
                /* %s = [%d*i for i in range(%d)]  %s = sum(%s) - sum(%s) + sum(%s) */
                snprintf(buf, sizeof(buf), side_effect_pool[18],
                         v1.c_str(), vx, size, v2.c_str(), v2.c_str(),
                         v1.c_str(), v3.c_str(), v3.c_str());
                break;
            case 19:
                /* %s = list(%d for _ in range(%d))  %s = %s.count(%d) */
                snprintf(buf, sizeof(buf), side_effect_pool[19],
                         v1.c_str(), vx, size, v2.c_str(), v1.c_str(), guard);
                break;
            default:
                buf[0] = '\0';
                break;
        }
    } else if ((sel >> 1) & 1) {
        int idx = rand_range(0, TRY_POOL_COUNT - 1);
        int sub_sz = rand_range(2, 32);
        /* Each try/except template has different format specifiers */
        switch (idx) {
            case 0:
                /* try: %s  except: %s = None */
                snprintf(buf, sizeof(buf), try_except_pool[0],
                         v1.c_str(), v2.c_str());
                break;
            case 1:
                /* try: %s = [%s for _ in range(%d)]  %s = %s.pop(0)  except: %s = None */
                snprintf(buf, sizeof(buf), try_except_pool[1],
                         v1.c_str(), v2.c_str(), sub_sz,
                         v3.c_str(), v1.c_str(), v2.c_str());
                break;
            case 2:
                /* try: %s = (lambda _x: _x // _x)(%d)  except: %s = 0 */
                snprintf(buf, sizeof(buf), try_except_pool[2],
                         v1.c_str(), size, v2.c_str());
                break;
            case 3:
                /* try: %s = %s[%d]  except: %s = None */
                snprintf(buf, sizeof(buf), try_except_pool[3],
                         v1.c_str(), v2.c_str(), sub_sz, v3.c_str());
                break;
            default:
                buf[0] = '\0';
                break;
        }
    } else {
        int idx = rand_range(0, SIMPLE_POOL_COUNT - 1);
        snprintf(buf, sizeof(buf), simple_junk_pool[idx], v1.c_str());
    }

    std::string result = buf;

    if (cfg->variable_names && cfg->num_variables > 0 && (sel & 4)) {
        int vi = rand_range(0, cfg->num_variables - 1);
        std::string refvar = cfg->variable_names[vi];
        result += v2 + " = isinstance(" + refvar + ", type(" + refvar + "))\n";
    }

    return strdup(result.c_str());
}

/* ── Generate if/else junk block ── */
char *junk_generate_ifelse_block(const JunkConfig *cfg) {
    if (!cfg) return nullptr;
    int idx = rand_range(0, IF_ELSE_COUNT - 1);
    std::string v1 = rand_var(), v2 = rand_var(), v3 = rand_var();
    std::string v4 = rand_var(), v5 = rand_var();
    std::string attr1 = rand_var(), attr2 = rand_var();
    int sz1 = rand_range(2, 64);
    int sz2 = rand_range(2, 64);
    int val = rand_range(0, 10000);

    char buf[2048];

    /* Each template has a different number of format specifiers;
       pass only the exact arguments each template needs. */
    switch (idx) {
        case 0:
            /* if %s >= %d:  %s = [x for x in range(%d, %d)]  %s = [x*x ... %d, %d)]  %s = %s + %s */
            snprintf(buf, sizeof(buf), if_else_pool[0],
                     v1.c_str(), val,
                     v2.c_str(), sz1, sz2,
                     v3.c_str(), sz1, sz2,
                     v4.c_str(), v2.c_str(), v3.c_str());
            break;
        case 1:
            /* if hasattr(%s, '%s'):  %s = %s.%s(%d)  %s = %s  else:  %s = %s.%s(%d)  %s = %s + %s  %s = %s */
            snprintf(buf, sizeof(buf), if_else_pool[1],
                     v1.c_str(), attr1.c_str(),
                     v2.c_str(), v1.c_str(), attr2.c_str(), sz1,
                     v3.c_str(), v2.c_str(),
                     v4.c_str(), v1.c_str(), attr1.c_str(), sz2,
                     v5.c_str(), v4.c_str(), v3.c_str(),
                     v4.c_str(), v5.c_str());
            break;
        case 2:
            /* if %s > %d:  %s = list(filter(..., %d, range(%d)))  %s = [x for x in range(%d)]  %s = %s + %s  %s = %s */
            snprintf(buf, sizeof(buf), if_else_pool[2],
                     v1.c_str(), val,
                     v2.c_str(), sz1, sz2,
                     v3.c_str(), sz2,
                     v4.c_str(), v2.c_str(), v3.c_str(),
                     v5.c_str(), v4.c_str());
            break;
    }
    return strdup(buf);
}

/* ── Generate junk function ── */
char *junk_generate_function(const JunkConfig *cfg) {
    if (!cfg) return nullptr;
    std::string fn = rand_var(), arg = rand_var();
    std::string v1 = rand_var(), v2 = rand_var();
    int size = rand_range(8, 256);
    int mod = rand_range(1000, 99999);
    int mul = rand_range(100, 999);

    std::string result;
    result += "def " + fn + "(" + arg + "):\n";
    result += "    if not isinstance(" + arg + ", (int, float, str)):\n";
    result += "        return None\n";
    result += "    " + v1 + " = [(" + arg + " + i) % " + std::to_string(mod) +
              " for i in range(" + std::to_string(size) + ")]\n";
    result += "    " + v2 + " = (sum(" + v1 + ") % " + std::to_string(mod) + ")\n";
    result += "    " + v2 + " = (" + v2 + " * " + std::to_string(mul) +
              " + len(" + v1 + ")) % " + std::to_string(mod) + "\n";
    result += "    return " + v2 + " if " + v2 + " > 0 else None\n";
    return strdup(result.c_str());
}

/* ── Generate full junk section ── */
char *junk_generate_section(const JunkConfig *cfg, int count) {
    if (!cfg || count < 1) return nullptr;
    std::string result;
    result.reserve((size_t)count * 512);

    unsigned char has_func;
    RAND_bytes(&has_func, 1);
    if (has_func % 3 != 0) {
        char *f = junk_generate_function(cfg);
        if (f) { result += f; result += "\n"; free(f); }
    }

    int if_else_count = (count > 3) ? rand_range(1, count / 2) : 1;
    for (int i = 0; i < count; i++) {
        unsigned char sel;
        RAND_bytes(&sel, 1);
        if (cfg->include_both_branches && (sel & 1) && if_else_count > 0) {
            char *block = junk_generate_ifelse_block(cfg);
            if (block) { result += block; result += "\n"; free(block); }
            if_else_count--;
        } else {
            char *stmt = junk_generate_statement(cfg);
            if (stmt) { result += stmt; free(stmt); }
        }
    }
    return strdup(result.c_str());
}