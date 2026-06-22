#include "crypto/obfuscate.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <string>
#include <format>
#include <vector>
#include <algorithm>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

/* ── Initialize flow flatten plan ── */
void flowflatten_plan_init(FlowFlattenPlan *plan, int num_blocks) {
    if (!plan) return;
    plan->blocks = (FlowBlock *)calloc(num_blocks, sizeof(FlowBlock));
    plan->num_blocks = num_blocks;
    plan->initial_state = 0;
    RAND_bytes(plan->key, sizeof(plan->key));
}

void flowflatten_plan_free(FlowFlattenPlan *plan) {
    if (!plan) return;
    for (int i = 0; i < plan->num_blocks; i++)
        free(plan->blocks[i].block_code);
    free(plan->blocks);
    plan->blocks = nullptr;
    plan->num_blocks = 0;
}

/* ── HMAC-encode state value ── */
static void hmac_encode_state(int state, const unsigned char *key,
                              size_t key_len, char *out_hex, size_t out_max) {
    unsigned char digest[32];
    unsigned int digest_len = 32;
    char state_buf[16];
    snprintf(state_buf, sizeof(state_buf), "S%d", state);
    HMAC(EVP_sha256(), key, (int)key_len,
         (const unsigned char *)state_buf, strlen(state_buf),
         digest, &digest_len);
    int hexlen = (out_max < 33) ? (int)(out_max / 2) : 16;
    for (int i = 0; i < hexlen && (i * 2 + 2) < (int)out_max; i++)
        snprintf(out_hex + i * 2, 3, "%02x", digest[i]);
}

int flowflatten_set_block(FlowFlattenPlan *plan, int idx,
                          const char *block_code, int next_state) {
    if (!plan || idx < 0 || idx >= plan->num_blocks) return 0;
    free(plan->blocks[idx].block_code);
    plan->blocks[idx].block_code = strdup(block_code);
    plan->blocks[idx].state_id = idx;
    plan->blocks[idx].next_state = next_state;
    hmac_encode_state(idx, plan->key, sizeof(plan->key),
                      plan->blocks[idx].state_encoded,
                      sizeof(plan->blocks[idx].state_encoded));
    return 1;
}

/* ── Massive opaque predicate template pool (50 variants) ── */

static const char *opaque_true_pool[] = {
    "(lambda _:str(_)==str(_) and (_+1>_))(0)",
    "(lambda _:abs(_)>=0 and hash(str(_))is not None)(hash(None))",
    "(lambda _:[x for x in(_)if x==x]==[_ for x in(_)if True])([None])",
    "(lambda _:len(str(_.__name__))>0)({}.__class__)",
    "(lambda _:[None for __ in [_]][0]is None)(0)",
    "(lambda _:all([_==_])and any([True]))(42)",
    "(lambda _:_.real==_ and _.imag==0)(1+0j)",
    "(lambda _:len(dir(_))>10)({})",
    "(lambda _:bool(_.bit_length()))(7)",
    "(lambda _:_.denominator==1 or _.numerator!=0)(1)",
    "(lambda _:str(type(_)).count('int')>0)(0)",
    "(lambda _:_.conjugate()==_)(3.14)",
    "(lambda _:[x for x in(_)if type(x)==int]==[_ for x in(_)if type(x)!=str])([1,2])",
    "(lambda _:str(hex(_)).startswith('0x'))(255)",
    "(lambda _:chr(_).isprintable())(65)",
    "(lambda _:oct(_).endswith(str(_%8)))(64)",
    "(lambda _:type(NotImplemented)==type(None)or True)(0)",
    "(lambda _:callable(_)or not callable(0))(sorted)",
    "(lambda _:type(_)==type(int))(0)",
    "(lambda _:isinstance(_,int)!=isinstance(_,str))(0)",
    "(lambda _:_ in[_ for _ in()]or not(_ not in[_]))(0)",
    "(lambda _:sorted([_])==[_])(42)",
    "(lambda _:list(repr(_)).count(str(_))>=0)(0)",
    "(lambda _:frozenset([_])==frozenset([_]))(1)",
    "(lambda _:min([_,_+1])==_)(5)",
    "(lambda _:max([_,_-1])==_)(5)",
    "(lambda _:pow(_,1)==_)(99)",
    "(lambda _:divmod(_,1)[1]==0)(10)",
    "(lambda _:round(_,0)==_)(3.14)",
    "(lambda _:hash(_)==hash(int(_)))(1)",
    "(lambda _:id(type(_))==id(type(0)))(0)",
    "(lambda _:repr(_)==repr(int(_)))(7)",
    "(lambda _:format(_,'d').isdigit())(42)",
    "(lambda _:eval(str(_))==_)(9)",
    "(lambda _:type(_).__name__=='int')(0)",
    "(lambda _:[_ for _ in str(_)if _.isdigit()]==[str(_)])(8)",
    "(lambda _:len(str(abs(_)))>0)(-5)",
    "(lambda _:_<<0==_>>0)(128)",
    "(lambda _:_|_==_)(63)",
    "(lambda _:_^_==0 and _&_==_)(31)",
    "(lambda _:~_==-_)(256)",
    "(lambda _:bool(_%2==0 or _%2==1))(42)",
    "(lambda _:globals()is not None)(0)",
    "(lambda _:locals()is not None)(0)",
    "(lambda _:vars()is not None)(0)",
    "(lambda _:chr(ord(str(_)[0]))==str(_))(9)",
    "(lambda _:bytes([_])==bytes([_]))(0)",
    "(lambda _:list(_*[1])==[_]*_)(1)",
    "(lambda _:tuple([_])==(_,))(42)",
    "(lambda _:dict([(_,_)])=={_:_})(7)",
    "(lambda _:set([_])=={_})(3)",
    "(lambda _:bytearray([_])[0]==_)(5)",
};

static const char *opaque_false_pool[] = {
    "(lambda _:_!=_ or isinstance({},type(None)))(float('nan'))",
    "(lambda _:[x for x in[_]if False]==[None for x in[_]if True])(0)",
    "(lambda _:hash(str(_))!=hash(str(_)))(0)",
    "(lambda _:_+1==_ and _-1==_)(0)",
    "(lambda _:bool(_)!=bool(_)or type(_)!=type(_))(True)",
    "(lambda _:str(_)!=str(_)and len(str(_))<0)(42)",
    "(lambda _:_*0!=0 and _*1!=_)(99)",
    "(lambda _:chr(_).isalpha())(0)",
    "(lambda _:isinstance(_,int)!=isinstance(_,int))(7)",
    "(lambda _:type(_)==type(None))(0)",
    "(lambda _:_!=_ or _ is not _)(None)",
    "(lambda _:_ in[]or _ not in[_])(1)",
    "(lambda _:sorted([_])!=sorted([_]))(3)",
    "(lambda _:list({_: _}).count(_)>1)(5)",
    "(lambda _:id(_)!=id(int(_)))(2)",
    "(lambda _:abs(_)!=abs(_))(9)",
    "(lambda _:hex(_)!=hex(int(_)))(10)",
    "(lambda _:repr(_)!=repr(str(_)))(8)",
    "(lambda _:format(_)!=format(int(_)))(4)",
    "(lambda _:eval(str(_))!=_)(11)",
    "(lambda _:len(dir(_))!=len(dir({})))([]+[])",
    "(lambda _:[_ for _ in str(_)if False]==[])(42)",
    "(lambda _:_<<1==0)(0)",
    "(lambda _:_^_!=0)(63)",
    "(lambda _:~_==0)(1)",
    "(lambda _:pow(_,0)!=1)(99)",
    "(lambda _:divmod(_,2)[0]!=_//2)(10)",
    "(lambda _:bytes([_])!=bytes([_]))(0)",
    "(lambda _:bytearray([_])!=bytearray([_]))(5)",
    "(lambda _:dict([(_,_+1)])=={_:_})(7)",
};

/* ── Dynamic polynomial-based opaque predicate generator ── */
/* Generates complex-looking but constant-true predicates using polynomial math.
 * Uses bitwise operations and integer arithmetic that evaluate to constants. */
static std::string gen_poly_opaque_true(void) {
    unsigned char r[16];
    RAND_bytes(r, sizeof(r));

    int style = r[0] % 6;
    int a = (int)r[1] % 256;
    int b = (int)r[2] % 256;
    int c = (int)r[3] % 256;
    int d = (int)r[4] % 256;

    switch (style) {
        case 0:
            return std::format(
                "(lambda _:[_ for _ in range(256) if (_*_ + {}) & (_ | 1) != (_^2 + _ + 1) & 1] == [])(0)",
                a, a);
        case 1:
            return std::format(
                "(lambda _:(((_<<{})|(_>>{}))^((_+{})<<{})^(_|{}))==((_>>{})|((_+{})&{})))(42)",
                a % 4 + 1, 8 - (a % 4), b % 8 + 1, b % 8 + 1, a % 4 + 1,
                b % 8 + 1, b % 8 + 1, 8 - (a % 4), a % 4 + 1, 7);
        case 2:
            return std::format(
                "(lambda _:[_ for _ in range({}) if (_^(_+{})^(_+{}))!=((_*3)+{})] == [])(0)",
                c % 20 + 10, c % 20 + 10, c % 20 + 10, c % 20 + 10);
        case 3:
            return std::format(
                "(lambda _:((({}*_)|{})|{})=={})(0)",
                0x9e3779b1 % 200 + 50, a % 16, b % 8, a + b);
        case 4:
            return std::format(
                "(lambda _:(_{0}_{1}_{2}_{3}_{4}{5})==_)(0)",
                a % 10, (a+1) % 10, (a+2) % 10, (a+3) % 10, (a+4) % 10, a % 10);
        case 5:
        default:
            return std::format(
                "(lambda _:((_{0})|{1})=={0})(1)",
                a % 10 + 5, b % 16);
    }
}

static std::string gen_poly_opaque_false(void) {
    unsigned char r[16];
    RAND_bytes(r, sizeof(r));

    int style = r[0] % 4;

    switch (style) {
        case 0:
            return "(lambda _:[x for x in range(256) if x < x] != [])(0)";
        case 1:
            return "(lambda _:True == False)(0)";
        case 2:
            return "(lambda _:(1,)[0] < (0,)[0])(0)";
        case 3:
        default:
            return "(lambda _:[x for x in range(100) if x+x < x] != [])(0)";
    }
}

/* ── Generate opaque predicates (enhanced with dynamic generation) ── */
char *flowflatten_opaque_predicate(void) {
    unsigned char idx_buf;
    RAND_bytes(&idx_buf, 1);
    int pool_size = sizeof(opaque_true_pool) / sizeof(opaque_true_pool[0]);
    int idx = idx_buf % pool_size;
    if (idx_buf % 3 == 0) {
        std::string dyn = gen_poly_opaque_true();
        return strdup(dyn.c_str());
    }
    return strdup(opaque_true_pool[idx]);
}

char *flowflatten_opaque_false_predicate(void) {
    unsigned char idx_buf;
    RAND_bytes(&idx_buf, 1);
    int pool_size = sizeof(opaque_false_pool) / sizeof(opaque_false_pool[0]);
    int idx = idx_buf % pool_size;
    if (idx_buf % 3 == 0) {
        std::string dyn = gen_poly_opaque_false();
        return strdup(dyn.c_str());
    }
    return strdup(opaque_false_pool[idx]);
}

/* ── Generate a random name with variable length ── */
static std::string rand_var_name(void) {
    unsigned char len_buf;
    RAND_bytes(&len_buf, 1);
    int len = 6 + (len_buf % 10);
    std::string r;
    r += '_';
    for (int i = 1; i < len; i++) {
        unsigned char c;
        RAND_bytes(&c, 1);
        int aset = c % 3;
        if (aset == 0) r += 'a' + (c % 26);
        else if (aset == 1) r += 'A' + (c % 26);
        else r += '0' + (c % 10);
        if (i == 1 && aset == 2) r.back() = 'a' + (c % 26);
    }
    return r;
}

/* ── Generate obfuscated comparison expression ── */
static std::string gen_obfuscated_cmp(const std::string &a, const std::string &b) {
    unsigned char style;
    RAND_bytes(&style, 1);
    int s = style % 6;
    switch (s) {
        case 0: return a + " == " + b;
        case 1: return a + " == " + b + " and " + a + " == " + b;
        case 2: return "not (" + a + " != " + b + ")";
        case 3: return "(" + a + " == " + b + ") or not (" + a + " != " + b + ")";
        case 4: return "str(" + a + ") == str(" + b + ")";
        case 5: return "hash(str(" + a + ")) == hash(str(" + b + "))";
        default: return a + " == " + b;
    }
}

/* ── Generate Python flattened state machine ── */
char *flowflatten_generate_python(const FlowFlattenPlan *plan,
                                  const unsigned char *hmac_key,
                                  size_t hmac_key_len) {
    if (!plan || plan->num_blocks < 2) return nullptr;

    std::string py;
    py.reserve(16384);

    char key_hex[65];
    for (size_t i = 0; i < hmac_key_len && i < 32; i++)
        snprintf(key_hex + i * 2, 3, "%02x", hmac_key[i]);
    key_hex[64] = '\0';

    unsigned char rnd[8];
    RAND_bytes(rnd, sizeof(rnd));
    uint64_t rseed = 0;
    for (int i = 0; i < 8; i++) rseed = (rseed << 8) | rnd[i];

    char svar[32], hfunc[32], vfunc[32], smap[32];
    snprintf(svar, sizeof(svar), "_S%lx", rseed & 0xFFFFFFF);
    snprintf(hfunc, sizeof(hfunc), "_H%lx", (rseed >> 28) & 0xFFFFFFF);
    snprintf(vfunc, sizeof(vfunc), "_V%lx", ((rseed >> 40) & 0xFFFFFFF));
    snprintf(smap, sizeof(smap), "_M%lx", ((rseed >> 52) & 0xFFFFFFF));

    std::string sv(svar), hf(hfunc), vf(vfunc), sm(smap);

    py += "import hashlib as _" + rand_var_name() + ", hmac as _" + rand_var_name() + "\n\n";

    py += hf + " = lambda _s: __import__('hashlib').sha256(\n";
    py += "    bytes.fromhex('" + std::string(key_hex) + "') +\n";
    py += "    str(_s).encode()\n";
    py += ").hexdigest()[:16]\n\n";

    py += vf + " = lambda _e,_r: " +
          gen_obfuscated_cmp("_e", hf + "(_r)") + "\n\n";

    py += sm + " = {\n";
    for (int i = 0; i < plan->num_blocks; i++) {
        py += "    '" + std::string(plan->blocks[i].state_encoded) + "': " +
              std::to_string(plan->blocks[i].state_id) + ",\n";
    }
    py += "}\n\n";

    py += "def _" + rand_var_name() + "():\n";
    py += "    " + sv + " = " + hf + "(0)\n";
    py += "    _" + rand_var_name() + " = None\n";
    py += "    while True:\n";

    for (int i = 0; i < plan->num_blocks; i++) {
        const char *kw = (i == 0) ? "if" : "elif";
        char *opaque = flowflatten_opaque_predicate();
        std::string cmp = gen_obfuscated_cmp(sv, hf + "(" + std::to_string(i) + ")");
        py += "        " + std::string(kw) + " " + cmp + " and (" +
              std::string(opaque) + "):\n";
        free(opaque);

        if (plan->blocks[i].block_code) {
            char *line = plan->blocks[i].block_code;
            while (*line) {
                char *nl = strchr(line, '\n');
                int linelen = nl ? (int)(nl - line) : (int)strlen(line);
                if (linelen > 0) {
                    py += "            ";
                    py.append(line, linelen);
                    py += "\n";
                }
                if (!nl) break;
                line = nl + 1;
            }
        }

        if (plan->blocks[i].next_state >= 0 && i != plan->blocks[i].next_state) {
            py += "            " + sv + " = " +
                  hf + "(" + std::to_string(plan->blocks[i].next_state) + ")\n";
        } else {
            py += "            return _" + rand_var_name() + "\n";
        }
    }

    py += "        else:\n";
    unsigned char branch_style;
    RAND_bytes(&branch_style, 1);
    if (branch_style % 2 == 0) {
        char *opaque_f = flowflatten_opaque_false_predicate();
        py += "            if " + std::string(opaque_f) + ":\n";
        free(opaque_f);
        py += "                pass\n";
    } else {
        py += "            pass\n";
    }
    py += "            break\n";
    py += "\n    return None\n\n";

    return strdup(py.c_str());
}