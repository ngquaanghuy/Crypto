#include "crypto/obfuscate.h"
#include "obfuscate/flow_flatten_opaque.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

/* ── Generate a random name with variable length ── */
std::string flowflatten_rand_var_name(void) {
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
std::string flowflatten_gen_obfuscated_cmp(const std::string &a, const std::string &b) {
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
static std::string gen_poly_opaque_true(void) {
    unsigned char r[16];
    RAND_bytes(r, sizeof(r));

    int style = r[0] % 5;

    switch (style) {
        case 0:
            return "(lambda _:[x for x in range(256) if x != x] == [])(0)";
        case 1:
            return "(lambda _:_ is _)(0)";
        case 2:
            return "(lambda _:_ == _)(0)";
        case 3:
            return "(lambda _:[].count(_) == 0)(0)";
        case 4:
        default:
            return "(lambda _:None is None)(0)";
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
    std::string dyn = gen_poly_opaque_true();
    return strdup(dyn.c_str());
}

char *flowflatten_opaque_false_predicate(void) {
    std::string dyn = gen_poly_opaque_false();
    return strdup(dyn.c_str());
}
