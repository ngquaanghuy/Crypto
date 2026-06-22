#ifndef CRYPTO_OBFUSCATE_H
#define CRYPTO_OBFUSCATE_H

#include "crypto/common.h"
#include <stddef.h>

/* ─── Obfuscation configuration ──────────────────────────── */
typedef struct {
    int use_rename;
    int use_flowflatten;
    int use_junk;
    int use_xorgenc;
    int use_antidebug;
    int use_decoys;
    int shuffle_order;
    int num_junk_statements;
    int num_decoys;
    int flowflatten_blocks;
    float density;
    const char *input_source;
    const unsigned char *master_key;
    size_t master_key_len;
    int seed;
} ObfuscateConfig;

void obfuscate_config_default(ObfuscateConfig *cfg);

char *obfuscate_apply_technique(const char *technique,
                                const char *source,
                                const unsigned char *key,
                                size_t key_len,
                                int count = 10,
                                int decoy_count = 8,
                                int block_count = 4);

char *obfuscate_pipeline(const ObfuscateConfig *cfg);

/* ─── Anti-debug result enum ────────────────────────────── */
typedef enum {
    ADBG_RESULT_CLEAN              = 0,
    ADBG_RESULT_DEBUGGER_DETECTED  = 1,
    ADBG_RESULT_VM_DETECTED        = 2,
    ADBG_RESULT_SANDBOX_DETECTED   = 3,
    ADBG_RESULT_HOOK_DETECTED      = 4,
} AntiDebugResult;

/* ─── Anti-debug ─────────────────────────────────────────── */
int    anti_debug_check_ptrace(void);
int    anti_debug_check_tracerpid(void);
int    anti_debug_check_maps(void);
int    anti_debug_check_cpuid(void);
int    anti_debug_check_timing(void);
int    anti_debug_check_parent(void);
int    anti_debug_check_debugregs(void);
int    anti_debug_check_procstat(void);
int    anti_debug_check_proc_cmdline(void);
int    anti_debug_check_seccomp(void);
int    anti_debug_check_prctl(void);
int    anti_debug_check_fork(void);
int    anti_debug_check_inline_hooks(void);
int    anti_debug_check_plt_hooks(void);
int    anti_debug_check_syscall_hooks(void);
int    anti_debug_check_memory_integrity(void);
AntiDebugResult anti_debug_check_all(void);
char  *anti_debug_generate_stub(int use_ptrace, int use_tracerpid);
char **anti_debug_sanitize_environment(void);

/* ─── Rename table ───────────────────────────────────────── */
typedef struct {
    char *original_name;
    char *mangled_name;
    int   scope_depth;
    char *parent_scope;
} RenameEntry;

typedef struct {
    RenameEntry *entries;
    size_t       count;
    size_t       capacity;
} RenameTable;

void        rename_table_init(RenameTable *tbl, size_t capacity);
const char *rename_register(RenameTable *tbl, const char *name,
                            int scope_id, const char *scope_name,
                            const unsigned char *key, size_t key_len);
int         rename_generate_decoys(RenameTable *tbl, int count,
                                   const unsigned char *key, size_t key_len);
void        rename_shuffle_table(RenameTable *tbl);
char       *rename_generate_python(const char *source,
                                   const RenameTable *tbl);
void        rename_table_free(RenameTable *tbl);
char       *rename_mangle_name(const char *name, int scope_id,
                               const char *scope_name,
                               const unsigned char *key, size_t key_len);

/* ─── Flow flatten ───────────────────────────────────────── */
typedef struct {
    char  *block_code;
    int    state_id;
    int    next_state;
    char   state_encoded[32];
} FlowBlock;

typedef struct {
    FlowBlock     *blocks;
    int            num_blocks;
    int            initial_state;
    unsigned char  key[32];
} FlowFlattenPlan;

void  flowflatten_plan_init(FlowFlattenPlan *plan, int num_blocks);
int   flowflatten_set_block(FlowFlattenPlan *plan, int index,
                            const char *block_code, int next_block);
void  flowflatten_plan_free(FlowFlattenPlan *plan);
char *flowflatten_generate_python(const FlowFlattenPlan *plan,
                                  const unsigned char *key, size_t key_len);
char *flowflatten_opaque_predicate(void);
char *flowflatten_opaque_false_predicate(void);

/* ─── Advanced CFG flattening with Dispatcher ────────────── */
typedef struct {
    char  *block_code;
    int    state_id;
    int    logical_next;
    int    encoded_state;
    int    dead_block;
} AdvFlowBlock;

typedef struct {
    AdvFlowBlock  *blocks;
    int            num_blocks;
    int            real_blocks;
    int            num_dead_blocks;
    int            dispatcher_type;   /* 0=dict, 1=list, 2=arithmetic */
    int            state_xor_key;
    int            state_mul_key;
    int            state_add_key;
    int            state_mod;
    int           *permutation;
    unsigned char  key[32];
} AdvFlowFlattenPlan;

void  adv_flowflatten_plan_init(AdvFlowFlattenPlan *plan, int num_real_blocks);
int   adv_flowflatten_set_block(AdvFlowFlattenPlan *plan, int logical_idx,
                                 const char *block_code, int next_logical_state);
int   adv_flowflatten_add_dead_block(AdvFlowFlattenPlan *plan,
                                      const char *block_code);
void  adv_flowflatten_plan_free(AdvFlowFlattenPlan *plan);
char *adv_flowflatten_generate_python(const AdvFlowFlattenPlan *plan);
char *adv_flowflatten_wrap_source(const char *source, int block_count,
                                    float density);

/* ─── Junk code ──────────────────────────────────────────── */
typedef struct {
    char **variable_names;
    int    num_variables;
    int    include_side_effects;
    int    include_both_branches;
} JunkConfig;

void  junk_config_default(JunkConfig *cfg);
char *junk_generate_statement(const JunkConfig *cfg);
char *junk_generate_ifelse_block(const JunkConfig *cfg);
char *junk_generate_function(const JunkConfig *cfg);
char *junk_generate_section(const JunkConfig *cfg, int count);

/* ─── XOR key generation / ChaCha20 stub ─────────────────── */
#define OBFUSCATE_SALT_SIZE         16
#define OBFUSCATE_NONCE_SIZE        12
#define OBFUSCATE_CHACHA20_KEY_SIZE 32
#define OBFUSCATE_HMAC_KEY_SIZE     32
#define OBFUSCATE_TAG_SIZE          32 /* HMAC-SHA256 produces 32 bytes */

ExitCode xorgen_derive_keys(const unsigned char *master, size_t master_len,
                            const unsigned char *salt, size_t salt_len,
                            unsigned char *enc_key, size_t enc_key_size,
                            unsigned char *hmac_key, size_t hmac_key_size);

ExitCode xorgen_chacha20_encrypt(const unsigned char *plaintext,
                                 size_t plaintext_len,
                                 const unsigned char *key, size_t key_len,
                                 unsigned char **out, size_t *out_len);

ExitCode xorgen_chacha20_decrypt(const unsigned char *ciphertext,
                                 size_t ciphertext_len,
                                 const unsigned char *key, size_t key_len,
                                 unsigned char **out, size_t *out_len);

char *xorgen_generate_python_stub(const unsigned char *source,
                                  size_t source_len,
                                  const unsigned char *key, size_t key_len);

char *xorgen_generate_xor_stub(const unsigned char *source,
                               size_t source_len,
                               const unsigned char *key, size_t key_len);

#endif /* CRYPTO_OBFUSCATE_H */
