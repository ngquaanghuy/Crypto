#ifndef CRYPTO_OBFUSCATE_H
#define CRYPTO_OBFUSCATE_H

#include "crypto/common.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Anti-Debugging & Secure Execution (Phương án A + D) ───────────────── */

typedef enum {
    ADBG_RESULT_CLEAN = 0,
    ADBG_RESULT_DEBUGGER_DETECTED,
    ADBG_RESULT_VM_DETECTED,
    ADBG_RESULT_HOOK_DETECTED,
    ADBG_RESULT_SANDBOX_DETECTED,
    ADBG_RESULT_ERROR,
} AntiDebugResult;

/* Run all anti-debugging checks; returns ADBG_RESULT_CLEAN if safe. */
AntiDebugResult anti_debug_check_all(void);

/* Sanitize environment: strip PYTHONPATH, LD_PRELOAD, etc. Returns new env. */
char **anti_debug_sanitize_environment(void);

/* Check if debugger/tracer is attached (Linux: /proc/self/status TracerPid,
 * Windows: IsDebuggerPresent/CheckRemoteDebuggerPresent,
 * MacOS: sysctl KERN_PROC/P_TRACED). */
int anti_debug_check_tracerpid(void);

/* Attempt PTRACE_TRACEME (Linux) or equivalent on other platforms;
 * returns 0 if not traced. */
int anti_debug_check_ptrace(void);

/* Scan /proc/self/maps for suspicious libraries (debuggers, injectors). */
int anti_debug_check_maps(void);

/* Check CPUID for hypervisor bit (VM detection). */
int anti_debug_check_cpuid(void);

/* Generate Python anti-debugging code stub. Returns malloc'd string. */
char *anti_debug_generate_stub(int include_vm_check, int include_hook_check);


/* ── Context-Aware Rename (Phương án A + B + D) ────────────────────────── */

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

/* Initialize a rename table for an obfuscation session. */
void rename_table_init(RenameTable *tbl, size_t initial_cap);

/* Free all memory in a rename table. */
void rename_table_free(RenameTable *tbl);

/* Compute HMAC-SHA256 context-aware mangled name.
 * Returns malloc'd string like "_a1b2c3d4e5f6". */
char *rename_mangle_name(const char *original, int scope_depth,
                         const char *parent_scope, const unsigned char *key,
                         size_t key_len);

/* Register a name in the rename table (deduplicates by original+scope). */
const char *rename_register(RenameTable *tbl, const char *original,
                            int scope_depth, const char *parent_scope,
                            const unsigned char *key, size_t key_len);

/* Generate decoy symbol names and add them to the table.
 * count: number of decoys to generate. Returns number generated. */
int rename_generate_decoys(RenameTable *tbl, int count,
                           const unsigned char *key, size_t key_len);

/* Shuffle the rename table assignment order (randomized mapping). */
void rename_shuffle_table(RenameTable *tbl);

/* Generate a Python source string that performs the renaming.
 * Returns malloc'd Python source code. */
char *rename_generate_python(const char *input_source,
                             const RenameTable *tbl);


/* ── HMAC-Based Flow Flattening (Phương án A + C + D) ──────────────────── */

typedef struct {
    int    state_id;          /* Logical state number */
    char   state_encoded[64]; /* HMAC-hex encoded state value */
    char  *block_code;        /* Python code for this state block */
    int    next_state;        /* Next logical state (-1 = terminal) */
} FlowBlock;

typedef struct {
    FlowBlock *blocks;
    int        num_blocks;
    int        initial_state;
    unsigned char key[32];
} FlowFlattenPlan;

/* Initialize a flow flattening plan with n blocks. */
void flowflatten_plan_init(FlowFlattenPlan *plan, int num_blocks);

/* Free a flow flatten plan. */
void flowflatten_plan_free(FlowFlattenPlan *plan);

/* Set block code and compute its HMAC-encoded state. */
int flowflatten_set_block(FlowFlattenPlan *plan, int idx,
                          const char *block_code, int next_state);

/* Generate opaque true predicate (always-true, data-dependent). Returns malloc'd string. */
char *flowflatten_opaque_predicate(void);

/* Generate opaque false predicate (always-false, data-dependent). Returns malloc'd string. */
char *flowflatten_opaque_false_predicate(void);

/* Generate Python source implementing the flattened state machine.
 * Returns malloc'd string. */
char *flowflatten_generate_python(const FlowFlattenPlan *plan,
                                  const unsigned char *hmac_key,
                                  size_t hmac_key_len);


/* ── Context-Aware Junk Code (Phương án A + B + E) ─────────────────────── */

typedef struct {
    char **variable_names; /* Names of real variables to reference */
    int    num_variables;
    int    include_side_effects; /* Generate syscalls/list ops */
    int    include_both_branches; /* Distribute across if/else */
} JunkConfig;

/* Default junk configuration. */
void junk_config_default(JunkConfig *cfg);

/* Generate a single junk statement referencing given variables.
 * Returns malloc'd Python source line. */
char *junk_generate_statement(const JunkConfig *cfg);

/* Generate a junk if/else block with dead code in both branches.
 * Returns malloc'd Python source. */
char *junk_generate_ifelse_block(const JunkConfig *cfg);

/* Generate a junk function definition (unused but looks real).
 * Returns malloc'd Python source. */
char *junk_generate_function(const JunkConfig *cfg);

/* Generate a full junk code section with count statements.
 * Returns malloc'd Python source. */
char *junk_generate_section(const JunkConfig *cfg, int count);


/* ── Secure XOR Key Generation + ChaCha20 (Phương án A + B + C + E) ────── */

#define OBFUSCATE_SALT_SIZE     16
#define OBFUSCATE_CHACHA20_KEY_SIZE 32
#define OBFUSCATE_CHACHA20_IV_SIZE  12
#define OBFUSCATE_HMAC_KEY_SIZE     32
#define OBFUSCATE_HMAC_SIZE         32
#define OBFUSCATE_DERIVED_SIZE      (OBFUSCATE_CHACHA20_KEY_SIZE + \
                                     OBFUSCATE_CHACHA20_IV_SIZE + \
                                     OBFUSCATE_HMAC_KEY_SIZE)
#define OBFUSCATE_NONCE_SIZE        12
#define OBFUSCATE_TAG_SIZE          16

/* Derive encryption and HMAC keys from a master key using HKDF/HMAC. */
ExitCode xorgen_derive_keys(const unsigned char *master_key, size_t master_len,
                            const unsigned char *salt, size_t salt_len,
                            unsigned char *out_enc_key, size_t enc_key_len,
                            unsigned char *out_hmac_key, size_t hmac_key_len);

/* Encrypt plaintext with ChaCha20 + HMAC integrity tag.
 * Output format: [salt(16)][nonce(12)][ciphertext][tag(16)] */
ExitCode xorgen_chacha20_encrypt(const unsigned char *plain, size_t plain_len,
                                 const unsigned char *key, size_t key_len,
                                 unsigned char **out, size_t *out_len);

/* Decrypt and verify integrity tag. */
ExitCode xorgen_chacha20_decrypt(const unsigned char *in, size_t in_len,
                                 const unsigned char *key, size_t key_len,
                                 unsigned char **out, size_t *out_len);

/* Generate a Python self-decrypting stub using ChaCha20 + HMAC.
 * Returns malloc'd Python source code. */
char *xorgen_generate_python_stub(const unsigned char *plaintext,
                                  size_t plaintext_len,
                                  const unsigned char *key, size_t key_len);

/* Generate a Python multi-layer XOR stub (fallback, no crypto lib needed).
 * Returns malloc'd Python source code. */
char *xorgen_generate_xor_stub(const unsigned char *plaintext,
                               size_t plaintext_len,
                               const unsigned char *key, size_t key_len);


/* ── Obfuscation Pipeline Orchestrator ──────────────────────────────────── */

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
    const char *input_source;
    const unsigned char *master_key;
    size_t master_key_len;
    int seed;  /* -1 for random */
} ObfuscateConfig;

/* Default obfuscation configuration. */
void obfuscate_config_default(ObfuscateConfig *cfg);

/* Run the full obfuscation pipeline. Returns malloc'd obfuscated source. */
char *obfuscate_pipeline(const ObfuscateConfig *cfg);

/* Run a single technique by name. Returns malloc'd obfuscated source. */
char *obfuscate_apply_technique(const char *technique,
                                const char *source,
                                const unsigned char *key,
                                size_t key_len);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_OBFUSCATE_H */