#ifndef CRYPTO_OBFUSCATE_FLOW_H
#define CRYPTO_OBFUSCATE_FLOW_H

#include "crypto/common.h"
#include <stddef.h>

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
    int            dispatcher_type;
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

#endif /* CRYPTO_OBFUSCATE_FLOW_H */
