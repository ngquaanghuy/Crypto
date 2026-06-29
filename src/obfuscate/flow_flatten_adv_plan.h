#ifndef CRYPTO_OBFUSCATE_FLOW_FLATTEN_ADV_PLAN_H
#define CRYPTO_OBFUSCATE_FLOW_FLATTEN_ADV_PLAN_H

#include "crypto/obfuscate.h"
#include <string>

/* Internal: advanced flow flatten plan management + dispatcher generators.
 * Split from flow_flatten_adv.cpp for modularity.
 * Public API remains in obfuscate.h (umbrella). */

/* Plan lifecycle */
void  adv_flowflatten_plan_init(AdvFlowFlattenPlan *plan, int num_real_blocks);
int   adv_flowflatten_set_block(AdvFlowFlattenPlan *plan, int logical_idx,
                                const char *block_code, int next_logical_state);
int   adv_flowflatten_add_dead_block(AdvFlowFlattenPlan *plan,
                                     const char *block_code);
void  adv_flowflatten_plan_free(AdvFlowFlattenPlan *plan);

/* Dispatcher code generators (produce Python code indented at +4) */
std::string adv_flowflatten_gen_dict_dispatcher(const AdvFlowFlattenPlan *plan,
                                                 const std::string &sv,
                                                 const std::string &dp);
std::string adv_flowflatten_gen_list_dispatcher(const AdvFlowFlattenPlan *plan,
                                                 const std::string &sv,
                                                 const std::string &dp);
std::string adv_flowflatten_gen_arith_dispatcher(const AdvFlowFlattenPlan *plan,
                                                   const std::string &sv,
                                                   const std::string &dp);

/* Block code formatting helper */
void adv_flowflatten_append_block_code(std::string &out, const char *code,
                                        const std::string &indent);

#endif /* CRYPTO_OBFUSCATE_FLOW_FLATTEN_ADV_PLAN_H */
