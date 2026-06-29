#ifndef CRYPTO_OBFUSCATE_FLOW_FLATTEN_OPAQUE_H
#define CRYPTO_OBFUSCATE_FLOW_FLATTEN_OPAQUE_H

#include "crypto/obfuscate.h"
#include <string>

/* Internal: flow flatten plan management, opaque predicate pools/generators, helpers.
 * Split from flow_flatten.cpp for modularity.
 * Public API remains in obfuscate.h (umbrella). */

/* Plan lifecycle + helpers */
void  flowflatten_plan_init(FlowFlattenPlan *plan, int num_blocks);
int   flowflatten_set_block(FlowFlattenPlan *plan, int index,
                            const char *block_code, int next_block);
void  flowflatten_plan_free(FlowFlattenPlan *plan);

/* Opaque predicates */
char *flowflatten_opaque_predicate(void);
char *flowflatten_opaque_false_predicate(void);

/* Shared helpers (used by flow_flatten.cpp and flow_flatten_adv.cpp) */
std::string flowflatten_rand_var_name(void);
std::string flowflatten_gen_obfuscated_cmp(const std::string &a, const std::string &b);

#endif /* CRYPTO_OBFUSCATE_FLOW_FLATTEN_OPAQUE_H */
