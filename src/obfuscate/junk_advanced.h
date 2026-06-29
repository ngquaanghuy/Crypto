#ifndef CRYPTO_OBFUSCATE_JUNK_ADVANCED_H
#define CRYPTO_OBFUSCATE_JUNK_ADVANCED_H

#include "crypto/obfuscate.h"
#include <string>

/* Internal: advanced junk generators (MBA, opaque jump, codec).
 * Split from junk.cpp for modularity.
 * Public API remains in obfuscate.h (umbrella). */

std::string junk_gen_mba(void);
std::string junk_gen_opaque_jump(void);
std::string junk_gen_codec(void);

#endif /* CRYPTO_OBFUSCATE_JUNK_ADVANCED_H */
