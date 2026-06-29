#ifndef CRYPTO_OBFUSCATE_ANTIDEBUG_H
#define CRYPTO_OBFUSCATE_ANTIDEBUG_H

#include "crypto/common.h"

typedef enum {
    ADBG_RESULT_CLEAN              = 0,
    ADBG_RESULT_DEBUGGER_DETECTED  = 1,
    ADBG_RESULT_VM_DETECTED        = 2,
    ADBG_RESULT_SANDBOX_DETECTED   = 3,
    ADBG_RESULT_HOOK_DETECTED      = 4,
} AntiDebugResult;

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

#endif /* CRYPTO_OBFUSCATE_ANTIDEBUG_H */
