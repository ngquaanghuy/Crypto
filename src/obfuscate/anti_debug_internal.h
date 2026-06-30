#ifndef CRYPTO_ANTI_DEBUG_INTERNAL_H
#define CRYPTO_ANTI_DEBUG_INTERNAL_H

#include <cstddef>
#include <cstdint>
#include <cerrno>

#include <signal.h>
#include <setjmp.h>

#if defined(_WIN32) || defined(_WIN64)
    #define PLATFORM_WINDOWS 1
    #include <windows.h>
    #include <winternl.h>
#elif defined(__APPLE__) && defined(__MACH__)
    #define PLATFORM_MACOS 1
    #include <sys/types.h>
    #include <sys/sysctl.h>
    #include <sys/ptrace.h>
    #include <mach/mach.h>
    #include <mach/mach_vm.h>
    #include <mach-o/dyld.h>
    #include <dlfcn.h>
#elif defined(__linux__)
    #define PLATFORM_LINUX 1
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <fcntl.h>
    #include <unistd.h>
    #include <sys/ptrace.h>
    #include <sys/wait.h>
    #include <sys/prctl.h>
    #include <cerrno>
    #include <dlfcn.h>
#endif

namespace antidebug {

extern sigjmp_buf g_safe_read_jump;
extern volatile sig_atomic_t g_safe_read_jump_set;

ssize_t safe_pread(int fd, void *buf, size_t count, off_t offset);
int is_valid_user_address(unsigned long addr);

#if defined(PLATFORM_LINUX)
int read_proc_self_line(const char *file, char *buf, size_t bufsz);
#endif

int check_sandbox();
int check_hooks();

#if defined(PLATFORM_WINDOWS)
int check_remote_debugger();
int check_debug_port();
int check_debug_flags();
int check_debug_object();
int check_output_debug_string();
#elif defined(PLATFORM_MACOS)
int check_ptrace_deny_attach();
int check_mach_task();
int check_loaded_modules();
#endif

}

#endif
