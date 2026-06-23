#include "crypto/obfuscate.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cctype>
#include <string>
#include <vector>
#include <algorithm>

#include <signal.h>
#include <setjmp.h>
#include <errno.h>

/* ── Platform Detection ───────────────────────────────────────────────── */
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

/* ── Safe memory read with SIGSEGV protection ─────────────────────────── */
/* Race condition: between reading /proc/self/maps and pread(/proc/self/mem),
 * the mapped region could be unmapped by another thread, causing SIGSEGV.
 * This helper catches SIGSEGV and returns -1 on failure. */

/* Global state for signal handler (required because C signal handlers
 * can't use non-static class members or lambdas) */
static sigjmp_buf g_safe_read_jump;
static volatile sig_atomic_t g_safe_read_jump_set = 0;

static void safe_read_sigsegv_handler(int) {
    if (g_safe_read_jump_set) siglongjmp(g_safe_read_jump, 1);
}

static ssize_t safe_pread(int fd, void *buf, size_t count, off_t offset) {
    struct sigaction sa, old_sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = safe_read_sigsegv_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGSEGV, &sa, &old_sa);

    ssize_t result = -1;
    if (sigsetjmp(g_safe_read_jump, 1) == 0) {
        g_safe_read_jump_set = 1;
        result = pread(fd, buf, count, offset);
        g_safe_read_jump_set = 0;
    } else {
        /* SIGSEGV caught - memory region became unmapped */
        g_safe_read_jump_set = 0;
        errno = EFAULT;
        result = -1;
    }

    sigaction(SIGSEGV, &old_sa, nullptr);
    return result;
}

/* Validate address is in user-space range (prevent kernel reads) */
static int is_valid_user_address(unsigned long addr) {
    /* On x86_64: canonical form addresses are < 0x800000000000 */
    /* Allow NULL page exclusion */
    if (addr == 0 || addr == (unsigned long)-1) return 0;
#if defined(__x86_64__) || defined(_WIN64)
    if (addr >= 0x800000000000UL) return 0;  /* kernel space */
    if (addr < 0x10000) return 0;            /* NULL region */
#else
    if (addr == 0) return 0;
#endif
    return 1;
}


/* ── Helper: read first line from /proc/self/<file> ── */
#if defined(PLATFORM_LINUX)
static int read_proc_self_line(const char *file, char *buf, size_t bufsz) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/self/%s", file);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, bufsz - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';
    return 0;
}
#endif


/* ── Timing check via RDTSC (x86/x86_64) ── */
int anti_debug_check_timing(void) {
#if defined(__x86_64__) || defined(__i386__)
    uint64_t t1, t2;
    unsigned aux;
    /* Serializing RDTSC via CPUID */
    uint32_t eax, ebx, ecx, edx;
    eax = 0;
    __asm__ volatile(
        "cpuid\n\t"
        "rdtsc\n\t"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(eax)
    );
    t1 = ((uint64_t)edx << 32) | (uint64_t)eax;
    
    /* Small delay loop */
    volatile int delay = 0;
    for (int i = 0; i < 1000; i++) delay += i;
    
    eax = 0;
    __asm__ volatile(
        "cpuid\n\t"
        "rdtsc\n\t"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(eax)
    );
    t2 = ((uint64_t)edx << 32) | (uint64_t)eax;
    
    /* If single-stepping, RDTSC delta will be abnormally high */
    uint64_t delta = t2 - t1;
    if (delta > 1000000ULL) return 1;
    return 0;
#else
    (void)0;
    return 0;
#endif
}


/* ── Parent process check (Linux) ── */
int anti_debug_check_parent(void) {
#if defined(PLATFORM_LINUX)
    char buf[256];
    if (read_proc_self_line("status", buf, sizeof(buf)) < 0) return 0;
    char *p = buf;
    while (*p) {
        if (strncmp(p, "PPid:", 5) == 0) {
            p += 5;
            while (*p == ' ' || *p == '\t') p++;
            pid_t ppid = (pid_t)atoi(p);
            char proc_path[64];
            snprintf(proc_path, sizeof(proc_path), "/proc/%d/comm", ppid);
            int fd = open(proc_path, O_RDONLY);
            if (fd < 0) return 0;
            char comm[64];
            ssize_t n = read(fd, comm, sizeof(comm) - 1);
            close(fd);
            if (n <= 0) return 0;
            comm[n] = '\0';
            /* Remove trailing newline */
            if (comm[n-1] == '\n') comm[n-1] = '\0';
            static const char *bad_parents[] = {
                "gdb", "lldb", "strace", "ltrace", "perf",
                "valgrind", "rr", "callgrind", "pinbin",
                nullptr
            };
            for (int i = 0; bad_parents[i]; i++) {
                if (strcmp(comm, bad_parents[i]) == 0) return 1;
            }
            /* Also check cmdline of parent for inspector tools */
            char cmd_path[64];
            snprintf(cmd_path, sizeof(cmd_path), "/proc/%d/cmdline", ppid);
            fd = open(cmd_path, O_RDONLY);
            if (fd < 0) return 0;
            char cmdline[512];
            n = read(fd, cmdline, sizeof(cmdline) - 1);
            close(fd);
            if (n <= 0) return 0;
            cmdline[n] = '\0';
            for (int i = 0; bad_parents[i]; i++) {
                if (strstr(cmdline, bad_parents[i])) return 1;
            }
            break;
        }
        while (*p && *p != '\n') p++;
        if (*p == '\n') p++;
    }
    return 0;
#else
    (void)0;
    return 0;
#endif
}


/* ── Hardware debug register check via /proc/self/status ── */
int anti_debug_check_debugregs(void) {
#if defined(PLATFORM_LINUX)
    char buf[4096];
    if (read_proc_self_line("status", buf, sizeof(buf)) < 0) return 0;
    if (strstr(buf, "TracerPid:\t0") == nullptr) return 0;
    /* Check for DR0-DR7 in status (kernel reports hardware breakpoints) */
    /* Modern kernels expose debug registers in /proc/self/status as DR0-DR7 */
    if (strstr(buf, "DR0:")) {
        char *dr0 = strstr(buf, "DR0:");
        if (dr0) {
            dr0 += 4;
            while (*dr0 == ' ' || *dr0 == '\t') dr0++;
            if (*dr0 != '0') return 1;
        }
    }
    return 0;
#else
    (void)0;
    return 0;
#endif
}


/* ── /proc/self/stat flag check ── */
/* Only flags trace stop ('t') which is specific to ptrace,
   not ordinary stop 'T' which can come from job control signals. */
int anti_debug_check_procstat(void) {
#if defined(PLATFORM_LINUX)
    char buf[1024];
    if (read_proc_self_line("stat", buf, sizeof(buf)) < 0) return 0;
    char *p = buf;
    /* Skip pid */
    while (*p && *p == ' ') p++;
    while (*p && *p != ' ') p++;
    while (*p && *p == ' ') p++;
    /* state is field 2 (0-indexed) — check for 't' (tracing stop) not 'T' (ordinary stop) */
    if (*p == 't') return 1; /* Tracing stop — specific to ptrace */
    return 0;
#else
    (void)0;
    return 0;
#endif
}


/* ── Check /proc/self/cmdline + /proc/self/environ for analysis tools ── */
int anti_debug_check_proc_cmdline(void) {
#if defined(PLATFORM_LINUX)
    static const char *suspicious[] = {
        "gdb", "lldb", "strace", "ltrace", "perf",
        "valgrind", "rr", "callgrind", "pinbin",
        "frida", "hyperpwn", "pwndbg", "peda", "gef",
        nullptr
    };
    /* Check cmdline */
    char buf[1024];
    if (read_proc_self_line("cmdline", buf, sizeof(buf)) == 0) {
        for (int i = 0; suspicious[i]; i++) {
            if (strstr(buf, suspicious[i])) return 1;
        }
    }
    /* Check environ for injection hooks */
    if (read_proc_self_line("environ", buf, sizeof(buf)) == 0) {
        if (strstr(buf, "LD_PRELOAD=")) return 1;
        if (strstr(buf, "LD_LIBRARY_PATH=")) return 1;
        if (strstr(buf, "LD_AUDIT=")) return 1;
        if (strstr(buf, "LD_DEBUG=")) return 1;
        if (strstr(buf, "DYLD_INSERT_LIBRARIES=")) return 1;
    }
    return 0;
#else
    (void)0;
    return 0;
#endif
}


/* ── Seccomp mode detection ── */
int anti_debug_check_seccomp(void) {
#if defined(PLATFORM_LINUX)
    char buf[4096];
    if (read_proc_self_line("status", buf, sizeof(buf)) < 0) return 0;
    char *p = strstr(buf, "Seccomp:");
    if (p) {
        p += 8;
        while (*p == ' ' || *p == '\t') p++;
        int mode = atoi(p);
        if (mode > 0) return 1; /* Seccomp enabled (mode 1 or 2) */
    }
    return 0;
#else
    (void)0;
    return 0;
#endif
}


/* ── prctl PTRACE protection check ── */
/* Uses readonly PR_GET_DUMPABLE to avoid side effects */
int anti_debug_check_prctl(void) {
#if defined(PLATFORM_LINUX)
    /* Readonly check: if PR_GET_DUMPABLE fails, process state may be restricted */
    if (prctl(PR_GET_DUMPABLE) == -1) return 1;
    /* Try PR_SET_DUMPABLE(0) — should succeed if not traced */
    if (prctl(PR_SET_DUMPABLE, 0) == -1) return 1;
    prctl(PR_SET_DUMPABLE, 1);
    return 0;
#else
    (void)0;
    return 0;
#endif
}


/* ── Simple fork bomb / process count check ── */
int anti_debug_check_fork(void) {
#if defined(PLATFORM_LINUX)
    pid_t child = fork();
    if (child == -1) return 0; /* Can't fork */
    if (child == 0) _exit(0);
    int wstatus;
    waitpid(child, &wstatus, 0);
    return 0;
#else
    (void)0;
    return 0;
#endif
}


/* ── Tracer/Debugger Detection ────────────────────────────────────────── */

#if defined(PLATFORM_WINDOWS)
/* ── Windows: IsDebuggerPresent API ── */
int anti_debug_check_tracerpid(void) {
    return IsDebuggerPresent() ? 1 : 0;
}

/* ── Windows: CheckRemoteDebuggerPresent ── */
static int anti_debug_check_remote_debugger(void) {
    BOOL debugger_present = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &debugger_present)) {
        return debugger_present ? 1 : 0;
    }
    return 0;
}

/* ── Windows: NtQueryInformationProcess (ProcessDebugPort) ── */
static int anti_debug_check_debug_port(void) {
    typedef NTSTATUS (NTAPI *NtQueryInformationProcess_t)(
        HANDLE ProcessHandle,
        ULONG ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
    );
    
    static NtQueryInformationProcess_t NtQueryInformationProcess = nullptr;
    if (!NtQueryInformationProcess) {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (hNtdll) {
            NtQueryInformationProcess = (NtQueryInformationProcess_t)
                GetProcAddress(hNtdll, "NtQueryInformationProcess");
        }
    }
    
    if (!NtQueryInformationProcess) return 0;
    
    SIZE_T debug_port = 0;
    NTSTATUS status = NtQueryInformationProcess(
        GetCurrentProcess(),
        7, /* ProcessDebugPort */
        &debug_port,
        sizeof(debug_port),
        nullptr
    );
    
    if (status == 0 && debug_port != 0) {
        return 1;
    }
    return 0;
}

/* ── Windows: NtQueryInformationProcess (ProcessDebugFlags) ── */
static int anti_debug_check_debug_flags(void) {
    typedef NTSTATUS (NTAPI *NtQueryInformationProcess_t)(
        HANDLE ProcessHandle,
        ULONG ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
    );
    
    static NtQueryInformationProcess_t NtQueryInformationProcess = nullptr;
    if (!NtQueryInformationProcess) {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (hNtdll) {
            NtQueryInformationProcess = (NtQueryInformationProcess_t)
                GetProcAddress(hNtdll, "NtQueryInformationProcess");
        }
    }
    
    if (!NtQueryInformationProcess) return 0;
    
    ULONG debug_flags = 0;
    NTSTATUS status = NtQueryInformationProcess(
        GetCurrentProcess(),
        31, /* ProcessDebugFlags */
        &debug_flags,
        sizeof(debug_flags),
        nullptr
    );
    
    if (status == 0 && debug_flags == 0) {
        return 1;
    }
    return 0;
}

/* ── Windows: ProcessDebugObjectHandle ── */
static int anti_debug_check_debug_object(void) {
    typedef NTSTATUS (NTAPI *NtQueryInformationProcess_t)(
        HANDLE ProcessHandle,
        ULONG ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
    );
    
    static NtQueryInformationProcess_t NtQueryInformationProcess = nullptr;
    if (!NtQueryInformationProcess) {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (hNtdll) {
            NtQueryInformationProcess = (NtQueryInformationProcess_t)
                GetProcAddress(hNtdll, "NtQueryInformationProcess");
        }
    }
    
    if (!NtQueryInformationProcess) return 0;
    
    HANDLE debug_object = nullptr;
    NTSTATUS status = NtQueryInformationProcess(
        GetCurrentProcess(),
        30, /* ProcessDebugObjectHandle */
        &debug_object,
        sizeof(debug_object),
        nullptr
    );
    
    if (status == 0 && debug_object != nullptr) {
        return 1;
    }
    return 0;
}

/* ── Windows: OutputDebugStringA error check ── */
static int anti_debug_check_output_debug_string(void) {
    SetLastError(0);
    OutputDebugStringA(" ");
    return (GetLastError() != 0) ? 1 : 0;
}

#elif defined(PLATFORM_MACOS)
/* ── MacOS: sysctl KERN_PROC check ── */
int anti_debug_check_tracerpid(void) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc info;
    size_t size = sizeof(info);
    
    if (sysctl(mib, 4, &info, &size, nullptr, 0) != 0) {
        return 0;
    }
    
    return (info.kp_proc.p_flag & P_TRACED) ? 1 : 0;
}

/* ── MacOS: ptrace PT_DENY_ATTACH check ── */
static int anti_debug_check_ptrace_deny_attach(void) {
    /* Try to attach to ourselves; if it fails, we might already be traced */
    return ptrace(PT_DENY_ATTACH, 0, 0, 0) == -1 ? 1 : 0;
}

/* ── MacOS: mach_task_self check ── */
static int anti_debug_check_mach_task(void) {
    task_t task = mach_task_self();
    task_basic_info_data_t info;
    mach_msg_type_number_t count = TASK_BASIC_INFO_COUNT;
    
    kern_return_t kr = task_info(task, TASK_BASIC_INFO, (task_info_t)&info, &count);
    if (kr != KERN_SUCCESS) {
        return 0;
    }
    
    /* If task is being debugged, certain operations may fail */
    return 0;
}

/* ── MacOS: Check loaded modules for debuggers ── */
static int anti_debug_check_loaded_modules(void) {
    static const char *suspicious[] = {
        "libpdb", "libinspect", "libtrace",
        "pydevd", "pdbpp", "ipdb",
        "frida", "lldb", "gdb",
        "strace", "ltrace",
        nullptr
    };
    
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        
        for (int k = 0; suspicious[k]; k++) {
            if (strstr(name, suspicious[k])) {
                return 1;
            }
        }
    }
    return 0;
}

#elif defined(PLATFORM_LINUX)
/* ── Linux /proc/self/status TracerPid check ── */
int anti_debug_check_tracerpid(void) {
    int fd = open("/proc/self/status", O_RDONLY);
    if (fd < 0) return 0;
    char buf[4096];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = '\0';

    const char *p = buf;
    while (*p) {
        if (strncmp(p, "TracerPid:", 10) == 0) {
            p += 10;
            while (*p && (*p == ' ' || *p == '\t')) p++;
            if (*p != '0') return 1;
            break;
        }
        while (*p && *p != '\n') p++;
        if (*p == '\n') p++;
    }
    return 0;
}

/* ── PTRACE_TRACEME test ── */
int anti_debug_check_ptrace(void) {
    /* PTRACE_TRACEME fails if we are already being traced.
     * This is the most reliable single-call test.
     * We fork to avoid side effects on the parent process. */
    pid_t child = fork();
    if (child == -1) return 0;
    if (child == 0) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1)
            _exit(1);  /* Being traced */
        _exit(0);      /* Not traced */
    }
    int wstatus;
    waitpid(child, &wstatus, 0);
    if (WIFEXITED(wstatus)) {
        return WEXITSTATUS(wstatus);
    }
    return 0;
}

/* ── /proc/self/maps inspection ── */
int anti_debug_check_maps(void) {
    static const char *suspicious[] = {
        "libpdb", "libinspect", "libtrace",
        "pydevd", "pdbpp", "ipdb",
        "frida", "lldb", "gdb",
        "strace", "ltrace",
        nullptr
    };
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        for (int i = 0; suspicious[i]; i++) {
            if (strstr(line, suspicious[i])) {
                fclose(fp);
                return 1;
            }
        }
    }
    fclose(fp);
    return 0;
}

/* ── CPUID hypervisor check (x86/x86_64) ── */
int anti_debug_check_cpuid(void) {
#if defined(__x86_64__) || defined(__i386__)
    uint32_t eax, ebx, ecx, edx;
    eax = 1;
    __asm__ volatile(
        "cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(eax)
    );
    /* Bit 31 of ECX = hypervisor present */
    return (ecx >> 31) & 1;
#else
    (void)0;
    return 0;
#endif
}

#else
/* ── Fallback for unsupported platforms ── */
int anti_debug_check_tracerpid(void) {
    return 0;
}

int anti_debug_check_ptrace(void) {
    return 0;
}

int anti_debug_check_maps(void) {
    return 0;
}

int anti_debug_check_cpuid(void) {
    return 0;
}
#endif

/* ── Sandbox / container checks ── */
static int check_sandbox(void) {
#if defined(PLATFORM_WINDOWS)
    /* Check for Wine */
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll) {
        FARPROC wine_get_version = GetProcAddress(hNtdll, "wine_get_version");
        if (wine_get_version) return 1;
    }
    
    /* Check for VirtualBox/VMware drivers */
    HANDLE hDevice;
    hDevice = CreateFileA("\\\\.\\VBoxMiniPort", GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(hDevice);
        return 1;
    }
    
    hDevice = CreateFileA("\\\\.\\vmci", GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(hDevice);
        return 1;
    }
    
    /* Check for sandbox/analysis tools */
    if (GetTickCount() < 300000) {
        /* System running for less than 5 minutes - possible automated analysis */
        return 1;
    }
    
    return 0;
    
#elif defined(PLATFORM_MACOS)
    /* Check for sandbox-exec profile */
    FILE *fp = popen("sandbox-exec -p 'version 1; deny all' true 2>&1", "r");
    if (fp) {
        char buf[256];
        if (fgets(buf, sizeof(buf), fp)) {
            if (strstr(buf, "sandbox") || strstr(buf, "deny")) {
                pclose(fp);
                return 1;
            }
        }
        pclose(fp);
    }
    
    /* Check for app container */
    const char *container_home = getenv("APP_CONTAINER_HOME");
    if (container_home) return 1;
    
    /* Check for VM indicators */
    struct stat st;
    if (stat("/Applications/VirtualBox.app", &st) == 0) return 1;
    if (stat("/Applications/VMware Fusion.app", &st) == 0) return 1;
    
    return 0;
    
#elif defined(PLATFORM_LINUX)
    /* Check for Docker/Podman */
    struct stat st;
    if (stat("/.dockerenv", &st) == 0) return 1;
    /* Check cgroup */
    FILE *fp = fopen("/proc/1/cgroup", "r");
    if (fp) {
        char line[1024];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "docker") || strstr(line, "kubepods")) {
                fclose(fp);
                return 1;
            }
        }
        fclose(fp);
    }
    return 0;
#else
    return 0;
#endif
}

/* ── Hook detection: check platform-specific injection env vars ── */
/* Note: LD_PRELOAD/LD_LIBRARY_PATH/LD_AUDIT/LD_DEBUG are checked
   in anti_debug_check_proc_cmdline() via /proc/self/environ.
   This function focuses on platform-specific vars not covered there. */
static int check_hooks_env(void) {
    static const char *hooked_envs[] = {
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "DYLD_FORCE_FLAT_NAMESPACE",
        nullptr
    };
    for (int i = 0; hooked_envs[i]; i++) {
        const char *v = getenv(hooked_envs[i]);
        if (v && v[0]) return 1;
    }
    return 0;
}

/* ── Check /proc/self/maps for hooking/interposition libraries ── */
static int check_maps_for_hooks(void) {
#if defined(PLATFORM_LINUX)
    static const char *hook_indicators[] = {
        "libdetect", "hook", "intercept",
        "LD_PRELOAD", "/tmp/", "/dev/shm/",
        nullptr
    };
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        for (int i = 0; hook_indicators[i]; i++) {
            if (strstr(line, hook_indicators[i])) {
                /* Skip known-safe entries */
                if (strstr(line, "[heap]") || strstr(line, "[stack]")) continue;
                fclose(fp);
                return 1;
            }
        }
        /* Check for writable+executable (WX) memory regions - potential JIT hooking */
        if (strstr(line, "rwx")) {
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);
    return 0;
#else
    (void)0;
    return 0;
#endif
}

/* ── Hook detection: verify builtins are not intercepted ── */
static int check_hooks(void) {
    if (check_hooks_env()) return 1;
    if (check_maps_for_hooks()) return 1;
    
#if defined(PLATFORM_WINDOWS)
    /* Check for AppInit_DLLs in registry */
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char dllName[MAX_PATH];
        DWORD size = sizeof(dllName);
        if (RegQueryValueExA(hKey, "AppInit_DLLs", nullptr, nullptr, 
                (LPBYTE)dllName, &size) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            if (dllName[0] != '\0') return 1;
        }
        RegCloseKey(hKey);
    }
    
    /* Check for KnownDLLs hooking */
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs",
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char value[256];
        DWORD size = sizeof(value);
        DWORD type;
        /* Check if known DLLs list is abnormally modified */
        for (DWORD idx = 0; RegEnumValueA(hKey, idx, value, &size,
                nullptr, &type, nullptr, nullptr) == ERROR_SUCCESS; idx++) {
            if (strstr(value, "hook") || strstr(value, "inject")) {
                RegCloseKey(hKey);
                return 1;
            }
            size = sizeof(value);
        }
        RegCloseKey(hKey);
    }
#endif
    
    return 0;
}

/* ── Inline Hook Detection ────────────────────────────────────────────────── */
/* Detects common inline hook patterns:
 *   x86_64: mov rax, imm64; jmp rax  (FF D0) or push/ret patterns
 *   x86:   push addr; ret            (FF 35 or 68 + C3)
 *   ARM:   LDR pc, [pc, #-4]         (E51FF004)
 * Returns 1 if hook detected, 0 otherwise. */
int anti_debug_check_inline_hooks(void) {
#if defined(PLATFORM_LINUX)
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    char line[1024];
    char last_path[256] = {0};

    while (fgets(line, sizeof(line), fp)) {
        /* Only scan executable library mappings (not [vdso], [vvar], [vsyscall]) */
        if (!strstr(line, " r-xp ") || strstr(line, "[vdso]") ||
            strstr(line, "[vvar]") || strstr(line, "[vsyscall]"))
            continue;

        /* Extract path */
        char *path_start = strchr(line, '/');
        if (!path_start) continue;

        /* Skip if same as last (avoid re-scanning same library) */
        if (strcmp(path_start, last_path) == 0) continue;
        strncpy(last_path, path_start, sizeof(last_path) - 1);
        last_path[sizeof(last_path) - 1] = '\0';

        /* Extract permissions and inode - check for [heap] or [stack] in line */
        if (strstr(line, "[heap]") || strstr(line, "[stack]") ||
            strstr(line, "[anon_") || strstr(line, "[stack:"))
            continue;

        /* Extract start address */
        unsigned long start_addr = strtoul(line, nullptr, 16);
        if (!start_addr || !is_valid_user_address(start_addr)) continue;

        /* Read first 64 bytes of each executable mapping for hook patterns */
        int fd = open("/proc/self/mem", O_RDONLY);
        if (fd < 0) continue;

        unsigned char buf[64];
        /* Use safe_pread to catch SIGSEGV from race condition */
        ssize_t bytes_read = safe_pread(fd, buf, sizeof(buf), start_addr);

        if (bytes_read < 12) { close(fd); continue; }

        /* Common inline hook patterns to detect */
        for (int i = 0; i < bytes_read - 11; i++) {
            /* Pattern 1: mov rax, imm64; jmp rax (FF D0) - common x86_64 hook */
            if (buf[i] == 0x48 && buf[i+1] == 0xB8 && buf[i+10] == 0xFF && buf[i+11] == 0xD0) {
                close(fd);
                fclose(fp);
                return 1;
            }

            /* Pattern 2: push + ret (common cross-platform hook) */
            if (buf[i] == 0xFF && (buf[i+1] == 0x35 || buf[i+1] == 0x25) && buf[i+6] == 0xC3) {
                close(fd);
                fclose(fp);
                return 1;
            }

            /* Pattern 3: push imm32; ret (0x68 + ret) */
            if (buf[i] == 0x68 && buf[i+5] == 0xC3) {
                unsigned char *next = (unsigned char *)((unsigned long)start_addr + i + 5 + 1);
                unsigned char tmp[2];
                /* Use safe_pread for the additional read */
                ssize_t next_bytes = safe_pread(fd, tmp, 2, (off_t)next);
                if (next_bytes == 2 && tmp[0] == 0xC3) {
                    close(fd);
                    fclose(fp);
                    return 1;
                }
            }

            /* Pattern 4: jmp far (FF /5) - indirect far jump */
            if ((buf[i] & 0xFF) == 0xFF && (buf[i+1] & 0x38) == 0x20) {
                close(fd);
                fclose(fp);
                return 1;
            }
        }

        close(fd);
    }
    fclose(fp);
#elif defined(PLATFORM_MACOS)
    /* macOS inline hook detection via dyld and mach_vm APIs.
     * Scans loaded dylibs for hook patterns in function prologues. */
    uint32_t image_count = _dyld_image_count();
    if (image_count == 0) return 0;

    task_t self_task = mach_task_self();

    for (uint32_t i = 0; i < image_count; i++) {
        const mach_header *header = _dyld_get_image_header(i);
        if (!header) continue;

        const char *name = _dyld_get_image_name(i);
        if (!name) continue;

        /* Skip dyld itself */
        if (strstr(name, "/dyld") || strstr(name, "/libdyld.dylib"))
            continue;

        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        if (slide == 0 && header != _dyld_get_image_header(0)) {
            if (i > 0) continue;
        }

        uint64_t text_start = (uint64_t)header + slide;
        uint64_t text_size = 4096; /* Read first page of text segment */

        vm_offset_t data_ptr;
        mach_msg_type_number_t bytes_read = 0;
        kern_return_t kr = mach_vm_read(self_task, text_start, text_size, &data_ptr, &bytes_read);

        if (kr != KERN_SUCCESS || bytes_read < 16) continue;

        unsigned char *buf = (unsigned char *)data_ptr;
        for (mach_msg_type_number_t j = 0; j < bytes_read - 15; j++) {
            /* Pattern 1: mov rax, imm64; jmp rax (12 bytes) */
            if (buf[j] == 0x48 && buf[j+1] == 0xB8 && buf[j+10] == 0xFF && buf[j+11] == 0xD0) {
                vm_deallocate(self_task, data_ptr, bytes_read);
                return 1;
            }
            /* Pattern 2: push + ret */
            if (buf[j] == 0xFF && (buf[j+1] == 0x35 || buf[j+1] == 0x25) && buf[j+6] == 0xC3) {
                vm_deallocate(self_task, data_ptr, bytes_read);
                return 1;
            }
            /* Pattern 3: push imm32; ret */
            if (buf[j] == 0x68 && buf[j+5] == 0xC3) {
                vm_deallocate(self_task, data_ptr, bytes_read);
                return 1;
            }
            /* Pattern 4: jmp far */
            if ((buf[j] & 0xFF) == 0xFF && (buf[j+1] & 0x38) == 0x20) {
                vm_deallocate(self_task, data_ptr, bytes_read);
                return 1;
            }
            /* Pattern 5: 5-byte jmp rel32 */
            if (buf[j] == 0xE9) {
                vm_deallocate(self_task, data_ptr, bytes_read);
                return 1;
            }
            /* Pattern 6: mov rsi, rdi; jmp - common Swift hook */
            if (buf[j] == 0x48 && buf[j+1] == 0x89 && buf[j+2] == 0xFE && buf[j+3] == 0xFF && buf[j+4] == 0xE0) {
                vm_deallocate(self_task, data_ptr, bytes_read);
                return 1;
            }
        }

        vm_deallocate(self_task, data_ptr, bytes_read);
    }
    return 0;
#elif defined(PLATFORM_WINDOWS)
    /* Windows inline hook detection via function prologue scanning.
     * Uses direct memory access with SEH for safety. */
    static const struct {
        const char *dll;
        const char *funcs[20];
    } hook_targets[] = {
        {"kernel32.dll", {"OpenProcess", "ReadProcessMemory", "WriteProcessMemory",
                          "CreateRemoteThread", "VirtualProtectEx", "VirtualAllocEx",
                          "CreateProcessA", "WinExec", "LoadLibraryA", nullptr}},
        {"ntdll.dll",   {"NtOpenProcess", "NtReadVirtualMemory", "NtWriteVirtualMemory",
                          "NtCreateThreadEx", "NtProtectVirtualMemory",
                          "NtResumeThread", "NtSuspendThread", nullptr}},
        {nullptr, {nullptr}}
    };
    
    for (int d = 0; hook_targets[d].dll; d++) {
        HMODULE hMod = GetModuleHandleA(hook_targets[d].dll);
        if (!hMod) continue;
        
        for (int f = 0; hook_targets[d].funcs[f]; f++) {
            FARPROC addr = GetProcAddress(hMod, hook_targets[d].funcs[f]);
            if (!addr) continue;
            
            unsigned char *p = (unsigned char *)addr;
            __try {
                /* Pattern 1: mov rax, imm64; jmp rax (12-byte trampoline) */
                if (p[0] == 0x48 && p[1] == 0xB8 && p[10] == 0xFF && p[11] == 0xD0)
                    return 1;
                
                /* Pattern 2: jmp [rip+offset] (FF 25 XX XX XX XX) - IAT thunk */
                if (p[0] == 0xFF && p[1] == 0x25 && p[6] == 0x48) /* followed by standard prologue? */
                    continue; /* Legitimate IAT thunk, not a hook */
                
                /* Pattern 3: push imm32; ret (68 XX XX XX XX C3) */
                if (p[0] == 0x68 && p[5] == 0xC3)
                    return 1;
                
                /* Pattern 4: jmp short (EB XX) at start - overwritten prologue */
                if (p[0] == 0xEB && p[5] == 0xC3) /* jmp short + push imm32 + ret */
                    return 1;
                    
                /* Pattern 5: 5-byte jmp rel32 (E9 XX XX XX XX) - Detours-style hook */
                if (p[0] == 0xE9)
                    return 1;
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                continue;
            }
        }
    }
    return 0; /* No hooks detected */
#else
    return 0;
#endif
}

/* ── PLT/GOT / IAT Hook Detection ──────────────────────────────────────────── */
/* Linux: PLT/GOT hook detection via /proc/self/maps memory scanning.
 * Windows: IAT hook detection via scanning writable PE sections for
 *   pointers that point outside legitimate module address ranges. */
int anti_debug_check_plt_hooks(void) {
#if defined(PLATFORM_LINUX)
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    char line[1024];
    char last_lib[256] = {0};

    while (fgets(line, sizeof(line), fp)) {
        /* Look for writable segments in shared libraries (potential GOT hooks) */
        if (!strstr(line, " rw-p ") && !strstr(line, " rwxp ")) continue;

        /* Extract library path */
        char *path = strchr(line, '/');
        if (!path) continue;

        /* Skip pseudo-VMAs */
        if (strstr(line, "[heap]") || strstr(line, "[stack]") ||
            strstr(line, "[anon_") || strstr(line, "]"))
            continue;

        /* Only check main executables and known system libs */
        if (strncmp(path, "/lib", 4) != 0 && strncmp(path, "/usr/lib", 8) != 0)
            continue;

        /* Extract start and end addresses */
        unsigned long start, end;
        if (sscanf(line, "%lx-%lx", &start, &end) != 2) continue;

        size_t seg_size = end - start;
        if (seg_size < 8 || seg_size > 16*1024*1024) continue;
        if (!is_valid_user_address(start)) continue;

        /* Map the segment and scan for GOT/PLT indicators */
        int fd = open("/proc/self/mem", O_RDONLY);
        if (fd < 0) continue;

        /* Sample scan: check first 4KB for suspicious pointer values */
        unsigned char *buf = (unsigned char *)malloc(4096);
        if (!buf) { close(fd); continue; }

        /* Use safe_pread to catch SIGSEGV from race condition */
        ssize_t n = safe_pread(fd, buf, 4096, start);
        close(fd);

        if (n > 0) {
            /* Scan for pointers that point to:
             * 1. Memory regions not in any mapped library
             * 2. Executable segments of other libraries (potential hooks)
             * 3. WX memory regions (injected code) */
            for (ssize_t i = 0; i < n - 8; i += 8) {
                unsigned long ptr = *(unsigned long *)(buf + i);

                /* Check if pointer is in user-space range */
                if (ptr < 0x10000 || ptr > 0x7FFFFFFFFFFF) continue;

                /* Check if pointer points to suspicious WX memory */
                char ptr_path[64];
                snprintf(ptr_path, sizeof(ptr_path), "/proc/self/maps");

                FILE *mp = fopen(ptr_path, "r");
                if (!mp) continue;

                char mline[1024];
                int found_valid = 0;
                while (fgets(mline, sizeof(mline), mp)) {
                    unsigned long m_start, m_end;
                    char perms[8], dev[8], pathname[256] = "";

                    sscanf(mline, "%lx-%lx %s %*s %*s %*s %*s %s",
                           &m_start, &m_end, perms, pathname);

                    if (ptr >= m_start && ptr < m_end) {
                        found_valid = 1;

                        /* If pointing to WX memory that's not a known library, flag it */
                        if (strstr(perms, "rwx") && strlen(pathname) == 0) {
                            free(buf);
                            fclose(mp);
                            fclose(fp);
                            return 1;
                        }
                        break;
                    }
                }
                fclose(mp);
            }
        }

        free(buf);
    }
    fclose(fp);
#elif defined(PLATFORM_MACOS)
    /* macOS: Check for hooked dylibs via dyld image verify.
     * Looks for suspicious library injections and modified segment permissions. */
    uint32_t image_count = _dyld_image_count();
    if (image_count == 0) return 0;

    task_t self_task = mach_task_self();

    /* Collect all dylib load addresses for pointer validation */
    struct DylibInfo {
        uint64_t addr;
        uint64_t size;
        const char *name;
    };
    std::vector<DylibInfo> dylibs;

    for (uint32_t i = 0; i < image_count; i++) {
        const mach_header *header = _dyld_get_image_header(i);
        if (!header) continue;

        DylibInfo info;
        info.name = _dyld_get_image_name(i);
        info.addr = (uint64_t)header + _dyld_get_image_vmaddr_slide(i);

        /* Get size from dyld - approximate via first 16KB scan */
        info.size = 16 * 1024;

        if (info.name) dylibs.push_back(info);
    }

    /* Check for suspicious dylibs (hooks often inject new dylibs) */
    for (uint32_t i = 0; i < image_count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;

        /* Suspicious patterns: /tmp, /var/folders, unexpected paths */
        if (strstr(name, "/tmp/") || strstr(name, "/var/folders/") ||
            strstr(name, ".hook") || strstr(name, "_hook") ||
            strstr(name, "injected") || strstr(name, "Injected") ||
            strstr(name, "frida") || strstr(name, "Frida")) {
            return 1;
        }
    }

    /* Check for suspicious WX memory regions via vm_region */
    for (uint32_t i = 0; i < dylibs.size(); i++) {
        uint64_t addr = dylibs[i].addr;
        uint64_t size = dylibs[i].size;

        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        uint64_t region_addr = addr;
        kern_return_t kr;

        for (uint64_t scan_addr = addr; scan_addr < addr + size; scan_addr += 4096) {
            mach_port_t object_name;
            kr = vm_region_64(self_task, &region_addr, &size, VM_REGION_BASIC_INFO_64,
                             (vm_region_info_t)&info, &count, &object_name);

            if (kr == KERN_SUCCESS) {
                /* Check for WX (writable + executable) private memory */
                if (info.protection & VM_PROT_WRITE && info.protection & VM_PROT_EXECUTE) {
                    if (info.shared == 0) { /* Private mapping */
                        /* Check if it's not from a known dylib */
                        int found = 0;
                        for (const auto& d : dylibs) {
                            if (scan_addr >= d.addr && scan_addr < d.addr + d.size) {
                                found = 1;
                                break;
                            }
                        }
                        if (!found) return 1;
                    }
                }
            }
        }
    }
    return 0;
#elif defined(PLATFORM_WINDOWS)
    /* Windows IAT hook detection.
     * Scans writable sections of loaded DLLs for pointers that
     * point outside legitimate module ranges (potential IAT hooks). */
    static const char *modules_to_check[] = {
        "kernel32.dll", "ntdll.dll", "user32.dll", "ws2_32.dll", nullptr
    };
    
    for (int mi = 0; modules_to_check[mi]; mi++) {
        HMODULE hMod = GetModuleHandleA(modules_to_check[mi]);
        if (!hMod) continue;
        
        /* Get PE headers */
        IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)hMod;
        IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)((BYTE *)hMod + dos->e_lfanew);
        
        /* Scan each section for writable content (potential IAT) */
        IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
        for (WORD si = 0; si < nt->FileHeader.NumberOfSections; si++) {
            if (!(sec[si].Characteristics & IMAGE_SCN_MEM_WRITE))
                continue;
            
            BYTE *secStart = (BYTE *)hMod + sec[si].VirtualAddress;
            DWORD secSize = min(sec[si].SizeOfRawData, 4096u);
            if (secSize < 8) continue;
            
            __try {
                /* Sample scan first 4KB for suspicious pointers */
                for (DWORD off = 0; off < secSize - sizeof(void *); off += sizeof(void *)) {
                    void *ptr = *(void **)(secStart + off);
                    if ((uintptr_t)ptr < 0x10000) continue;
                    
                    /* Check if pointer lands in a WX private region */
                    MEMORY_BASIC_INFORMATION mbi;
                    if (VirtualQuery(ptr, &mbi, sizeof(mbi))) {
                        if (mbi.Protect == PAGE_EXECUTE_READWRITE &&
                            mbi.Type == MEM_PRIVATE) {
                            return 1;
                        }
                    }
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                continue;
            }
        }
    }
    return 1; /* On Windows, IAT hooks are common; flag if any WX+private detected */
#else
    return 0;
#endif
}

/* ── Syscall Wrapper Verification ────────────────────────────────────────── */
/* Checks for modifications to common syscall wrapper functions by scanning
 * the first few bytes of critical libc functions. */
int anti_debug_check_syscall_hooks(void) {
#if defined(PLATFORM_LINUX)
    /* Get address of a few critical libc functions */
    void *libc_handle = dlopen("libc.so.6", RTLD_NOLOAD);
    if (!libc_handle) return 0;

    /* Critical functions that are common hook targets */
    const char *critical_funcs[] = {
        "open", "openat", "read", "write", "close",
        "socket", "connect", "accept", "send", "recv",
        "execve", "system", "popen",
        "_exit", "exit",
        "mmap", "mprotect", "munmap",
        "ptrace", "prctl",
        nullptr
    };

    int fd = open("/proc/self/mem", O_RDONLY);
    if (fd < 0) { dlclose(libc_handle); return 0; }

    int hooked = 0;

    for (int fi = 0; critical_funcs[fi] && !hooked; fi++) {
        void *func_addr = dlsym(libc_handle, critical_funcs[fi]);
        if (!func_addr) continue;

        /* Validate address is in user space */
        if (!is_valid_user_address((unsigned long)func_addr)) continue;

        /* Read first 16 bytes of each function (typical function prologue) */
        unsigned char buf[16];
        /* Use safe_pread to catch SIGSEGV from race condition */
        ssize_t n = safe_pread(fd, buf, sizeof(buf), (off_t)func_addr);

        if (n < 8) continue;

        /* Check for common hook patterns:
         * 1. mov rax, imm64; jmp rax (hook trampoline)
         * 2. push pattern followed by near jump
         * 3. Single byte 0x90 (nop) padding followed by indirect jump */
        for (int j = 0; j < n - 7; j++) {
            /* mov rax, imm64; jmp rax - 12 bytes */
            if (buf[j] == 0x48 && buf[j+1] == 0xB8 &&
                buf[j+10] == 0xFF && buf[j+11] == 0xD0) {
                hooked = 1;
                break;
            }

            /* push rbp; mov rbp, rsp; jmp (standard prologue - OK) */
            if (buf[j] == 0x55 && buf[j+1] == 0x48 && buf[j+2] == 0x89 &&
                buf[j+3] == 0xE5 && buf[j+4] == 0x90) {
                /* Function starts with standard prologue + nop, OK */
                break;
            }

            /* Standard x86_64 prologue without nop (OK) */
            if (buf[j] == 0x55 && buf[j+1] == 0x48 && buf[j+2] == 0x89 &&
                buf[j+3] == 0xE5) {
                break;
            }

            /* Standard x86 prologue (OK) */
            if (buf[j] == 0x55 && buf[j+1] == 0x89 && buf[j+2] == 0xE5) {
                break;
            }

            /* If none of the above and bytes don't look like a normal hook... */
            if (j == n - 8) {
                /* Check if function is entirely nops (packed/encrypted stub) */
                int all_nops = 1;
                for (int k = 0; k < n; k++) {
                    if (buf[k] != 0x90 && buf[k] != 0xCC) {
                        all_nops = 0;
                        break;
                    }
                }
                if (!all_nops) {
                    /* Unknown pattern that doesn't match normal prologue */
                    hooked = 1;
                }
            }
        }
    }

    close(fd);
    dlclose(libc_handle);
    return hooked;
#elif defined(PLATFORM_MACOS)
    /* macOS syscall hook detection via libSystem.B.dylib function scanning.
     * Uses dlopen/dlsym for symbol resolution and mach_vm_read for safe memory reading. */
    void *libc_handle = dlopen("libSystem.B.dylib", RTLD_NOLOAD);
    if (!libc_handle) {
        /* Try libSystem.dylib as fallback */
        libc_handle = dlopen("libSystem.dylib", RTLD_NOLOAD);
    }
    if (!libc_handle) return 0;

    task_t self_task = mach_task_self();

    /* Critical functions that are common hook targets on macOS */
    const char *critical_funcs[] = {
        "open", "open_nocancel", "read", "read_nocancel", "write", "write_nocancel",
        "close", "close_nocancel", "socket", "connect", "accept",
        "execve", "exit", "_exit",
        "mmap", "mprotect", "munmap",
        "ptrace", "stat", "lstat", "fstat",
        nullptr
    };

    int hooked = 0;

    for (int fi = 0; critical_funcs[fi] && !hooked; fi++) {
        void *func_addr = dlsym(libc_handle, critical_funcs[fi]);
        if (!func_addr) continue;

        /* Read first 16 bytes of each function using mach_vm_read */
        unsigned char buf[16];
        vm_size_t bytes_read = 0;
        kern_return_t kr = mach_vm_read(self_task, (uint64_t)func_addr, 16, (vm_offset_t *)buf, &bytes_read);

        if (kr != KERN_SUCCESS || bytes_read < 8) continue;

        for (int j = 0; j < bytes_read - 7; j++) {
            /* mov rax, imm64; jmp rax - 12 bytes hook pattern */
            if (buf[j] == 0x48 && buf[j+1] == 0xB8 &&
                buf[j+10] == 0xFF && buf[j+11] == 0xD0) {
                hooked = 1;
                break;
            }

            /* Standard macOS x86_64 prologue: push rbp; mov rbp, rsp */
            if (buf[j] == 0x55 && buf[j+1] == 0x48 && buf[j+2] == 0x89 &&
                buf[j+3] == 0xE5) {
                break;
            }

            /* Alternative prologue with nop */
            if (buf[j] == 0x55 && buf[j+1] == 0x48 && buf[j+2] == 0x89 &&
                buf[j+3] == 0xE5 && buf[j+4] == 0x90) {
                break;
            }

            /* Standard x86 prologue */
            if (buf[j] == 0x55 && buf[j+1] == 0x89 && buf[j+2] == 0xE5) {
                break;
            }

            /* Check for suspicious patterns at end of buffer */
            if (j == bytes_read - 8) {
                int all_nops = 1;
                for (int k = 0; k < bytes_read; k++) {
                    if (buf[k] != 0x90 && buf[k] != 0xCC) {
                        all_nops = 0;
                        break;
                    }
                }
                if (!all_nops) {
                    hooked = 1;
                }
            }
        }
    }

    dlclose(libc_handle);
    return hooked;
#elif defined(PLATFORM_WINDOWS)
    /* Windows syscall hook detection via ntdll.dll function scanning.
     * Checks critical ntdll functions for modified prologues. */
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return 0;
    
    static const char *nt_funcs[] = {
        "NtOpenProcess", "NtReadVirtualMemory", "NtWriteVirtualMemory",
        "NtCreateThreadEx", "NtProtectVirtualMemory", "NtAllocateVirtualMemory",
        "NtFreeVirtualMemory", "NtResumeThread", "NtSuspendThread",
        "NtClose", "NtCreateFile", "NtDeviceIoControlFile",
        nullptr
    };
    
    for (int fi = 0; nt_funcs[fi]; fi++) {
        FARPROC addr = GetProcAddress(hNtdll, nt_funcs[fi]);
        if (!addr) continue;
        
        unsigned char *p = (unsigned char *)addr;
        __try {
            /* Standard ntdll x64 prologue is mov [rsp+8],rbx or similar
             * Hook patterns to detect: */
            
            /* mov rax, imm64; jmp rax (12-byte trampoline) */
            if (p[0] == 0x48 && p[1] == 0xB8 && p[10] == 0xFF && p[11] == 0xD0)
                return 1;
            
            /* 5-byte jmp rel32 (E9 XX XX XX XX) */
            if (p[0] == 0xE9)
                return 1;
            
            /* push imm32; ret (hook trampoline) */
            if (p[0] == 0x68 && p[5] == 0xC3)
                return 1;
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            continue;
        }
    }
    return 0;
#else
    return 0;
#endif
}

/* ── Enhanced Memory Region Integrity Check ─────────────────────────────── */
/* Enhanced version that detects:
 * - Newly allocated WX memory regions
 * - Unexpected changes in memory layout
 * - Private WX mappings (potential code injection) */
int anti_debug_check_memory_integrity(void) {
#if defined(PLATFORM_LINUX)
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    char line[1024];
    int wx_regions = 0;
    int private_wx_count = 0;

    while (fgets(line, sizeof(line), fp)) {
        /* Parse permissions field - format: rwxp or rw-p */
        char perms[5] = "";
        unsigned long start, end;
        char pathname[256] = "";

        if (sscanf(line, "%lx-%lx %4s %*s %*s %*s %*s %255[^\n]",
                   &start, &end, perms, pathname) < 3)
            continue;

        /* Count WX regions */
        if (strchr(perms, 'w') && strchr(perms, 'x')) {
            wx_regions++;

            /* Private WX mappings (not backed by file) are suspicious for JIT hooks */
            if (!pathname[0] || strstr(pathname, "[anon") || strstr(pathname, "[heap]")) {
                private_wx_count++;
            }
        }

        /* Check for anonymous executable memory with excessive size */
        if (strchr(perms, 'x') && (!pathname[0] || strstr(pathname, "[anon"))) {
            /* Only flag if not vdso/vvar/vsyscall (those are legitimate) */
            if (!strstr(line, "[vdso]") && !strstr(line, "[vvar]") &&
                !strstr(line, "[vsyscall]")) {
                /* Large anonymous executable mapping (> 1MB) is suspicious */
                size_t size = end - start;
                if (size > 1024 * 1024) {
                    fclose(fp);
                    return 1;
                }
            }
        }
    }
    fclose(fp);

    /* Multiple private WX mappings suggest JIT hooking */
    if (private_wx_count > 2) return 1;

    /* Multiple WX regions in general could indicate hooking libraries */
    if (wx_regions > 10) return 1;

#elif defined(PLATFORM_MACOS)
    /* macOS memory integrity check via mach_vm_region.
     * Enumerates VM regions and checks for suspicious WX mappings. */
    task_t self_task = mach_task_self();
    uint64_t addr = 0;
    int wx_regions = 0;
    int private_wx_count = 0;

    kern_return_t kr;
    vm_size_t size = 0;

    while (1) {
        mach_port_t object_name;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;

        kr = vm_region_64(self_task, &addr, &size, VM_REGION_BASIC_INFO_64,
                         (vm_region_info_t)&info, &count, &object_name);

        if (kr != KERN_SUCCESS) {
            if (addr >= (uint64_t)0x7FFFFFFF0000) break;
            addr += 4096;
            continue;
        }

        /* Check for WX regions */
        if (info.protection & VM_PROT_WRITE && info.protection & VM_PROT_EXECUTE) {
            wx_regions++;

            /* Private WX mappings are suspicious (injected code) */
            if (info.shared == 0) {
                private_wx_count++;
            }
        }

        addr += size;
        if (addr >= (uint64_t)0x7FFFFFFF0000) break;
    }

    /* Suspicious if multiple private WX regions found */
    if (private_wx_count > 2) return 1;
    if (wx_regions > 15) return 1;

#elif defined(PLATFORM_WINDOWS)
    /* Windows memory integrity check via VirtualQuery.
     * Enumerates all committed memory regions and counts
     * WX (PAGE_EXECUTE_READWRITE) mappings. */
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    
    BYTE *addr = (BYTE *)si.lpMinimumApplicationAddress;
    BYTE *maxAddr = (BYTE *)si.lpMaximumApplicationAddress;
    
    int wx_regions = 0;
    int private_wx = 0;
    
    while (addr < maxAddr) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0) {
            addr += 0x10000;  /* Skip unreadable region */
            continue;
        }
        
        if (mbi.State == MEM_COMMIT) {
            DWORD prot = mbi.Protect & 0xFF;
            
            /* Check for WX regions (PAGE_EXECUTE_READWRITE or PAGE_EXECUTE_WRITECOPY) */
            if (prot == PAGE_EXECUTE_READWRITE) {
                wx_regions++;
                
                /* Private WX mappings are suspicious */
                if (mbi.Type == MEM_PRIVATE) {
                    private_wx++;
                    /* Large private WX mapping > 1MB is definitely suspicious */
                    if (mbi.RegionSize > 1024 * 1024)
                        return 1;
                }
            }
        }
        
        addr += mbi.RegionSize;
    }
    
    /* Multiple private WX mappings suggest JIT hooking */
    if (private_wx > 2) return 1;
    
    /* Multiple WX regions could indicate hooking libraries */
    if (wx_regions > 10) return 1;
#endif
    return 0;
}

/* ── Combined check ── */
AntiDebugResult anti_debug_check_all(void) {
    if (anti_debug_check_tracerpid())    return ADBG_RESULT_DEBUGGER_DETECTED;
    
#if defined(PLATFORM_WINDOWS)
    if (anti_debug_check_remote_debugger()) return ADBG_RESULT_DEBUGGER_DETECTED;
    if (anti_debug_check_debug_port())      return ADBG_RESULT_DEBUGGER_DETECTED;
    if (anti_debug_check_debug_flags())     return ADBG_RESULT_DEBUGGER_DETECTED;
    if (anti_debug_check_debug_object())    return ADBG_RESULT_DEBUGGER_DETECTED;
    if (anti_debug_check_output_debug_string()) return ADBG_RESULT_DEBUGGER_DETECTED;
#elif defined(PLATFORM_MACOS)
    if (anti_debug_check_ptrace_deny_attach()) return ADBG_RESULT_DEBUGGER_DETECTED;
    if (anti_debug_check_mach_task())          return ADBG_RESULT_DEBUGGER_DETECTED;
    if (anti_debug_check_loaded_modules())     return ADBG_RESULT_DEBUGGER_DETECTED;
#elif defined(PLATFORM_LINUX)
    if (anti_debug_check_ptrace())       return ADBG_RESULT_DEBUGGER_DETECTED;
    if (anti_debug_check_fork())         return ADBG_RESULT_DEBUGGER_DETECTED;
    if (anti_debug_check_maps())         return ADBG_RESULT_DEBUGGER_DETECTED;
    if (anti_debug_check_parent())       return ADBG_RESULT_DEBUGGER_DETECTED;
    if (anti_debug_check_debugregs())    return ADBG_RESULT_DEBUGGER_DETECTED;
    if (anti_debug_check_procstat())     return ADBG_RESULT_DEBUGGER_DETECTED;
    if (anti_debug_check_proc_cmdline()) return ADBG_RESULT_DEBUGGER_DETECTED;
    if (anti_debug_check_prctl())        return ADBG_RESULT_DEBUGGER_DETECTED;
    if (anti_debug_check_timing())       return ADBG_RESULT_DEBUGGER_DETECTED;
    if (anti_debug_check_cpuid())        return ADBG_RESULT_VM_DETECTED;
    if (anti_debug_check_seccomp())      return ADBG_RESULT_VM_DETECTED;
#endif
    
    if (check_sandbox())                 return ADBG_RESULT_SANDBOX_DETECTED;
    if (check_hooks())                   return ADBG_RESULT_HOOK_DETECTED;

    /* Advanced hook detection */
#if defined(PLATFORM_LINUX) || defined(PLATFORM_WINDOWS) || defined(PLATFORM_MACOS)
    if (anti_debug_check_inline_hooks())      return ADBG_RESULT_HOOK_DETECTED;
    if (anti_debug_check_plt_hooks())         return ADBG_RESULT_HOOK_DETECTED;
    if (anti_debug_check_syscall_hooks())     return ADBG_RESULT_HOOK_DETECTED;
    if (anti_debug_check_memory_integrity()) return ADBG_RESULT_HOOK_DETECTED;
#endif

    return ADBG_RESULT_CLEAN;
}

/* ── Environment sanitization ── */
char **anti_debug_sanitize_environment(void) {
    static const char *blocklist[] = {
        "PYTHONPATH",
        "PYTHONHOME",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "LD_DEBUG",
        "LD_OPENCL_LIBRARY_PATH",
        nullptr
    };
    extern char **environ;
    size_t count = 0;
    for (size_t i = 0; environ[i]; i++) count++;

    char **new_env = (char **)malloc((count + 1) * sizeof(char *));
    if (!new_env) return nullptr;

    size_t out = 0;
    for (size_t i = 0; environ[i]; i++) {
        int block = 0;
        for (int k = 0; blocklist[k]; k++) {
            size_t blen = strlen(blocklist[k]);
            if (strncmp(environ[i], blocklist[k], blen) == 0 &&
                environ[i][blen] == '=') {
                block = 1;
                break;
            }
        }
        if (!block) {
            new_env[out] = strdup(environ[i]);
            if (!new_env[out]) { /* cleanup on failure */ }
            out++;
        }
    }
    new_env[out] = nullptr;
    return new_env;
}

/* ── Generate Python anti-debugging stub ── */
char *anti_debug_generate_stub(int include_vm_check, int include_hook_check) {
    std::string s;
    s.reserve(4096);

    s += "import sys as _SYS\n";
    s += "import os as _OS\n";
    s += "import platform as _PLATFORM\n";

    /* Platform-specific debugger checks */
    s += "_IS_WINDOWS = _PLATFORM.system() == 'Windows'\n";
    s += "_IS_MACOS = _PLATFORM.system() == 'Darwin'\n";
    s += "_IS_LINUX = _PLATFORM.system() == 'Linux'\n";
    
    /* Windows debugger checks */
    s += "if _IS_WINDOWS:\n";
    s += "    try:\n";
    s += "        import ctypes as _CT\n";
    s += "        _K32 = _CT.windll.kernel32\n";
    s += "        if _K32.IsDebuggerPresent():\n";
    s += "            _SYS.stderr.write('error: debugger detected\\n'); _SYS.exit(1)\n";
    s += "    except: pass\n";
    
    /* Linux TracerPid check */
    s += "if _IS_LINUX:\n";
    s += "    try:\n";
    s += "        with open('/proc/self/status') as _F:\n";
    s += "            for _L in _F:\n";
    s += "                if 'TracerPid:' in _L:\n";
    s += "                    if _L.split(':')[1].strip() != '0':\n";
    s += "                        _SYS.stderr.write('error: debugger detected\\n'); _SYS.exit(1)\n";
    s += "    except: pass\n";
    
    /* MacOS sysctl check via ctypes — uses raw buffer for cross-version compatibility */
    s += "if _IS_MACOS:\n";
    s += "    try:\n";
    s += "        import ctypes as _CT\n";
    s += "        _LIBC = _CT.CDLL(None)\n";
    s += "        # sysctl CTL_KERN(1) KERN_PROC(14) KERN_PROC_PID(1) pid\n";
    s += "        _MIB = (_CT.c_int * 4)(1, 14, 1, _SYS.getpid())\n";
    s += "        _BUF = (_CT.c_char * 1024)()\n";
    s += "        _SIZE = _CT.c_size_t(1024)\n";
    s += "        if _LIBC.sysctl(_MIB, 4, _CT.byref(_BUF), _CT.byref(_SIZE), None, 0) == 0:\n";
    s += "            _RAW = bytes(_BUF)\n";
    s += "            P_TRACED = 0x800\n";
    s += "            # Check multiple possible p_flag offsets (macOS version-dependent)\n";
    s += "            for _OFF in (64, 68, 72, 76, 80):\n";
    s += "                if _OFF + 4 <= _SIZE.value:\n";
    s += "                    _FLAG = int.from_bytes(_RAW[_OFF:_OFF+4], 'little')\n";
    s += "                    if _FLAG & P_TRACED:\n";
    s += "                        _SYS.stderr.write('error: debugger detected\\n'); _SYS.exit(1)\n";
    s += "    except: pass\n";

    /* Breakpoint hook removal */
    s += "try: _SYS.breakpointhook = None\n";
    s += "except: pass\n";

    /* Module scan for debuggers */
    s += "for _M in ('pydevd','pdb','ipdb','pdbpp','pydevconsole','trace'):\n";
    s += "    if _M in _SYS.modules:\n";
    s += "        _SYS.stderr.write('error: debugger detected\\n'); _SYS.exit(1)\n";

    /* ── Frida instrumentation detection ── */
    s += "if 'frida' in _SYS.modules:\n";
    s += "    _SYS.stderr.write('error: instrumentation detected\\n'); _SYS.exit(1)\n";
    s += "if _OS.environ.get('FRIDA_SCRIPT'):\n";
    s += "    _SYS.stderr.write('error: instrumentation detected\\n'); _SYS.exit(1)\n";
    s += "if _IS_LINUX or _IS_MACOS:\n";
    s += "    try:\n";
    s += "        import socket as _SK\n";
    s += "        _S = _SK.socket(_SK.AF_INET, _SK.SOCK_STREAM)\n";
    s += "        _S.settimeout(1.0)\n";
    s += "        if _S.connect_ex(('127.0.0.1', 27042)) == 0:\n";
    s += "            _S.close()\n";
    s += "            _SYS.stderr.write('error: instrumentation detected\\n'); _SYS.exit(1)\n";
    s += "        _S.close()\n";
    s += "    except: pass\n";
    s += "if _IS_LINUX:\n";
    s += "    try:\n";
    s += "        with open('/proc/self/maps') as _F:\n";
    s += "            if 'frida' in _F.read():\n";
    s += "                _SYS.stderr.write('error: instrumentation detected\\n'); _SYS.exit(1)\n";
    s += "    except: pass\n";
    s += "    try:\n";
    s += "        with open('/proc/self/cmdline') as _F:\n";
    s += "            _C = _F.read()\n";
    s += "        with open('/proc/self/status') as _F:\n";
    s += "            for _L in _F:\n";
    s += "                if 'frida' in _L.lower():\n";
    s += "                    _SYS.stderr.write('error: instrumentation detected\\n'); _SYS.exit(1)\n";
    s += "    except: pass\n";
    s += "if _IS_MACOS:\n";
    s += "    try:\n";
    s += "        import subprocess as _SP\n";
    s += "        if 'frida' in _SP.check_output(['ps', 'aux'], stderr=_SP.DEVNULL).decode().lower():\n";
    s += "            _SYS.stderr.write('error: instrumentation detected\\n'); _SYS.exit(1)\n";
    s += "    except: pass\n";
    s += "    for _P in _OS.listdir('/tmp'):\n";
    s += "        if 'frida' in _P.lower():\n";
    s += "            _SYS.stderr.write('error: instrumentation detected\\n'); _SYS.exit(1)\n";
    s += "            break\n";

    if (include_hook_check) {
        /* ── Advanced builtin function integrity check ──
         * Verifies __name__ attribute of critical builtins (__import__,
         * compile, exec, eval, open) and their type to detect
         * monkey-patching/hooking via function replacement. */
        s += "_B = _SYS.modules.get('builtins')\n";
        s += "_HOOKED = 0\n";
        s += "for _N in ('__import__','compile','exec','eval','open'):\n";
        s += "    _F = getattr(_B, _N, None)\n";
        s += "    if _F is None:\n";
        s += "        _HOOKED = 1; break\n";
        s += "    _G = getattr(_F, '__name__', '')\n";
        s += "    if _G != _N:\n";
        s += "        _HOOKED = 1; break\n";
        s += "if _HOOKED:\n";
        s += "    _SYS.stderr.write('error: hook detected\\n'); _SYS.exit(1)\n";
        
        /* ── Check __builtins__ type integrity ── */
        s += "_BT = type(getattr(_B, '__build_class__', None))\n";
        s += "if _BT.__name__ != 'builtin_function_or_method':\n";
        s += "    _SYS.stderr.write('error: builtin tampering detected\\n'); _SYS.exit(1)\n";
        
        /* ── Sys module integrity check ── */
        s += "_ST = type(getattr(_SYS, 'settrace', None))\n";
        s += "if _ST.__name__ != 'builtin_function_or_method':\n";
        s += "    _SYS.stderr.write('error: sys tampering detected\\n'); _SYS.exit(1)\n";
        
        /* ── Comprehensive environment variable check ── */
        s += "for _EV in ('LD_PRELOAD','LD_LIBRARY_PATH','LD_AUDIT','LD_DEBUG',\n";
        s += "            'LD_OPENCL_LIBRARY_PATH','DYLD_INSERT_LIBRARIES',\n";
        s += "            'DYLD_LIBRARY_PATH','DYLD_FORCE_FLAT_NAMESPACE'):\n";
        s += "    if _OS.environ.get(_EV):\n";
        s += "        _SYS.stderr.write('error: injection detected\\n'); _SYS.exit(1)\n";
        
        /* ── /proc/self/maps check for hooking/interposition libraries (Linux) ── */
        s += "if _IS_LINUX:\n";
        s += "    try:\n";
        s += "        with open('/proc/self/maps') as _M:\n";
        s += "            for _L in _M:\n";
        s += "                if 'rwx' in _L and '[' not in _L:\n";
        s += "                    _SYS.stderr.write('error: WX memory detected\\n'); _SYS.exit(1)\n";
        s += "                if any(x in _L for x in ('/tmp/','/dev/shm/','hook','intercept')):\n";
        s += "                    _SYS.stderr.write('error: hook injection detected\\n'); _SYS.exit(1)\n";
        s += "    except: pass\n";
        
        /* ── Check sys.settrace / sys.setprofile for tracer interference ── */
        s += "_TR = _SYS.gettrace()\n";
        s += "if _TR is not None:\n";
        s += "    _SYS.stderr.write('error: tracer detected\\n'); _SYS.exit(1)\n";
        
        /* ── Windows: registry-based checks ── */
        s += "if _IS_WINDOWS:\n";
        s += "    try:\n";
        s += "        import winreg as _WR\n";
        s += "        try:\n";
        s += "            _K = _WR.OpenKey(_WR.HKEY_LOCAL_MACHINE,\n";
        s += "                r'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows')\n";
        s += "            _V, _ = _WR.QueryValueEx(_K, 'AppInit_DLLs')\n";
        s += "            _WR.CloseKey(_K)\n";
        s += "            if _V:\n";
        s += "                _SYS.stderr.write('error: DLL injection detected\\n'); _SYS.exit(1)\n";
        s += "        except: pass\n";
        s += "    except: pass\n";
        
        /* ── macOS: DYLD injection checks ── */
        s += "if _IS_MACOS:\n";
        s += "    for _DY in ('DYLD_INSERT_LIBRARIES','DYLD_LIBRARY_PATH',\n";
        s += "                'DYLD_FORCE_FLAT_NAMESPACE'):\n";
        s += "        if _OS.environ.get(_DY):\n";
        s += "            _SYS.stderr.write('error: DYLD injection detected\\n'); _SYS.exit(1)\n";

        /* ── Enhanced memory integrity: multiple WX region check ── */
        s += "if _IS_LINUX:\n";
        s += "    try:\n";
        s += "        _WX_COUNT = 0\n";
        s += "        _PRIVATE_WX = 0\n";
        s += "        with open('/proc/self/maps') as _M:\n";
        s += "            for _L in _M:\n";
        s += "                if ' rwx' in _L:\n";
        s += "                    _WX_COUNT += 1\n";
        s += "                    if '[heap]' in _L or '[anon' in _L:\n";
        s += "                        _PRIVATE_WX += 1\n";
        s += "        if _WX_COUNT > 10 or _PRIVATE_WX > 2:\n";
        s += "            _SYS.stderr.write('error: suspicious memory regions detected\\n'); _SYS.exit(1)\n";
        s += "    except: pass\n";

        /* ── Inline hook detection via function prologue scan (Linux) ── */
        s += "if _IS_LINUX:\n";
        s += "    try:\n";
        s += "        import ctypes as _CT\n";
        s += "        _LIBC = _CT.CDLL('libc.so.6')\n";
        s += "        for _FN in ('open', 'read', 'write', 'execve', 'system'):\n";
        s += "            try:\n";
        s += "                _ADDR = getattr(_LIBC, _FN)\n";
        s += "                _PROLOGUE = b''\n";
        s += "                for _I in range(16):\n";
        s += "                    try:\n";
        s += "                        _PROLOGUE += _CT.c_ubyte.from_address(_ADDR + _I)\n";
        s += "                    except: break\n";
        s += "                if len(_PROLOGUE) >= 8:\n";
        s += "                    if _PROLOGUE[0] == 0x48 and _PROLOGUE[1] == 0xB8 and _PROLOGUE[10] == 0xFF and _PROLOGUE[11] == 0xD0:\n";
        s += "                        _SYS.stderr.write('error: inline hook detected\\n'); _SYS.exit(1)\n";
        s += "            except: pass\n";
        s += "    except: pass\n";

        /* ── Inline hook detection via function prologue scan (Windows) ── */
        s += "if _IS_WINDOWS:\n";
        s += "    try:\n";
        s += "        import ctypes as _CT\n";
        s += "        _K32 = _CT.windll.kernel32\n";
        s += "        _NTDLL = _CT.WinDLL('ntdll.dll')\n";
        s += "        for _FN in ('OpenProcess', 'ReadProcessMemory', 'WriteProcessMemory',\n";
        s += "                    'CreateRemoteThread', 'VirtualProtectEx'):\n";
        s += "            try:\n";
        s += "                _ADDR = getattr(_K32, _FN)\n";
        s += "                _PRO = b''\n";
        s += "                for _I in range(12):\n";
        s += "                    try:\n";
        s += "                        _PRO += _CT.c_ubyte.from_address(_ADDR + _I)\n";
        s += "                    except: break\n";
        s += "                if len(_PRO) >= 8:\n";
        s += "                    if _PRO[0] == 0x48 and _PRO[1] == 0xB8 and _PRO[10] == 0xFF and _PRO[11] == 0xD0:\n";
        s += "                        _SYS.stderr.write('error: inline hook detected\\n'); _SYS.exit(1)\n";
        s += "                    if _PRO[0] == 0xE9:\n";
        s += "                        _SYS.stderr.write('error: detours hook detected\\n'); _SYS.exit(1)\n";
        s += "                    if _PRO[0] == 0x68 and _PRO[5] == 0xC3:\n";
        s += "                        _SYS.stderr.write('error: push-ret hook detected\\n'); _SYS.exit(1)\n";
        s += "            except: pass\n";
        s += "        for _FN in ('NtOpenProcess', 'NtReadVirtualMemory', 'NtWriteVirtualMemory',\n";
        s += "                    'NtCreateThreadEx', 'NtProtectVirtualMemory'):\n";
        s += "            try:\n";
        s += "                _ADDR = getattr(_NTDLL, _FN)\n";
        s += "                _PRO = b''\n";
        s += "                for _I in range(12):\n";
        s += "                    try:\n";
        s += "                        _PRO += _CT.c_ubyte.from_address(_ADDR + _I)\n";
        s += "                    except: break\n";
        s += "                if len(_PRO) >= 8:\n";
        s += "                    if _PRO[0] == 0x48 and _PRO[1] == 0xB8 and _PRO[10] == 0xFF and _PRO[11] == 0xD0:\n";
        s += "                        _SYS.stderr.write('error: ntdll hook detected\\n'); _SYS.exit(1)\n";
        s += "                    if _PRO[0] == 0xE9:\n";
        s += "                        _SYS.stderr.write('error: ntdll detours hook detected\\n'); _SYS.exit(1)\n";
        s += "            except: pass\n";
        s += "    except: pass\n";

        /* ── Syscall hook detection via function prologue scan ── */
        s += "if _IS_LINUX:\n";
        s += "    try:\n";
        s += "        import ctypes as _CT\n";
        s += "        _LIBC = _CT.CDLL('libc.so.6')\n";
        s += "        _SYSCALLS = ['open', 'read', 'write', 'exit', 'close', 'mmap']\n";
        s += "        for _S in _SYSCALLS:\n";
        s += "            try:\n";
        s += "                _SADDR = getattr(_LIBC, _S)\n";
        s += "                _SB = b''\n";
        s += "                for _J in range(12):\n";
        s += "                    try: _SB += _CT.c_ubyte.from_address(_SADDR + _J)\n";
        s += "                    except: break\n";
        s += "                if _SB[:3] == b'\\x48\\xb8' and _SB[10:12] == b'\\xff\\xd0':\n";
        s += "                    _SYS.stderr.write('error: syscall hook detected\\n'); _SYS.exit(1)\n";
        s += "            except: pass\n";
        s += "    except: pass\n";
        s += "if _IS_WINDOWS:\n";
        s += "    try:\n";
        s += "        import ctypes as _CT\n";
        s += "        _NTDLL = _CT.WinDLL('ntdll.dll')\n";
        s += "        for _FN in ('NtOpenProcess', 'NtReadVirtualMemory', 'NtWriteVirtualMemory',\n";
        s += "                    'NtCreateThreadEx', 'NtAllocateVirtualMemory'):\n";
        s += "            try:\n";
        s += "                _ADDR = getattr(_NTDLL, _FN)\n";
        s += "                _PRO = b''\n";
        s += "                for _I in range(12):\n";
        s += "                    try:\n";
        s += "                        _PRO += _CT.c_ubyte.from_address(_ADDR + _I)\n";
        s += "                    except: break\n";
        s += "                if len(_PRO) >= 8:\n";
        s += "                    if _PRO[0] == 0x48 and _PRO[1] == 0xB8 and _PRO[10] == 0xFF and _PRO[11] == 0xD0:\n";
        s += "                        _SYS.stderr.write('error: ntdll syscall hook detected\\n'); _SYS.exit(1)\n";
        s += "                    if _PRO[0] == 0xE9:\n";
        s += "                        _SYS.stderr.write('error: ntdll detours hook detected\\n'); _SYS.exit(1)\n";
        s += "            except: pass\n";
        s += "    except: pass\n";
        s += "if _IS_LINUX:\n";
        s += "    try:\n";
        s += "        _WX_COUNT = 0\n";
        s += "        with open('/proc/self/maps') as _M:\n";
        s += "            for _L in _M:\n";
        s += "                if ' rwx' in _L:\n";
        s += "                    _WX_COUNT += 1\n";
        s += "        if _WX_COUNT > 10:\n";
        s += "            _SYS.stderr.write('error: suspicious WX regions detected\\n'); _SYS.exit(1)\n";
        s += "    except: pass\n";
        s += "if _IS_WINDOWS:\n";
        s += "    try:\n";
        s += "        import ctypes as _CT\n";
        s += "        _K32 = _CT.windll.kernel32\n";
        s += "        class _MEMORY_BASIC_INFORMATION(_CT.Structure):\n";
        s += "            _fields_ = [\n";
        s += "                ('BaseAddress', _CT.c_void_p),\n";
        s += "                ('AllocationBase', _CT.c_void_p),\n";
        s += "                ('AllocationProtect', _CT.c_ulong),\n";
        s += "                ('RegionSize', _CT.c_size_t),\n";
        s += "                ('State', _CT.c_ulong),\n";
        s += "                ('Protect', _CT.c_ulong),\n";
        s += "                ('Type', _CT.c_ulong),\n";
        s += "            ]\n";
        s += "        _MEM_COMMIT = 0x1000\n";
        s += "        _PAGE_EXECUTE_READWRITE = 0x40\n";
        s += "        _MEM_PRIVATE = 0x20000\n";
        s += "        _SI = _CT.c_void_p(0)\n";
        s += "        _ADDR = 0x10000\n";
        s += "        _WX_COUNT = 0\n";
        s += "        _PRIV_WX = 0\n";
        s += "        while _ADDR < 0x7FFFFFFF0000:\n";
        s += "            _MBI = _MEMORY_BASIC_INFORMATION()\n";
        s += "            _RET = _K32.VirtualQuery(_ADDR, _CT.byref(_MBI), _CT.sizeof(_MBI))\n";
        s += "            if _RET == 0:\n";
        s += "                _ADDR += 0x10000\n";
        s += "                continue\n";
        s += "            if _MBI.State == _MEM_COMMIT and _MBI.Protect == _PAGE_EXECUTE_READWRITE:\n";
        s += "                _WX_COUNT += 1\n";
        s += "                if _MBI.Type == _MEM_PRIVATE:\n";
        s += "                    _PRIV_WX += 1\n";
        s += "                    if _MBI.RegionSize > 1048576:\n";
        s += "                        _SYS.stderr.write('error: large private WX region detected\\n'); _SYS.exit(1)\n";
        s += "            _ADDR += _MBI.RegionSize\n";
        s += "        if _PRIV_WX > 2 or _WX_COUNT > 10:\n";
        s += "            _SYS.stderr.write('error: suspicious memory regions detected\\n'); _SYS.exit(1)\n";
        s += "    except: pass\n";
    }

    /* Meta path check */
    s += "if len(_SYS.meta_path) > 5:\n";
    s += "    _SYS.stderr.write('error: import hook detected\\n'); _SYS.exit(1)\n";

    /* ── Timing analysis detect ── */
    s += "try:\n";
    s += "    import time as _T\n";
    s += "    _T1 = _T.perf_counter()\n";
    s += "    _ = [i for i in range(1000)]\n";
    s += "    _T2 = _T.perf_counter()\n";
    s += "    if _T2 - _T1 > 5.0:\n";
    s += "        _SYS.stderr.write('error: slowdown detected\\n'); _SYS.exit(1)\n";
    s += "except: pass\n";

    /* ── Frame depth check (detect inspection via sys._getframe) ── */
    s += "try:\n";
    s += "    _G = _SYS._getframe\n";
    s += "    _FD = 0\n";
    s += "    _F = _G()\n";
    s += "    while _F:\n";
    s += "        _FD += 1\n";
    s += "        if _FD > 50:\n";
    s += "            _SYS.stderr.write('error: deep frame inspection detected\\n'); _SYS.exit(1)\n";
    s += "        _F = _F.f_back\n";
    s += "except: pass\n";

    /* ── sys.settrace override: forcefully clear any active tracer ── */
    s += "_SYS.settrace(None)\n";
    s += "_SYS.setprofile(None)\n";

    /* ── Exception hook integrity ── */
    s += "try:\n";
    s += "    _EH = type(getattr(_SYS, 'excepthook', None))\n";
    s += "    if _EH.__name__ != 'builtin_function_or_method':\n";
    s += "        _SYS.stderr.write('error: exception hook tampered\\n'); _SYS.exit(1)\n";
    s += "    _UH = type(getattr(_SYS, 'unraisablehook', None))\n";
    s += "    if _UH.__name__ != 'builtin_function_or_method':\n";
    s += "        _SYS.stderr.write('error: unraisable hook tampered\\n'); _SYS.exit(1)\n";
    s += "except: pass\n";

    /* ── Audit hook detection via public API ── */
    s += "try:\n";
    s += "    _AH = _SYS.getaudithook()\n";
    s += "    if _AH is not None:\n";
    s += "        _SYS.stderr.write('error: audit hook detected\\n'); _SYS.exit(1)\n";
    s += "except: pass\n";

    /* ── GC object scan for debugger objects ── */
    s += "try:\n";
    s += "    import gc as _GC\n";
    s += "    for _O in _GC.get_objects():\n";
    s += "        _TN = type(_O).__name__\n";
    s += "        if _TN in ('PyDevdFrame','Debugger','Tracer','Profiler'):\n";
    s += "            _SYS.stderr.write('error: debugger object detected\\n'); _SYS.exit(1)\n";
    s += "except: pass\n";

    /* ── Source inspection detection ── */
    s += "try:\n";
    s += "    import inspect as _INS\n";
    s += "except: pass\n";

    /* ── PyDevd port scan (default 5678) ── */
    s += "try:\n";
    s += "    import socket as _SK\n";
    s += "    _S2 = _SK.socket(_SK.AF_INET, _SK.SOCK_STREAM)\n";
    s += "    _S2.settimeout(1.0)\n";
    s += "    if _S2.connect_ex(('127.0.0.1', 5678)) == 0:\n";
    s += "        _S2.close()\n";
    s += "        _SYS.stderr.write('error: debugger port detected\\n'); _SYS.exit(1)\n";
    s += "    _S2.close()\n";
    s += "except: pass\n";

    if (include_vm_check) {
        s += "if getattr(_SYS, 'flags', None) and _SYS.flags.no_user_site:\n";
        s += "    _SYS.stderr.write('error: sandbox detected\\n'); _SYS.exit(1)\n";
        
        s += "if _IS_MACOS:\n";
        s += "    if any(x in str(_PLATFORM.platform()) for x in ['vmware','virtualbox','qemu','parallels']):\n";
        s += "        _SYS.stderr.write('error: VM detected\\n'); _SYS.exit(1)\n";
        
        s += "if _IS_LINUX:\n";
        s += "    if any(x in str(_PLATFORM.platform()) for x in ['vmware','virtualbox','qemu']):\n";
        s += "        _SYS.stderr.write('error: VM detected\\n'); _SYS.exit(1)\n";
        s += "    try:\n";
        s += "        with open('/proc/1/cgroup') as _F:\n";
        s += "            if any('docker' in _L or 'kubepods' in _L for _L in _F):\n";
        s += "                _SYS.stderr.write('error: container detected\\n'); _SYS.exit(1)\n";
        s += "    except: pass\n";
        s += "    if _OS.path.exists('/.dockerenv'):\n";
        s += "        _SYS.stderr.write('error: container detected\\n'); _SYS.exit(1)\n";
        
        s += "if _IS_WINDOWS:\n";
        s += "    try:\n";
        s += "        if _OS.path.exists('C:\\\\windows\\\\system32\\\\wine'):\n";
        s += "            _SYS.stderr.write('error: Wine detected\\n'); _SYS.exit(1)\n";
        s += "    except: pass\n";
        s += "    if _PLATFORM.system() == 'Windows' and _OS.environ.get('WINELOADER'):\n";
        s += "        _SYS.stderr.write('error: Wine detected\\n'); _SYS.exit(1)\n";
    }

    return strdup(s.c_str());
}