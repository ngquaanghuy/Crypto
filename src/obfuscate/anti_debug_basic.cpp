#include "crypto/obfuscate.h"
#include "anti_debug_internal.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>

using namespace antidebug;

int anti_debug_check_timing(void) {
#if defined(__x86_64__) || defined(__i386__)
    uint64_t t1, t2;
    uint32_t eax, ebx, ecx, edx;
    eax = 0;
    __asm__ volatile(
        "cpuid\n\t"
        "rdtsc\n\t"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(eax)
    );
    t1 = ((uint64_t)edx << 32) | (uint64_t)eax;
    
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
    
    uint64_t delta = t2 - t1;
    if (delta > 1000000ULL) return 1;
    return 0;
#else
    (void)0;
    return 0;
#endif
}


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
            if (comm[n-1] == '\n') comm[n-1] = '\0';
            static const char *bad_parents[] = {
                "gdb", "lldb", "strace", "ltrace", "perf",
                "valgrind", "rr", "callgrind", "pinbin",
                nullptr
            };
            for (int i = 0; bad_parents[i]; i++) {
                if (strcmp(comm, bad_parents[i]) == 0) return 1;
            }
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


int anti_debug_check_debugregs(void) {
#if defined(PLATFORM_LINUX)
    char buf[4096];
    if (read_proc_self_line("status", buf, sizeof(buf)) < 0) return 0;
    if (strstr(buf, "TracerPid:\t0") == nullptr) return 0;
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


int anti_debug_check_procstat(void) {
#if defined(PLATFORM_LINUX)
    char buf[1024];
    if (read_proc_self_line("stat", buf, sizeof(buf)) < 0) return 0;
    char *p = buf;
    while (*p && *p == ' ') p++;
    while (*p && *p != ' ') p++;
    while (*p && *p == ' ') p++;
    if (*p == 't') return 1;
    return 0;
#else
    (void)0;
    return 0;
#endif
}


int anti_debug_check_proc_cmdline(void) {
#if defined(PLATFORM_LINUX)
    static const char *suspicious[] = {
        "gdb", "lldb", "strace", "ltrace", "perf",
        "valgrind", "rr", "callgrind", "pinbin",
        "frida", "hyperpwn", "pwndbg", "peda", "gef",
        nullptr
    };
    char buf[1024];
    if (read_proc_self_line("cmdline", buf, sizeof(buf)) == 0) {
        for (int i = 0; suspicious[i]; i++) {
            if (strstr(buf, suspicious[i])) return 1;
        }
    }
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


int anti_debug_check_seccomp(void) {
#if defined(PLATFORM_LINUX)
    char buf[4096];
    if (read_proc_self_line("status", buf, sizeof(buf)) < 0) return 0;
    char *p = strstr(buf, "Seccomp:");
    if (p) {
        p += 8;
        while (*p == ' ' || *p == '\t') p++;
        int mode = atoi(p);
        if (mode > 0) return 1;
    }
    return 0;
#else
    (void)0;
    return 0;
#endif
}


int anti_debug_check_prctl(void) {
#if defined(PLATFORM_LINUX)
    int orig_dumpable = prctl(PR_GET_DUMPABLE);
    if (orig_dumpable == -1) return 1;

    if (prctl(PR_SET_DUMPABLE, 0) == -1) {
        if (orig_dumpable == 1) prctl(PR_SET_DUMPABLE, 1);
        return 1;
    }

    if (orig_dumpable == 1) prctl(PR_SET_DUMPABLE, 1);

    return 0;
#else
    (void)0;
    return 0;
#endif
}


int anti_debug_check_fork(void) {
#if defined(PLATFORM_LINUX)
    pid_t child = fork();
    if (child == -1) return 0;
    if (child == 0) _exit(0);
    int wstatus;
    waitpid(child, &wstatus, 0);
    return 0;
#else
    (void)0;
    return 0;
#endif
}


/* ── Tracer/Debugger Detection (platform-specific) ─────── */

#if defined(PLATFORM_WINDOWS)
int anti_debug_check_tracerpid(void) {
    return IsDebuggerPresent() ? 1 : 0;
}

namespace antidebug {

int check_remote_debugger() {
    BOOL debugger_present = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &debugger_present)) {
        return debugger_present ? 1 : 0;
    }
    return 0;
}

int check_debug_port() {
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
        7,
        &debug_port,
        sizeof(debug_port),
        nullptr
    );
    
    if (status == 0 && debug_port != 0) {
        return 1;
    }
    return 0;
}

int check_debug_flags() {
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
        31,
        &debug_flags,
        sizeof(debug_flags),
        nullptr
    );
    
    if (status == 0 && debug_flags == 0) {
        return 1;
    }
    return 0;
}

int check_debug_object() {
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
        30,
        &debug_object,
        sizeof(debug_object),
        nullptr
    );
    
    if (status == 0 && debug_object != nullptr) {
        return 1;
    }
    return 0;
}

int check_output_debug_string() {
    SetLastError(0);
    OutputDebugStringA(" ");
    return (GetLastError() != 0) ? 1 : 0;
}

} /* namespace antidebug */

#elif defined(PLATFORM_MACOS)
int anti_debug_check_tracerpid(void) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc info;
    size_t size = sizeof(info);
    
    if (sysctl(mib, 4, &info, &size, nullptr, 0) != 0) {
        return 0;
    }
    
    return (info.kp_proc.p_flag & P_TRACED) ? 1 : 0;
}

namespace antidebug {

int check_ptrace_deny_attach() {
    return ptrace(PT_DENY_ATTACH, 0, 0, 0) == -1 ? 1 : 0;
}

int check_mach_task() {
    task_t task = mach_task_self();
    task_basic_info_data_t info;
    mach_msg_type_number_t count = TASK_BASIC_INFO_COUNT;
    
    kern_return_t kr = task_info(task, TASK_BASIC_INFO, (task_info_t)&info, &count);
    if (kr != KERN_SUCCESS) {
        return 0;
    }
    
    return 0;
}

int check_loaded_modules() {
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

} /* namespace antidebug */

#elif defined(PLATFORM_LINUX)
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

int anti_debug_check_ptrace(void) {
    pid_t child = fork();
    if (child == -1) return 0;
    if (child == 0) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1)
            _exit(1);
        _exit(0);
    }
    int wstatus;
    waitpid(child, &wstatus, 0);
    if (WIFEXITED(wstatus)) {
        return WEXITSTATUS(wstatus);
    }
    return 0;
}

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

int anti_debug_check_cpuid(void) {
#if defined(__x86_64__) || defined(__i386__)
    uint32_t eax, ebx, ecx, edx;
    eax = 1;
    __asm__ volatile(
        "cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(eax)
    );
    return (ecx >> 31) & 1;
#else
    (void)0;
    return 0;
#endif
}

#else
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
