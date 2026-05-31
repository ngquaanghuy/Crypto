#include "crypto/obfuscate.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cctype>
#include <string>
#include <vector>
#include <algorithm>

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
    #include <mach-o/dyld.h>
#elif defined(__linux__)
    #define PLATFORM_LINUX 1
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <fcntl.h>
    #include <unistd.h>
    #include <sys/ptrace.h>
    #include <sys/wait.h>
    #include <cerrno>
#endif


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

/* ── Hook detection: verify builtins are not intercepted ── */
static int check_hooks(void) {
#if defined(PLATFORM_WINDOWS)
    /* Check for DLL injection via environment */
    const char *ld_preload = getenv("LD_PRELOAD");
    if (ld_preload && ld_preload[0]) return 1;
    
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
    
    return 0;
    
#elif defined(PLATFORM_MACOS)
    /* Check for DYLD environment variables */
    const char *dyld_preload = getenv("DYLD_INSERT_LIBRARIES");
    if (dyld_preload && dyld_preload[0]) return 1;
    
    const char *dyld_library_path = getenv("DYLD_LIBRARY_PATH");
    if (dyld_library_path && dyld_library_path[0]) return 1;
    
    const char *ld_preload = getenv("LD_PRELOAD");
    if (ld_preload && ld_preload[0]) return 1;
    
    const char *ld_library_path = getenv("LD_LIBRARY_PATH");
    if (ld_library_path && ld_library_path[0]) return 1;
    
    return 0;
    
#elif defined(PLATFORM_LINUX)
    /* In Python we check __import__, compile, exec.
     * In C++ we check if common functions are hooked by looking
     * for LD_PRELOAD in environment. */
    const char *ld_preload = getenv("LD_PRELOAD");
    if (ld_preload && ld_preload[0]) return 1;
    const char *ld_library_path = getenv("LD_LIBRARY_PATH");
    if (ld_library_path && ld_library_path[0]) return 1;
    return 0;
#else
    return 0;
#endif
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
    if (anti_debug_check_maps())         return ADBG_RESULT_DEBUGGER_DETECTED;
    if (anti_debug_check_cpuid())        return ADBG_RESULT_VM_DETECTED;
#endif
    
    if (check_sandbox())                 return ADBG_RESULT_SANDBOX_DETECTED;
    if (check_hooks())                   return ADBG_RESULT_HOOK_DETECTED;
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
    
    /* MacOS sysctl check via ctypes */
    s += "if _IS_MACOS:\n";
    s += "    try:\n";
    s += "        import ctypes as _CT\n";
    s += "        _LIBC = _CT.CDLL(None)\n";
    s += "        # KERN_PROC=14, KERN_PROC_PID=1\n";
    s += "        class KInfoProc(_CT.Structure):\n";
    s += "            _fields_ = [('kp_proc', _CT.c_int * 12)]\n";
    s += "        _INFO = KInfoProc()\n";
    s += "        _SIZE = _CT.c_size_t(_CT.sizeof(_INFO))\n";
    s += "        _MIB = (_CT.c_int * 4)(1, 14, 1, _SYS.getpid())\n";
    s += "        if _LIBC.sysctl(_MIB, 4, _CT.byref(_INFO), _CT.byref(_SIZE), None, 0) == 0:\n";
    s += "            P_TRACED = 0x800\n";
    s += "            if _INFO.kp_proc[0] & P_TRACED:\n";
    s += "                _SYS.stderr.write('error: debugger detected\\n'); _SYS.exit(1)\n";
    s += "    except: pass\n";

    /* Breakpoint hook removal */
    s += "try: _SYS.breakpointhook = None\n";
    s += "except: pass\n";

    /* Module scan for debuggers */
    s += "for _M in ('pydevd','pdb','ipdb','pdbpp','pydevconsole','trace'):\n";
    s += "    if _M in _SYS.modules:\n";
    s += "        _SYS.stderr.write('error: debugger detected\\n'); _SYS.exit(1)\n";

    if (include_hook_check) {
        s += "for _N in ('__import__','compile','exec'):\n";
        s += "    _F = getattr(_SYS.modules.get('builtins'), _N, None)\n";
        s += "    if _F is not None:\n";
        s += "        _G = getattr(_F, '__name__', '')\n";
        s += "        if _G != _N:\n";
        s += "            _SYS.stderr.write('error: hook detected\\n'); _SYS.exit(1)\n";
        
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
        
        s += "if _IS_MACOS:\n";
        s += "    if _OS.environ.get('DYLD_INSERT_LIBRARIES') or _OS.environ.get('DYLD_LIBRARY_PATH'):\n";
        s += "        _SYS.stderr.write('error: DYLD injection detected\\n'); _SYS.exit(1)\n";
    }

    /* Meta path check */
    s += "if len(_SYS.meta_path) > 5:\n";
    s += "    _SYS.stderr.write('error: import hook detected\\n'); _SYS.exit(1)\n";

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