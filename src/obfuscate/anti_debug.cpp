#include "crypto/obfuscate.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cctype>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <cerrno>
#include <string>
#include <vector>
#include <algorithm>

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

/* ── Sandbox / container checks ── */
static int check_sandbox(void) {
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
}

/* ── Hook detection: verify builtins are not intercepted ── */
static int check_hooks(void) {
    /* In Python we check __import__, compile, exec.
     * In C++ we check if common functions are hooked by looking
     * for LD_PRELOAD in environment. */
    const char *ld_preload = getenv("LD_PRELOAD");
    if (ld_preload && ld_preload[0]) return 1;
    const char *ld_library_path = getenv("LD_LIBRARY_PATH");
    if (ld_library_path && ld_library_path[0]) return 1;
    return 0;
}

/* ── Combined check ── */
AntiDebugResult anti_debug_check_all(void) {
    if (anti_debug_check_tracerpid())    return ADBG_RESULT_DEBUGGER_DETECTED;
    if (anti_debug_check_ptrace())       return ADBG_RESULT_DEBUGGER_DETECTED;
    if (anti_debug_check_maps())         return ADBG_RESULT_DEBUGGER_DETECTED;
    if (anti_debug_check_cpuid())        return ADBG_RESULT_VM_DETECTED;
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

    /* TracerPid check */
    s += "try:\n";
    s += "    with open('/proc/self/status') as _F:\n";
    s += "        for _L in _F:\n";
    s += "            if 'TracerPid:' in _L:\n";
    s += "                if _L.split(':')[1].strip() != '0':\n";
    s += "                    _SYS.stderr.write('error: debugger detected\\n'); _SYS.exit(1)\n";
    s += "except: pass\n";

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
    }

    /* Meta path check */
    s += "if len(_SYS.meta_path) > 5:\n";
    s += "    _SYS.stderr.write('error: import hook detected\\n'); _SYS.exit(1)\n";

    if (include_vm_check) {
        s += "if getattr(_SYS, 'flags', None) and _SYS.flags.no_user_site:\n";
        s += "    _SYS.stderr.write('error: sandbox detected\\n'); _SYS.exit(1)\n";
        s += "if any(x in str(_SYS.platform) for x in ['vmware','virtualbox','qemu']):\n";
        s += "    _SYS.stderr.write('error: VM detected\\n'); _SYS.exit(1)\n";
        s += "try:\n";
        s += "    with open('/proc/1/cgroup') as _F:\n";
        s += "        if any('docker' in _L or 'kubepods' in _L for _L in _F):\n";
        s += "            _SYS.stderr.write('error: container detected\\n'); _SYS.exit(1)\n";
        s += "except: pass\n";
        s += "if _OS.path.exists('/.dockerenv'):\n";
        s += "    _SYS.stderr.write('error: container detected\\n'); _SYS.exit(1)\n";
    }

    return strdup(s.c_str());
}