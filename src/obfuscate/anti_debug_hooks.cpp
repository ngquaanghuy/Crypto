#include "crypto/obfuscate.h"
#include "anti_debug_internal.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <vector>
#include <algorithm>

using namespace antidebug;

/* ── Sandbox / container checks ── */
int antidebug::check_sandbox(void) {
#if defined(PLATFORM_WINDOWS)
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll) {
        FARPROC wine_get_version = GetProcAddress(hNtdll, "wine_get_version");
        if (wine_get_version) return 1;
    }
    
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
    
    if (GetTickCount() < 300000) {
        return 1;
    }
    
    return 0;
    
#elif defined(PLATFORM_MACOS)
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
    
    const char *container_home = getenv("APP_CONTAINER_HOME");
    if (container_home) return 1;
    
    struct stat st;
    if (stat("/Applications/VirtualBox.app", &st) == 0) return 1;
    if (stat("/Applications/VMware Fusion.app", &st) == 0) return 1;
    
    return 0;
    
#elif defined(PLATFORM_LINUX)
    struct stat st;
    if (stat("/.dockerenv", &st) == 0) return 1;
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
                if (strstr(line, "[heap]") || strstr(line, "[stack]")) continue;
                fclose(fp);
                return 1;
            }
        }
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


int antidebug::check_hooks(void) {
    if (check_hooks_env()) return 1;
    if (check_maps_for_hooks()) return 1;
    
#if defined(PLATFORM_WINDOWS)
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
    
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs",
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char value[256];
        DWORD size = sizeof(value);
        DWORD type;
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


int anti_debug_check_inline_hooks(void) {
#if defined(PLATFORM_LINUX)
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    char line[1024];
    char last_path[256] = {0};

    while (fgets(line, sizeof(line), fp)) {
        if (!strstr(line, " r-xp ") || strstr(line, "[vdso]") ||
            strstr(line, "[vvar]") || strstr(line, "[vsyscall]"))
            continue;

        char *path_start = strchr(line, '/');
        if (!path_start) continue;

        if (strcmp(path_start, last_path) == 0) continue;
        strncpy(last_path, path_start, sizeof(last_path) - 1);
        last_path[sizeof(last_path) - 1] = '\0';

        if (strstr(line, "[heap]") || strstr(line, "[stack]") ||
            strstr(line, "[anon_") || strstr(line, "[stack:"))
            continue;

        unsigned long start_addr = strtoul(line, nullptr, 16);
        if (!start_addr || !is_valid_user_address(start_addr)) continue;

        int fd = open("/proc/self/mem", O_RDONLY);
        if (fd < 0) continue;

        unsigned char buf[64];
        ssize_t bytes_read = safe_pread(fd, buf, sizeof(buf), start_addr);

        if (bytes_read < 12) { close(fd); continue; }

        for (int i = 0; i < bytes_read - 11; i++) {
            if (buf[i] == 0x48 && buf[i+1] == 0xB8 && buf[i+10] == 0xFF && buf[i+11] == 0xD0) {
                close(fd);
                fclose(fp);
                return 1;
            }

            if (buf[i] == 0xFF && (buf[i+1] == 0x35 || buf[i+1] == 0x25) && buf[i+6] == 0xC3) {
                close(fd);
                fclose(fp);
                return 1;
            }

            if (buf[i] == 0x68 && buf[i+5] == 0xC3) {
                unsigned char *next = (unsigned char *)((unsigned long)start_addr + i + 5 + 1);
                unsigned char tmp[2];
                ssize_t next_bytes = safe_pread(fd, tmp, 2, (off_t)next);
                if (next_bytes == 2 && tmp[0] == 0xC3) {
                    close(fd);
                    fclose(fp);
                    return 1;
                }
            }

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
    uint32_t image_count = _dyld_image_count();
    if (image_count == 0) return 0;

    task_t self_task = mach_task_self();

    for (uint32_t i = 0; i < image_count; i++) {
        const mach_header *header = _dyld_get_image_header(i);
        if (!header) continue;

        const char *name = _dyld_get_image_name(i);
        if (!name) continue;

        if (strstr(name, "/dyld") || strstr(name, "/libdyld.dylib"))
            continue;

        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        if (slide == 0 && header != _dyld_get_image_header(0)) {
            if (i > 0) continue;
        }

        uint64_t text_start = (uint64_t)header + slide;
        uint64_t text_size = 4096;

        vm_offset_t data_ptr;
        mach_msg_type_number_t bytes_read = 0;
        kern_return_t kr = mach_vm_read(self_task, text_start, text_size, &data_ptr, &bytes_read);

        if (kr != KERN_SUCCESS || bytes_read < 16) continue;

        unsigned char *buf = (unsigned char *)data_ptr;
        for (mach_msg_type_number_t j = 0; j < bytes_read - 15; j++) {
            if (buf[j] == 0x48 && buf[j+1] == 0xB8 && buf[j+10] == 0xFF && buf[j+11] == 0xD0) {
                vm_deallocate(self_task, data_ptr, bytes_read);
                return 1;
            }
            if (buf[j] == 0xFF && (buf[j+1] == 0x35 || buf[j+1] == 0x25) && buf[j+6] == 0xC3) {
                vm_deallocate(self_task, data_ptr, bytes_read);
                return 1;
            }
            if (buf[j] == 0x68 && buf[j+5] == 0xC3) {
                vm_deallocate(self_task, data_ptr, bytes_read);
                return 1;
            }
            if ((buf[j] & 0xFF) == 0xFF && (buf[j+1] & 0x38) == 0x20) {
                vm_deallocate(self_task, data_ptr, bytes_read);
                return 1;
            }
            if (buf[j] == 0xE9) {
                vm_deallocate(self_task, data_ptr, bytes_read);
                return 1;
            }
            if (buf[j] == 0x48 && buf[j+1] == 0x89 && buf[j+2] == 0xFE && buf[j+3] == 0xFF && buf[j+4] == 0xE0) {
                vm_deallocate(self_task, data_ptr, bytes_read);
                return 1;
            }
        }

        vm_deallocate(self_task, data_ptr, bytes_read);
    }
    return 0;
#elif defined(PLATFORM_WINDOWS)
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
                if (p[0] == 0x48 && p[1] == 0xB8 && p[10] == 0xFF && p[11] == 0xD0)
                    return 1;
                
                if (p[0] == 0xFF && p[1] == 0x25 && p[6] == 0x48)
                    continue;
                
                if (p[0] == 0x68 && p[5] == 0xC3)
                    return 1;
                
                if (p[0] == 0xEB && p[5] == 0xC3)
                    return 1;
                    
                if (p[0] == 0xE9)
                    return 1;
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                continue;
            }
        }
    }
    return 0;
#else
    return 0;
#endif
}


int anti_debug_check_plt_hooks(void) {
#if defined(PLATFORM_LINUX)
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    char line[1024];
    char last_lib[256] = {0};

    while (fgets(line, sizeof(line), fp)) {
        if (!strstr(line, " rw-p ") && !strstr(line, " rwxp ")) continue;

        char *path = strchr(line, '/');
        if (!path) continue;

        if (strstr(line, "[heap]") || strstr(line, "[stack]") ||
            strstr(line, "[anon_") || strstr(line, "]"))
            continue;

        if (strncmp(path, "/lib", 4) != 0 && strncmp(path, "/usr/lib", 8) != 0)
            continue;

        unsigned long start, end;
        if (sscanf(line, "%lx-%lx", &start, &end) != 2) continue;

        size_t seg_size = end - start;
        if (seg_size < 8 || seg_size > 16*1024*1024) continue;
        if (!is_valid_user_address(start)) continue;

        int fd = open("/proc/self/mem", O_RDONLY);
        if (fd < 0) continue;

        unsigned char *buf = (unsigned char *)malloc(4096);
        if (!buf) { close(fd); continue; }

        ssize_t n = safe_pread(fd, buf, 4096, start);
        close(fd);

        if (n > 0) {
            for (ssize_t i = 0; i < n - 8; i += 8) {
                unsigned long ptr = *(unsigned long *)(buf + i);

                if (ptr < 0x10000 || ptr > 0x7FFFFFFFFFFF) continue;

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
    uint32_t image_count = _dyld_image_count();
    if (image_count == 0) return 0;

    task_t self_task = mach_task_self();

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
        info.size = 16 * 1024;

        if (info.name) dylibs.push_back(info);
    }

    for (uint32_t i = 0; i < image_count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;

        if (strstr(name, "/tmp/") || strstr(name, "/var/folders/") ||
            strstr(name, ".hook") || strstr(name, "_hook") ||
            strstr(name, "injected") || strstr(name, "Injected") ||
            strstr(name, "frida") || strstr(name, "Frida")) {
            return 1;
        }
    }

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
                if (info.protection & VM_PROT_WRITE && info.protection & VM_PROT_EXECUTE) {
                    if (info.shared == 0) {
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
    static const char *modules_to_check[] = {
        "kernel32.dll", "ntdll.dll", "user32.dll", "ws2_32.dll", nullptr
    };
    
    for (int mi = 0; modules_to_check[mi]; mi++) {
        HMODULE hMod = GetModuleHandleA(modules_to_check[mi]);
        if (!hMod) continue;
        
        IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)hMod;
        IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)((BYTE *)hMod + dos->e_lfanew);
        
        IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
        for (WORD si = 0; si < nt->FileHeader.NumberOfSections; si++) {
            if (!(sec[si].Characteristics & IMAGE_SCN_MEM_WRITE))
                continue;
            
            BYTE *secStart = (BYTE *)hMod + sec[si].VirtualAddress;
            DWORD secSize = min(sec[si].SizeOfRawData, 4096u);
            if (secSize < 8) continue;
            
            __try {
                for (DWORD off = 0; off < secSize - sizeof(void *); off += sizeof(void *)) {
                    void *ptr = *(void **)(secStart + off);
                    if ((uintptr_t)ptr < 0x10000) continue;
                    
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
    return 1;
#else
    return 0;
#endif
}


int anti_debug_check_syscall_hooks(void) {
#if defined(PLATFORM_LINUX)
    void *libc_handle = dlopen("libc.so.6", RTLD_NOLOAD);
    if (!libc_handle) return 0;

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

        if (!is_valid_user_address((unsigned long)func_addr)) continue;

        unsigned char buf[16];
        ssize_t n = safe_pread(fd, buf, sizeof(buf), (off_t)func_addr);

        if (n < 8) continue;

        for (int j = 0; j < n - 7; j++) {
            if (buf[j] == 0x48 && buf[j+1] == 0xB8 &&
                buf[j+10] == 0xFF && buf[j+11] == 0xD0) {
                hooked = 1;
                break;
            }

            if (buf[j] == 0x55 && buf[j+1] == 0x48 && buf[j+2] == 0x89 &&
                buf[j+3] == 0xE5 && buf[j+4] == 0x90) {
                break;
            }

            if (buf[j] == 0x55 && buf[j+1] == 0x48 && buf[j+2] == 0x89 &&
                buf[j+3] == 0xE5) {
                break;
            }

            if (buf[j] == 0x55 && buf[j+1] == 0x89 && buf[j+2] == 0xE5) {
                break;
            }

            if (j == n - 8) {
                int all_nops = 1;
                for (int k = 0; k < n; k++) {
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

    close(fd);
    dlclose(libc_handle);
    return hooked;
#elif defined(PLATFORM_MACOS)
    void *libc_handle = dlopen("libSystem.B.dylib", RTLD_NOLOAD);
    if (!libc_handle) {
        libc_handle = dlopen("libSystem.dylib", RTLD_NOLOAD);
    }
    if (!libc_handle) return 0;

    task_t self_task = mach_task_self();

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

        unsigned char buf[16];
        vm_size_t bytes_read = 0;
        kern_return_t kr = mach_vm_read(self_task, (uint64_t)func_addr, 16, (vm_offset_t *)buf, &bytes_read);

        if (kr != KERN_SUCCESS || bytes_read < 8) continue;

        for (int j = 0; j < bytes_read - 7; j++) {
            if (buf[j] == 0x48 && buf[j+1] == 0xB8 &&
                buf[j+10] == 0xFF && buf[j+11] == 0xD0) {
                hooked = 1;
                break;
            }

            if (buf[j] == 0x55 && buf[j+1] == 0x48 && buf[j+2] == 0x89 &&
                buf[j+3] == 0xE5) {
                break;
            }

            if (buf[j] == 0x55 && buf[j+1] == 0x48 && buf[j+2] == 0x89 &&
                buf[j+3] == 0xE5 && buf[j+4] == 0x90) {
                break;
            }

            if (buf[j] == 0x55 && buf[j+1] == 0x89 && buf[j+2] == 0xE5) {
                break;
            }

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
            if (p[0] == 0x48 && p[1] == 0xB8 && p[10] == 0xFF && p[11] == 0xD0)
                return 1;
            
            if (p[0] == 0xE9)
                return 1;
            
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


int anti_debug_check_memory_integrity(void) {
#if defined(PLATFORM_LINUX)
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    char line[1024];
    int wx_regions = 0;
    int private_wx_count = 0;

    while (fgets(line, sizeof(line), fp)) {
        char perms[5] = "";
        unsigned long start, end;
        char pathname[256] = "";

        if (sscanf(line, "%lx-%lx %4s %*s %*s %*s %*s %255[^\n]",
                   &start, &end, perms, pathname) < 3)
            continue;

        if (strchr(perms, 'w') && strchr(perms, 'x')) {
            wx_regions++;

            if (!pathname[0] || strstr(pathname, "[anon") || strstr(pathname, "[heap]")) {
                private_wx_count++;
            }
        }

        if (strchr(perms, 'x') && (!pathname[0] || strstr(pathname, "[anon"))) {
            if (!strstr(line, "[vdso]") && !strstr(line, "[vvar]") &&
                !strstr(line, "[vsyscall]")) {
                size_t size = end - start;
                if (size > 1024 * 1024) {
                    fclose(fp);
                    return 1;
                }
            }
        }
    }
    fclose(fp);

    if (private_wx_count > 2) return 1;
    if (wx_regions > 10) return 1;

#elif defined(PLATFORM_MACOS)
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

        if (info.protection & VM_PROT_WRITE && info.protection & VM_PROT_EXECUTE) {
            wx_regions++;

            if (info.shared == 0) {
                private_wx_count++;
            }
        }

        addr += size;
        if (addr >= (uint64_t)0x7FFFFFFF0000) break;
    }

    if (private_wx_count > 2) return 1;
    if (wx_regions > 15) return 1;

#elif defined(PLATFORM_WINDOWS)
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    
    BYTE *addr = (BYTE *)si.lpMinimumApplicationAddress;
    BYTE *maxAddr = (BYTE *)si.lpMaximumApplicationAddress;
    
    int wx_regions = 0;
    int private_wx = 0;
    
    while (addr < maxAddr) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0) {
            addr += 0x10000;
            continue;
        }
        
        if (mbi.State == MEM_COMMIT) {
            DWORD prot = mbi.Protect & 0xFF;
            
            if (prot == PAGE_EXECUTE_READWRITE) {
                wx_regions++;
                
                if (mbi.Type == MEM_PRIVATE) {
                    private_wx++;
                    if (mbi.RegionSize > 1024 * 1024)
                        return 1;
                }
            }
        }
        
        addr += mbi.RegionSize;
    }
    
    if (private_wx > 2) return 1;
    if (wx_regions > 10) return 1;
#endif
    return 0;
}


AntiDebugResult anti_debug_check_all(void) {
    if (anti_debug_check_tracerpid())    return ADBG_RESULT_DEBUGGER_DETECTED;
    
#if defined(PLATFORM_WINDOWS)
    if (antidebug::check_remote_debugger()) return ADBG_RESULT_DEBUGGER_DETECTED;
    if (antidebug::check_debug_port())      return ADBG_RESULT_DEBUGGER_DETECTED;
    if (antidebug::check_debug_flags())      return ADBG_RESULT_DEBUGGER_DETECTED;
    if (antidebug::check_debug_object())    return ADBG_RESULT_DEBUGGER_DETECTED;
    if (antidebug::check_output_debug_string()) return ADBG_RESULT_DEBUGGER_DETECTED;
#elif defined(PLATFORM_MACOS)
    if (antidebug::check_ptrace_deny_attach()) return ADBG_RESULT_DEBUGGER_DETECTED;
    if (antidebug::check_mach_task())          return ADBG_RESULT_DEBUGGER_DETECTED;
    if (antidebug::check_loaded_modules())     return ADBG_RESULT_DEBUGGER_DETECTED;
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
    
    if (antidebug::check_sandbox())                 return ADBG_RESULT_SANDBOX_DETECTED;
    if (antidebug::check_hooks())                   return ADBG_RESULT_HOOK_DETECTED;

#if defined(PLATFORM_LINUX) || defined(PLATFORM_WINDOWS) || defined(PLATFORM_MACOS)
    if (anti_debug_check_inline_hooks())      return ADBG_RESULT_HOOK_DETECTED;
    if (anti_debug_check_plt_hooks())         return ADBG_RESULT_HOOK_DETECTED;
    if (anti_debug_check_syscall_hooks())     return ADBG_RESULT_HOOK_DETECTED;
    if (anti_debug_check_memory_integrity()) return ADBG_RESULT_HOOK_DETECTED;
#endif

    return ADBG_RESULT_CLEAN;
}
