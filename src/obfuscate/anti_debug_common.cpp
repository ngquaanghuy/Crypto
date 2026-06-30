#include "crypto/obfuscate.h"
#include "anti_debug_internal.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>

namespace antidebug {

sigjmp_buf g_safe_read_jump;
volatile sig_atomic_t g_safe_read_jump_set = 0;

static void safe_read_sigsegv_handler(int) {
    if (g_safe_read_jump_set) siglongjmp(g_safe_read_jump, 1);
}

ssize_t safe_pread(int fd, void *buf, size_t count, off_t offset) {
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
        g_safe_read_jump_set = 0;
        errno = EFAULT;
        result = -1;
    }

    sigaction(SIGSEGV, &old_sa, nullptr);
    return result;
}

int is_valid_user_address(unsigned long addr) {
    if (addr == 0 || addr == (unsigned long)-1) return 0;
#if defined(__x86_64__) || defined(_WIN64)
    if (addr >= 0x800000000000UL) return 0;
    if (addr < 0x10000) return 0;
#else
    if (addr == 0) return 0;
#endif
    return 1;
}

#if defined(PLATFORM_LINUX)
int read_proc_self_line(const char *file, char *buf, size_t bufsz) {
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

}
