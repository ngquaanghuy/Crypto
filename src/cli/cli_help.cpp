#include "cli/cli_help.h"
#include "crypto/common.h"

#include <stdio.h>

void print_usage(void) {
    printf("Usage: crypto [options] <command> [<args>]\n");
    printf("\n");
    printf("Commands:\n");
    printf("  encode <file>       Encode Python source file\n");
    printf("  decode <file>       Decode encoded file\n");
    printf("  encrypt <file>      Encrypt Python source file\n");
    printf("  decrypt <file>      Decrypt encrypted file\n");
    printf("  protect <file>      Encrypt + package into self-decrypting Python script\n");
    printf("\n");
    printf("Options:\n");
    printf("  -a, --algorithm <algo>  Algorithm: base64, base32, base85,\n");
    printf("                          ascii85, hex, xor, rolling-xor, xor-bit-rotation,\n");
    printf("                          multi-pass-xor, prng-xor,\n");
    printf("                          aes-ecb, aes-cbc, aes-ctr, aes-gcm, chacha20,\n");
    printf("                          chacha20-poly1305, xchacha20-poly1305\n");
    printf("                          (default: aes-gcm for encrypt/protect)\n");
    printf("  -k, --key <key>         Encryption/encoding key\n");
    printf("      --keyfile <file>    Read key from file\n");
    printf("      --keyenv <var>      Read key from environment variable\n");
    printf("      --keygen [<len>]    Generate random key (default 32, max 1024)\n");
    printf("      --obf <tech>        Obfuscation techniques: rename,strings,\n");
    printf("                          vstrings,cleanup,flow,aflow,opaque,\n");
    printf("                          mutate,mba,junk,apihash,funcenc,\n");
    printf("                          rolling-xor,multi-pass-xor,prng-xor,all\n");
    printf("                          (comma-separated, protect only)\n");
    printf("\n");
    printf("      --obf-none <tech>   Enable all obfuscation EXCEPT <tech>\n");
    printf("                          (mutually exclusive with --obf)\n");
    printf("      --anti-analysis <t> Anti-analysis protection: debug,\n");
    printf("                          hook, frida, scramble, opaque, inline,\n");
    printf("                          plt, syscall, memory (comma-separated,\n");
    printf("                          protect only)\n");
    printf("      --compress <algo>   Compression algorithm: zlib, lzma, bz2,\n");
    printf("                          brotli, gzip, lz4, snappy,\n");
    printf("                          blosc (default: lz4 for protect,\n");
    printf("                          none for encode/encrypt)\n");
    printf("      --compress-level <n> Compression level (1-9, default 6)\n");
    printf("      --no-compress       Disable compression\n");
    printf("      --vm                Enable Register VM protection\n");
    printf("                          (when --vm is active, --obf all uses\n");
    printf("                          full obfuscation via code-split pipeline)\n");
    printf("      --obf-density <n>   Obfuscation density multiplier (0.0-5.0,\n");
    printf("                          default 1.0). Higher values inject more\n");
    printf("                          junk, decoys, flow blocks, and auto-enable\n");
    printf("                          anti-analysis (scramble at 0.5+, debug/hook at\n");
    printf("                          1.0+, opaque at 1.5+) (protect only)\n");
    printf("      --vram-enable          Enable Virtual RAM (XOR-garbled scratch memory)\n");
    printf("      --vram-size <bytes>    Initial vRAM size in bytes (256-1048576, default 4096).\n");
    printf("                             vRAM auto-grows at runtime on out-of-bounds writes.\n");
    printf("      --vram-auto            Auto-configure vRAM size based on instruction count.\n");
    printf("      --vram-garble          Enable periodic vRAM re-key (only with --vram-enable)\n");
    printf("      --vram-garble-interval <min>-<max>\n");
    printf("                             Interval range between garbles (default 80-200)\n");
    printf("      --seed <int>        Seed for reproducible obfuscation output\n");
    printf("                          (protect only, any non-negative integer)\n");
    printf("  -o, --output <file>     Output file\n");
    printf("  -v, --version           Show version\n");
    printf("  -h, --help              Show this help\n");
    printf("\n");
    printf("Key priority: -k > --keygen > --keyfile > --keyenv > built-in default\n");
}

void print_version(void) {
    printf("%s v%s\n", CRYPTO_NAME, CRYPTO_VERSION);
}
