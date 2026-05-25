#include "encode/base32.h"
#include <stdlib.h>
#include <string.h>

static const char TBL_ENCODE[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

static signed char TBL_DECODE[256] = {0};

static void init_tbl(void) {
    static int done = 0;
    if (done) return;
    for (int i = 0; i < 256; i++) TBL_DECODE[i] = -1;
    for (int i = 0; i < 32; i++)
        TBL_DECODE[(unsigned char)TBL_ENCODE[i]] = i;
    done = 1;
}

ExitCode base32_encode(const unsigned char *in, size_t in_size, Buffer *out) {
    if (!in || !out || in_size == 0) return EXIT_ERR_INTERNAL;

    size_t groups = (in_size + 4) / 5;
    size_t out_size = groups * 8 + 1;
    out->data = (unsigned char *)malloc(out_size);
    if (!out->data) return EXIT_ERR_CRYPTO;

    size_t ip = 0, op = 0;
    while (ip < in_size) {
        int remain = (int)(in_size - ip > 5 ? 5 : in_size - ip);
        unsigned long long n = 0;
        for (int j = 0; j < 5; j++)
            n = (n << 8) | (j < remain ? in[ip++] : 0);

        int nbits = remain * 8;
        int nchars = (nbits + 4) / 5;
        for (int j = 0; j < nchars; j++)
            out->data[op++] = TBL_ENCODE[(n >> (35 - j * 5)) & 0x1F];
        for (int j = nchars; j < 8; j++)
            out->data[op++] = '=';
    }
    out->data[op] = '\0';
    out->size = op;
    return EXIT_OK;
}

ExitCode base32_decode(const unsigned char *in, size_t in_size, Buffer *out) {
    if (!in || !out || in_size == 0) return EXIT_ERR_INTERNAL;
    init_tbl();

    size_t max_out = (in_size * 5) / 8 + 8;
    out->data = (unsigned char *)malloc(max_out);
    if (!out->data) return EXIT_ERR_CRYPTO;

    size_t op = 0;
    unsigned long long buf = 0;
    int bits = 0;

    for (size_t i = 0; i < in_size; i++) {
        if (in[i] == '=') break;
        signed char c = TBL_DECODE[in[i]];
        if (c < 0) continue;

        buf = (buf << 5) | (unsigned long long)c;
        bits += 5;

        if (bits >= 8) {
            bits -= 8;
            out->data[op++] = (unsigned char)((buf >> bits) & 0xFF);
            buf &= ((1ULL << bits) - 1);
        }
    }
    out->size = op;
    return EXIT_OK;
}
