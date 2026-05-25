#include "encode/hexcode.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char TBL_HEX[] = "0123456789abcdef";

static signed char TBL_DECODE[256] = {0};

static void init_tbl(void) {
    static int done = 0;
    if (done) return;
    for (int i = 0; i < 256; i++) TBL_DECODE[i] = -1;
    for (int i = 0; i < 10; i++) TBL_DECODE['0' + i] = i;
    for (int i = 0; i < 6; i++) {
        TBL_DECODE['a' + i] = 10 + i;
        TBL_DECODE['A' + i] = 10 + i;
    }
    done = 1;
}

ExitCode hex_encode(const unsigned char *in, size_t in_size, Buffer *out) {
    if (!in || !out || in_size == 0) return EXIT_ERR_INTERNAL;

    size_t out_size = in_size * 2 + 1;
    out->data = (unsigned char *)malloc(out_size);
    if (!out->data) return EXIT_ERR_CRYPTO;

    for (size_t i = 0; i < in_size; i++) {
        out->data[i * 2]     = TBL_HEX[(in[i] >> 4) & 0x0F];
        out->data[i * 2 + 1] = TBL_HEX[in[i] & 0x0F];
    }
    out->data[out_size - 1] = '\0';
    out->size = out_size - 1;
    return EXIT_OK;
}

ExitCode hex_decode(const unsigned char *in, size_t in_size, Buffer *out) {
    if (!in || !out || in_size == 0) return EXIT_ERR_INTERNAL;
    init_tbl();

    if (in_size % 2 != 0) {
        fprintf(stderr, "error: hex string length must be even\n");
        return EXIT_ERR_CRYPTO;
    }

    size_t out_size = in_size / 2 + 1;
    out->data = (unsigned char *)malloc(out_size);
    if (!out->data) return EXIT_ERR_CRYPTO;

    for (size_t i = 0; i < in_size; i += 2) {
        signed char hi = TBL_DECODE[in[i]];
        signed char lo = TBL_DECODE[in[i + 1]];
        if (hi < 0 || lo < 0) {
            free(out->data);
            out->data = NULL;
            fprintf(stderr, "error: invalid hex character\n");
            return EXIT_ERR_CRYPTO;
        }
        out->data[i / 2] = (unsigned char)((hi << 4) | lo);
    }
    out->size = out_size - 1;
    return EXIT_OK;
}
