#include "encode/base64.h"
#include <stdlib.h>
#include <string.h>

static const char TBL_ENCODE[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

static signed char TBL_DECODE[256] = {0};

static void init_tbl(void) {
    static int done = 0;
    if (done) return;
    for (int i = 0; i < 256; i++) TBL_DECODE[i] = -1;
    for (int i = 0; i < 64; i++) TBL_DECODE[(unsigned char)TBL_ENCODE[i]] = i;
    done = 1;
}

ExitCode base64_encode(const unsigned char *in, size_t in_size, Buffer *out) {
    if (!in || !out || in_size == 0) return EXIT_ERR_INTERNAL;

    size_t out_size = ((in_size + 2) / 3) * 4 + 1;
    out->data = (unsigned char *)malloc(out_size);
    if (!out->data) return EXIT_ERR_CRYPTO;

    size_t i = 0, o = 0;
    while (i < in_size) {
        size_t remaining = in_size - i;
        unsigned a = in[i++];
        unsigned b = remaining > 1 ? in[i++] : 0;
        unsigned c = remaining > 2 ? in[i++] : 0;
        unsigned n = (a << 16) | (b << 8) | c;

        out->data[o++] = TBL_ENCODE[(n >> 18) & 0x3F];
        out->data[o++] = TBL_ENCODE[(n >> 12) & 0x3F];
        out->data[o++] = remaining > 1 ? TBL_ENCODE[(n >> 6) & 0x3F] : '=';
        out->data[o++] = remaining > 2 ? TBL_ENCODE[n & 0x3F] : '=';
    }
    out->data[o] = '\0';
    out->size = o;
    return EXIT_OK;
}

ExitCode base64_decode(const unsigned char *in, size_t in_size, Buffer *out) {
    if (!in || !out || in_size == 0) return EXIT_ERR_INTERNAL;
    init_tbl();

    size_t pad = 0;
    if (in_size > 0 && in[in_size - 1] == '=') pad++;
    if (in_size > 1 && in[in_size - 2] == '=') pad++;

    size_t out_size = (in_size / 4) * 3 - pad + 1;
    if (out_size == 0) { out->data = NULL; out->size = 0; return EXIT_OK; }

    out->data = (unsigned char *)malloc(out_size);
    if (!out->data) return EXIT_ERR_CRYPTO;

    size_t o = 0;
    for (size_t i = 0; i < in_size; i += 4) {
        unsigned n = 0;
        for (int j = 0; j < 4; j++) {
            signed char c = (i + j < in_size) ? TBL_DECODE[in[i + j]] : 0;
            if (c < 0) c = 0;
            n = (n << 6) | (unsigned)c;
        }
        out->data[o++] = (unsigned char)(n >> 16);
        if (i + 2 < in_size && in[i + 2] != '=') out->data[o++] = (unsigned char)(n >> 8);
        if (i + 3 < in_size && in[i + 3] != '=') out->data[o++] = (unsigned char)n;
    }
    out->size = o;
    return EXIT_OK;
}
