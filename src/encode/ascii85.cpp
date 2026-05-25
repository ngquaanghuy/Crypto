#include "encode/ascii85.h"
#include <stdlib.h>
#include <string.h>

static signed char TBL_DECODE[256] = {0};

static void init_tbl(void) {
    static int done = 0;
    if (done) return;
    for (int i = 0; i < 256; i++) TBL_DECODE[i] = -1;
    for (int i = 33; i <= 117; i++)
        TBL_DECODE[i] = (signed char)(i - 33);
    done = 1;
}

ExitCode ascii85_encode(const unsigned char *in, size_t in_size, Buffer *out) {
    if (!in || !out || in_size == 0) return EXIT_ERR_INTERNAL;

    size_t full = in_size / 4;
    size_t rem  = in_size % 4;
    size_t out_size = full * 5 + (rem > 0 ? rem + 1 : 0) + 5;
    out->data = (unsigned char *)malloc(out_size);
    if (!out->data) return EXIT_ERR_CRYPTO;

    size_t i = 0, o = 0;
    out->data[o++] = '<';
    out->data[o++] = '~';

    for (size_t g = 0; g < full; g++) {
        unsigned long n = ((unsigned long)in[i] << 24)
                        | ((unsigned long)in[i + 1] << 16)
                        | ((unsigned long)in[i + 2] << 8)
                        | in[i + 3];
        i += 4;

        if (n == 0) {
            out->data[o++] = 'z';
        } else {
            unsigned char tmp[5];
            for (int j = 4; j >= 0; j--) {
                tmp[j] = (unsigned char)(n % 85 + 33);
                n /= 85;
            }
            for (int j = 0; j < 5; j++)
                out->data[o++] = tmp[j];
        }
    }

    if (rem > 0) {
        unsigned long n = 0;
        for (size_t j = 0; j < rem; j++)
            n = (n << 8) | in[i++];

        int nchars = (int)rem + 1;
        unsigned char tmp[5];
        for (int j = nchars - 1; j >= 0; j--) {
            tmp[j] = (unsigned char)(n % 85 + 33);
            n /= 85;
        }
        for (int j = 0; j < nchars; j++)
            out->data[o++] = tmp[j];
    }

    out->data[o++] = '~';
    out->data[o++] = '>';
    out->data[o] = '\0';
    out->size = o;
    return EXIT_OK;
}

ExitCode ascii85_decode(const unsigned char *in, size_t in_size, Buffer *out) {
    if (!in || !out || in_size == 0) return EXIT_ERR_INTERNAL;
    init_tbl();

    size_t max_out = (in_size * 4) / 5 + 4;
    out->data = (unsigned char *)malloc(max_out);
    if (!out->data) return EXIT_ERR_CRYPTO;

    size_t o = 0;
    size_t i = 0;

    if (i < in_size && in[i] == '<') i++;
    if (i < in_size && in[i] == '~') i++;

    while (i < in_size) {
        if (in[i] == '~' && i + 1 < in_size && in[i + 1] == '>') break;
        if (in[i] == 'z') {
            for (int j = 0; j < 4; j++) out->data[o++] = 0;
            i++;
            continue;
        }
        if (strchr(" \t\n\r", in[i])) { i++; continue; }

        unsigned long n = 0;
        int nchars = 0;
        while (nchars < 5 && i < in_size
               && !(in[i] == '~' && i + 1 < in_size && in[i + 1] == '>')
               && !strchr(" \t\n\r", in[i])) {
            signed char c = TBL_DECODE[in[i]];
            if (c < 0) break;
            n = n * 85 + (unsigned long)c;
            i++;
            nchars++;
        }

        int nbytes = nchars - 1;
        for (int j = 0; j < nbytes; j++)
            out->data[o++] = (unsigned char)(n >> ((nbytes - 1 - j) * 8));
    }

    out->size = o;
    return EXIT_OK;
}
