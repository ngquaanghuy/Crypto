#include "crypto/file_util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

ExitCode file_read(const char *path, FileBuffer *buf) {
    buf->data = NULL;
    buf->size = 0;

    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "error: cannot open '%s'\n", path);
        return EXIT_ERR_FILE;
    }

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);

    if (sz <= 0) {
        fclose(f);
        fprintf(stderr, "error: '%s' is empty\n", path);
        return EXIT_ERR_FILE;
    }

    buf->data = (unsigned char *)malloc((size_t)sz);
    if (!buf->data) {
        fclose(f);
        fprintf(stderr, "error: out of memory\n");
        return EXIT_ERR_CRYPTO;
    }

    size_t nread = fread(buf->data, 1, (size_t)sz, f);
    fclose(f);

    if ((long)nread != sz) {
        free(buf->data);
        buf->data = NULL;
        fprintf(stderr, "error: failed to read '%s'\n", path);
        return EXIT_ERR_FILE;
    }

    buf->size = (size_t)sz;
    return EXIT_OK;
}

ExitCode file_write(const char *path, const unsigned char *data, size_t size) {
    FILE *f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "error: cannot write '%s'\n", path);
        return EXIT_ERR_FILE;
    }

    size_t nwritten = fwrite(data, 1, size, f);
    fclose(f);

    if (nwritten != size) {
        fprintf(stderr, "error: failed to write '%s'\n", path);
        return EXIT_ERR_FILE;
    }

    return EXIT_OK;
}

void file_buffer_free(FileBuffer *buf) {
    if (buf && buf->data) {
        free(buf->data);
        buf->data = NULL;
        buf->size = 0;
    }
}
