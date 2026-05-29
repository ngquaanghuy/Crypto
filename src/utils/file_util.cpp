#include "crypto/file_util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>

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

char *tmpdir_create(void) {
    char tmpl[] = "/tmp/crypto_XXXXXX";
    char *dir = mkdtemp(tmpl);
    if (!dir) {
        fprintf(stderr, "error: failed to create temp directory\n");
        return NULL;
    }
    return strdup(dir);
}

void tmpdir_destroy(char *dir_path) {
    if (!dir_path) return;
    DIR *d = opendir(dir_path);
    if (d) {
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            if (e->d_name[0] == '.') continue;
            char *p = tmpdir_path(dir_path, e->d_name);
            if (p) { unlink(p); free(p); }
        }
        closedir(d);
    }
    rmdir(dir_path);
    free(dir_path);
}

char *tmpdir_path(const char *dir_path, const char *name) {
    size_t len = strlen(dir_path) + 1 + strlen(name) + 1;
    char *p = (char *)malloc(len);
    if (!p) return NULL;
    snprintf(p, len, "%s/%s", dir_path, name);
    return p;
}
