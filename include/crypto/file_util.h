#ifndef CRYPTO_FILE_UTIL_H
#define CRYPTO_FILE_UTIL_H

#include "crypto/common.h"
#include <stdio.h>

typedef struct {
    unsigned char *data;
    size_t         size;
} FileBuffer;

ExitCode file_read(const char *path, FileBuffer *buf);
ExitCode file_write(const char *path, const unsigned char *data, size_t size);
void     file_buffer_free(FileBuffer *buf);

/* Secure temporary directory helpers — avoids TOCTOU in /tmp */
/* Create a private temp directory (mode 0700). Caller must free() the path. */
char   *tmpdir_create(void);
/* Remove a temp directory and all files inside it. dir_path is freed. */
void    tmpdir_destroy(char *dir_path);
/* Build full path: dir_path + "/" + name. Caller must free() the result. */
char   *tmpdir_path(const char *dir_path, const char *name);

#endif
