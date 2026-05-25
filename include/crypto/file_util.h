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

#endif
