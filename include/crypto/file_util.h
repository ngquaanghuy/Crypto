#ifndef CRYPTO_FILE_UTIL_H
#define CRYPTO_FILE_UTIL_H

#include "crypto/common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ─── File I/O ────────────────────────────────────────────── */
ExitCode    file_read(const char *path, FileBuffer *buf);
ExitCode    file_write(const char *path, const unsigned char *data, size_t size);
void        file_buffer_free(FileBuffer *buf);

/* ─── Temp directory helpers ─────────────────────────────── */
char       *tmpdir_create(void);
void        tmpdir_destroy(char *dir_path);
char       *tmpdir_path(const char *dir_path, const char *name);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_FILE_UTIL_H */
