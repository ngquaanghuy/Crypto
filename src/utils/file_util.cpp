#include "crypto/file_util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/types.h>

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

/* Secure file write: prevents race conditions and symlink attacks
 *
 * Security measures:
 * 1. O_EXCL: ensures file doesn't already exist (no TOCTOU race)
 * 2. O_NOFOLLOW: prevents symlink attacks
 * 3. 0xxx permissions: only owner can access
 * 4. Ownership check: verify file is owned by current user
 *
 * Use this for files that will be executed. */
ExitCode file_write_secure(const char *path, const unsigned char *data, size_t size) {
    /* Use open() with secure flags */
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) {
        if (errno == EEXIST) {
            fprintf(stderr, "error: path already exists (potential symlink attack): %s\n", path);
        } else if (errno == ELOOP) {
            fprintf(stderr, "error: symlink in path: %s\n", path);
        } else {
            fprintf(stderr, "error: cannot create '%s'\n", path);
        }
        return EXIT_ERR_FILE;
    }

    ssize_t written = write(fd, data, size);
    int save_errno = errno;
    close(fd);

    if (written != (ssize_t)size) {
        fprintf(stderr, "error: failed to write '%s'\n", path);
        unlink(path);
        return EXIT_ERR_FILE;
    }

    /* Verify ownership - file should be owned by current user
     * This prevents an attacker from creating a symlink before us */
    struct stat st;
    if (stat(path, &st) == 0) {
        if (st.st_uid != getuid()) {
            fprintf(stderr, "error: file ownership mismatch: %s\n", path);
            unlink(path);
            return EXIT_ERR_FILE;
        }
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
