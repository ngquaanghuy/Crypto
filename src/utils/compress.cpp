#include "crypto/compress.h"
#include "crypto/file_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdint.h>

// Embedded Python script that compresses/decompresses
static const char COMPRESS_SCRIPT[] =
    "import sys, struct\n"
    "algo_id = int(sys.argv[1])\n"
    "mode = sys.argv[2]\n"
    "level = int(sys.argv[3]) if len(sys.argv) > 3 else 6\n"
    "data = sys.stdin.buffer.read()\n"
    "try:\n"
    "    if mode == 'c':\n"
    "        if algo_id == 0:\n"
    "            sys.stdout.buffer.write(data)\n"
    "        elif algo_id == 1:\n"
    "            import zlib\n"
    "            sys.stdout.buffer.write(zlib.compress(data, level))\n"
    "        elif algo_id == 2:\n"
    "            import lzma\n"
    "            sys.stdout.buffer.write(lzma.compress(data, preset=level))\n"
    "        elif algo_id == 3:\n"
    "            import bz2\n"
    "            sys.stdout.buffer.write(bz2.compress(data, level))\n"
    "        elif algo_id == 4:\n"
    "            import brotli\n"
    "            sys.stdout.buffer.write(brotli.compress(data, quality=level))\n"
    "        elif algo_id == 5:\n"
    "            import zstandard\n"
    "            sys.stdout.buffer.write(zstandard.compress(data, level))\n"
    "        elif algo_id == 6:\n"
    "            import gzip\n"
    "            sys.stdout.buffer.write(gzip.compress(data, level))\n"
    "        elif algo_id == 7:\n"
    "            import lz4.frame\n"
    "            sys.stdout.buffer.write(lz4.frame.compress(data))\n"
    "        elif algo_id == 8:\n"
    "            import snappy\n"
    "            sys.stdout.buffer.write(snappy.compress(data))\n"
    "        elif algo_id == 9:\n"
    "            import zopfli.gzip\n"
    "            sys.stdout.buffer.write(zopfli.gzip.compress(data))\n"
    "        elif algo_id == 10:\n"
    "            import blosc\n"
    "            sys.stdout.buffer.write(blosc.compress(data, level))\n"
    "        else:\n"
    "            sys.stdout.buffer.write(data)\n"
    "    else:\n"
    "        if algo_id == 0:\n"
    "            sys.stdout.buffer.write(data)\n"
    "        elif algo_id == 1:\n"
    "            import zlib\n"
    "            sys.stdout.buffer.write(zlib.decompress(data))\n"
    "        elif algo_id == 2:\n"
    "            import lzma\n"
    "            sys.stdout.buffer.write(lzma.decompress(data))\n"
    "        elif algo_id == 3:\n"
    "            import bz2\n"
    "            sys.stdout.buffer.write(bz2.decompress(data))\n"
    "        elif algo_id == 4:\n"
    "            import brotli\n"
    "            sys.stdout.buffer.write(brotli.decompress(data))\n"
    "        elif algo_id == 5:\n"
    "            import zstandard\n"
    "            sys.stdout.buffer.write(zstandard.decompress(data))\n"
    "        elif algo_id == 6:\n"
    "            import gzip\n"
    "            sys.stdout.buffer.write(gzip.decompress(data))\n"
    "        elif algo_id == 7:\n"
    "            import lz4.frame\n"
    "            sys.stdout.buffer.write(lz4.frame.decompress(data))\n"
    "        elif algo_id == 8:\n"
    "            import snappy\n"
    "            sys.stdout.buffer.write(snappy.decompress(data))\n"
    "        elif algo_id == 9:\n"
    "            import gzip\n"
    "            sys.stdout.buffer.write(zopfli.gzip.decompress(data))\n"
    "        elif algo_id == 10:\n"
    "            import blosc\n"
    "            sys.stdout.buffer.write(blosc.decompress(data))\n"
    "        else:\n"
    "            sys.stdout.buffer.write(data)\n"
    "except Exception as e:\n"
    "    sys.stdout.buffer.write(b'ERROR:' + str(e).encode())\n"
;

// Run python3 with arguments, redirecting stdio to files.
// argv must be NULL-terminated, starting with the script path.
static int run_python3(const char **argv,
                        const char *stdin_file,
                        const char *stdout_file,
                        const char *stderr_file) {
    pid_t pid = fork();
    if (pid == -1) return -1;
    if (pid == 0) {
        if (stdin_file) {
            int fd = open(stdin_file, O_RDONLY);
            if (fd >= 0) { dup2(fd, 0); close(fd); }
        }
        if (stdout_file) {
            int fd = open(stdout_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd >= 0) { dup2(fd, 1); close(fd); }
        }
        if (stderr_file) {
            int fd = open(stderr_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd >= 0) { dup2(fd, 2); close(fd); }
        }
        int argc = 0;
        while (argv[argc]) argc++;
        const char *full_argv[16];
        int i = 0;
        full_argv[i++] = "python3";
        for (int j = 0; j < argc && i < 15; j++)
            full_argv[i++] = argv[j];
        full_argv[i] = NULL;
        execvp("python3", (char *const *)full_argv);
        _exit(127);
    }
    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return -1;
}

static ExitCode run_python_compress(int algo_id, int mode, int level,
                                     const unsigned char *input, size_t input_size,
                                     Buffer *out) {
    char tmpl_script[] = "/tmp/crypto_cmp_XXXXXX.py";
    char tmpl_in[]     = "/tmp/crypto_cin_XXXXXX";
    char tmpl_out[]    = "/tmp/crypto_cout_XXXXXX";

    int fd_s = mkstemps(tmpl_script, 3);
    int fd_i = mkstemp(tmpl_in);
    int fd_o = mkstemp(tmpl_out);

    if (fd_s < 0 || fd_i < 0 || fd_o < 0) {
        if (fd_s >= 0) { close(fd_s); unlink(tmpl_script); }
        if (fd_i >= 0) { close(fd_i); unlink(tmpl_in); }
        if (fd_o >= 0) { close(fd_o); unlink(tmpl_out); }
        return EXIT_ERR_CRYPTO;
    }

    size_t slen = strlen(COMPRESS_SCRIPT);
    if (write(fd_s, COMPRESS_SCRIPT, slen) != (ssize_t)slen ||
        write(fd_i, input, input_size) != (ssize_t)input_size) {
        close(fd_s); close(fd_i); close(fd_o);
        unlink(tmpl_script); unlink(tmpl_in); unlink(tmpl_out);
        return EXIT_ERR_FILE;
    }
    close(fd_s); close(fd_i);

    // Run python3 with fork/exec (no shell)
    char mode_str[2] = {(mode == 0) ? 'c' : 'd', '\0'};
    char algo_str[16], level_str[16];
    snprintf(algo_str, sizeof(algo_str), "%d", algo_id);
    snprintf(level_str, sizeof(level_str), "%d", level);
    const char *argv[] = {tmpl_script, algo_str, mode_str, level_str, NULL};
    if (run_python3(argv, tmpl_in, tmpl_out, NULL) != 0) {
        close(fd_o); unlink(tmpl_script); unlink(tmpl_in); unlink(tmpl_out);
        return EXIT_ERR_CRYPTO;
    }

    off_t fsz = lseek(fd_o, 0, SEEK_END);
    if (fsz <= 0) {
        close(fd_o); unlink(tmpl_script); unlink(tmpl_in); unlink(tmpl_out);
        return EXIT_ERR_CRYPTO;
    }
    lseek(fd_o, 0, SEEK_SET);

    out->data = (unsigned char *)malloc((size_t)fsz);
    if (!out->data) {
        close(fd_o); unlink(tmpl_script); unlink(tmpl_in); unlink(tmpl_out);
        return EXIT_ERR_CRYPTO;
    }

    ssize_t nr = read(fd_o, out->data, (size_t)fsz);
    close(fd_o);
    unlink(tmpl_script); unlink(tmpl_in); unlink(tmpl_out);

    if (nr != fsz) { free(out->data); out->data = NULL; return EXIT_ERR_FILE; }
    out->size = (size_t)nr;

    // Check for Python error
    if (nr >= 6 && memcmp(out->data, "ERROR:", 6) == 0) {
        fprintf(stderr, "error: compression/decompression failed: %s\n", (const char *)out->data + 6);
        free(out->data); out->data = NULL;
        return EXIT_ERR_CRYPTO;
    }

    return EXIT_OK;
}

ExitCode compress_data(const unsigned char *data, size_t size,
                        int algo_id, int level, Buffer *out) {
    if (algo_id <= COMPRESS_ID_NONE || algo_id > COMPRESS_ID_BLOSC) {
        out->data = (unsigned char *)malloc(size);
        if (!out->data) return EXIT_ERR_CRYPTO;
        memcpy(out->data, data, size);
        out->size = size;
        return EXIT_OK;
    }
    return run_python_compress(algo_id, 0, level, data, size, out);
}

ExitCode decompress_data(const unsigned char *data, size_t size,
                          int algo_id, Buffer *out) {
    if (algo_id <= COMPRESS_ID_NONE || algo_id > COMPRESS_ID_BLOSC) {
        out->data = (unsigned char *)malloc(size);
        if (!out->data) return EXIT_ERR_CRYPTO;
        memcpy(out->data, data, size);
        out->size = size;
        return EXIT_OK;
    }
    return run_python_compress(algo_id, 1, 6, data, size, out);
}

const char *compress_name(int algo_id) {
    switch (algo_id) {
        case COMPRESS_ID_NONE:   return "none";
        case COMPRESS_ID_ZLIB:   return "zlib";
        case COMPRESS_ID_LZMA:   return "lzma";
        case COMPRESS_ID_BZ2:    return "bz2";
        case COMPRESS_ID_BROTLI: return "brotli";
        case COMPRESS_ID_ZSTD:   return "zstd";
        case COMPRESS_ID_GZIP:   return "gzip";
        case COMPRESS_ID_LZ4:    return "lz4";
        case COMPRESS_ID_SNAPPY: return "snappy";
        case COMPRESS_ID_ZOPFLI: return "zopfli";
        case COMPRESS_ID_BLOSC:  return "blosc";
        default:                 return "unknown";
    }
}
