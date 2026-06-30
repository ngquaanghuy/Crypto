#include "cli/protect.h"
#include "cli/protect_internal.h"
#include "crypto/file_util.h"
#include "crypto/stub.h"
#include "crypto/pyobf.h"
#include "crypto/aes.h"
#include "crypto/chacha20.h"
#include "crypto/chacha20_poly1305.h"
#include "crypto/xchacha20_poly1305.h"
#include "crypto/compress.h"
#include "encode/base64.h"
#include "encode/base32.h"
#include "encode/base85.h"
#include "encode/ascii85.h"
#include "encode/hexcode.h"
#include "encode/xorcode.h"
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <ctime>
#include <unistd.h>
#include <fcntl.h>
#include <format>
#include <string>
#include <vector>
#include <cerrno>

#ifndef CRYPTO_OBFUSCATE_VM_RUNTIME
#define VM_INTERP_MARSHAL_DUMMY 1
#endif

#include "vm/vm.h"
#include "vm/vm_interp_py.h"
#include "vm/vm_interp_py.h"
#include "vm/vm_split.h"

ExitCode protect_file(const char *input, const char *output,
                      Algorithm algo, const char *key,
                      const char *obf_techniques,
                      const char *anti_analysis,
                      int compress_algo, int compress_level,
                      int use_vm, int obf_seed,
                      float obf_density,
                      int use_vram, int use_vram_garble,
                      int vram_garble_min, int vram_garble_max,
                      int use_vram_auto, int vram_size,
                      int use_antidump) {
    int sa_id = protect::stub_algo_id(algo);
    if (sa_id < 0) {
        fprintf(stderr, "error: unsupported algorithm for protect\n");
        return EXIT_ERR_ARGS;
    }
    if (algo_needs_key(algo) && (!key || strlen(key) == 0)) {
        fprintf(stderr, "error: protect requires a non-empty key for this algorithm\n");
        return EXIT_ERR_ARGS;
    }

    // Security warning for ECB mode
    if (algo == ALGO_AES_ECB) {
        fprintf(stderr, "warning: AES-ECB mode exposes patterns in ciphertext.\n");
        fprintf(stderr, "warning: identical blocks encrypt to identical output.\n");
        fprintf(stderr, "warning: for source protection, consider aes-cbc, aes-ctr, or aes-gcm.\n");
    }

    srand((unsigned)(time(NULL) ^ (uintptr_t)sa_id ^ (uintptr_t)input ^ (uintptr_t)output));

    // Use CSPRNG for xor_byte — it affects env_hash_byte and multi-key security
    int xor_byte = protect::rand_csprng_range(1, 254);

    // Declare multi-layer key data early for VM key obfuscation scope
    protect::MultiLayerKey ml_key_data;
    const protect::MultiLayerKey *ml_key_ptr = nullptr;
    std::string vm_enc_result;  // VM key encrypted result (set in VM block, used later)

    // Pre-compute key derivation data for VM key obfuscation (needed before if(use_vm) block)
    unsigned char layer1_key[16] = {0};
    unsigned char layer1_env_byte = 0;
    bool layer1_computed = false;
    size_t key_len = key ? strlen(key) : 0;
    if (algo_needs_key(algo) && key && key_len > 0) {
        unsigned char salt[16];
        unsigned char l2[16], l3[16];
        RAND_bytes(salt, 16);
        protect::derive_sub_keys((const unsigned char *)key, key_len,
                        salt, 16,
                        layer1_key, 16, l2, 16, l3, 16);
        layer1_env_byte = protect::gen_env_hash_byte(xor_byte);
        layer1_computed = true;
    }

    // ── anti-analysis assembly (with __S__ placeholder) ──
    int use_debug = 0, use_hook = 0, use_scramble = 0, use_opaque = 0, use_frida = 0;
    int use_inline = 0, use_plt = 0, use_syscall = 0, use_mem_integrity = 0;
    if (anti_analysis && anti_analysis[0]) {
        const char *p = anti_analysis;
        while (*p) {
            while (*p == ' ' || *p == ',') p++;
            if      (strncmp(p, "debug", 5) == 0) { use_debug = 1; p += 5; }
            else if (strncmp(p, "hook",  4) == 0) { use_hook  = 1; p += 4; }
            else if (strncmp(p, "scramble", 8) == 0) { use_scramble = 1; p += 8; }
            else if (strncmp(p, "opaque", 6) == 0) { use_opaque = 1; p += 6; }
            else if (strncmp(p, "frida",  5) == 0) { use_frida  = 1; p += 5; }
            else if (strncmp(p, "inline", 6) == 0) { use_inline = 1; p += 6; }
            else if (strncmp(p, "plt", 3) == 0) { use_plt = 1; p += 3; }
            else if (strncmp(p, "syscall", 7) == 0) { use_syscall = 1; p += 7; }
            else if (strncmp(p, "memory", 6) == 0) { use_mem_integrity = 1; p += 6; }
            else if (strncmp(p, "dump", 4) == 0) { use_antidump = 1; p += 4; }
            else if (strncmp(p, "all", 3) == 0) {
                use_debug = use_hook = use_scramble = use_opaque = use_frida = 1;
                use_inline = use_plt = use_syscall = use_mem_integrity = 1;
                use_antidump = 1;
                p += 3;
            }
            else    { while (*p && *p != ',') p++; }
        }
    }
    // Auto-enable features based on density
    if (obf_density >= 0.5f && !anti_analysis) {
        use_scramble = 1;
    }
    if (obf_density >= 1.0f && !anti_analysis) {
        use_debug = 1;
        use_hook = 1;
        use_frida = 1;
    }
    if (obf_density >= 1.5f) {
        use_opaque = 1;
    }
    if (obf_density >= 2.0f) {
        use_antidump = 1;
    }

    FileBuffer buf;
    ExitCode ret = file_read(input, &buf);
    if (ret != EXIT_OK) return ret;

    Buffer obf_buf = {0};
    Buffer exec_buf = {0};
    Buffer vm_buf_src = {0};
    unsigned char *src_data = buf.data;
    size_t src_size = buf.size;

    int vm_obf_enabled = 0;

    if (use_vm) {
        if (obf_techniques && obf_techniques[0]) {
            // VM + obf: split + obfuscate in one pipeline pass.
            // Pipeline handles rename-only pass for name mapping, then
            // applies remaining techniques to func defs only.
            char *obf_tmpdir = tmpdir_create();
            if (!obf_tmpdir) { file_buffer_free(&buf); return EXIT_ERR_CRYPTO; }
            char *obf_tmpl = tmpdir_path(obf_tmpdir, "obf.py");
            if (!obf_tmpl) { tmpdir_destroy(obf_tmpdir); file_buffer_free(&buf); return EXIT_ERR_CRYPTO; }
            /* Secure file creation with O_EXCL|O_NOFOLLOW */
            int obf_fd = open(obf_tmpl, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
            if (obf_fd < 0) { free(obf_tmpl); tmpdir_destroy(obf_tmpdir); file_buffer_free(&buf); return EXIT_ERR_CRYPTO; }
            size_t slen = strlen(PYOBF_SCRIPT);
            if (write(obf_fd, PYOBF_SCRIPT, slen) != (ssize_t)slen) {
                close(obf_fd); free(obf_tmpl); tmpdir_destroy(obf_tmpdir);
                file_buffer_free(&buf); return EXIT_ERR_FILE;
            }
            close(obf_fd);

            ret = protect::vm_split_source((const char *)buf.data, buf.size,
                                  obf_tmpl, obf_techniques,
                                  &exec_buf, &vm_buf_src);
            free(obf_tmpl);
            tmpdir_destroy(obf_tmpdir);
            if (ret != EXIT_OK) {
                fprintf(stderr, "[vm] error: split+obf failed\n");
                file_buffer_free(&buf);
                return ret;
            }
            printf("[vm] split+obf: %s (%zu bytes exec + %zu bytes VM source)\n",
                   obf_techniques, exec_buf.size, vm_buf_src.size);
            vm_obf_enabled = 1;
        } else {
            // VM only (no obfuscation): clean split
            ret = protect::vm_split_source_clean((const char *)buf.data, buf.size,
                                        &exec_buf, &vm_buf_src);
            if (ret != EXIT_OK) {
                fprintf(stderr, "[vm] error: clean split failed\n");
                file_buffer_free(&buf);
                return ret;
            }
            printf("[vm] split: %zu bytes exec + %zu bytes VM source\n",
                   exec_buf.size, vm_buf_src.size);
        }
    } else if (obf_techniques && obf_techniques[0]) {
        // Normal obfuscation (non-VM mode)
        ret = protect::obfuscate_source((const char *)buf.data, buf.size,
                                 obf_techniques, &obf_buf, obf_seed, obf_density);
        if (ret == EXIT_OK) {
            printf("[obf] obfuscated with: %s (%zu -> %zu bytes)\n",
                   obf_techniques, buf.size, obf_buf.size);
            src_data = obf_buf.data;
            src_size = obf_buf.size;

            if (protect::has_tech(obf_techniques, "rolling-xor")) {
                Buffer rx_buf = {0};
                if (protect::apply_rolling_xor_obfuscation((const char *)src_data, src_size, &rx_buf) == EXIT_OK) {
                    printf("[obf] applied rolling-xor wrapper (%zu -> %zu bytes)\n", src_size, rx_buf.size);
                    free(obf_buf.data);
                    obf_buf = rx_buf;
                    src_data = obf_buf.data;
                    src_size = obf_buf.size;
                }
            }
            if (protect::has_tech(obf_techniques, "xor-bit-rotation")) {
                Buffer xbr_buf = {0};
                if (protect::apply_xor_bit_rotation_obfuscation((const char *)src_data, src_size, &xbr_buf) == EXIT_OK) {
                    printf("[obf] applied xor-bit-rotation wrapper (%zu -> %zu bytes)\n", src_size, xbr_buf.size);
                    free(obf_buf.data);
                    obf_buf = xbr_buf;
                    src_data = obf_buf.data;
                    src_size = obf_buf.size;
                }
            }
        } else {
            fprintf(stderr, "[obf] warning: obfuscation failed, using original\n");
        }
    }


    char *vm_xor_key_hex = NULL;
    char *vm_nonce_hex = NULL;
    int vm_obf_algo = 0;
    int use_rolling_xor_vm = 0;


    unsigned char *pt = NULL;
    size_t ptsz = 0;
    Buffer vm_buf = {0};

    if (use_vm) {
        // VM mode: compile VM source to VM bytecodes
        VmProgram vm_prog;
        vm_program_init(&vm_prog);
        
        const char *vm_src = (const char *)(vm_buf_src.data ? vm_buf_src.data : src_data);
        size_t vm_src_len = vm_buf_src.data ? vm_buf_src.size : src_size;
        
        // Build VM compile config with vRAM settings
        VmCompileConfig vm_cfg;
        vm_default_config(&vm_cfg);
        vm_cfg.enable_opaque = use_opaque;
        vm_cfg.seed = obf_seed;
        vm_cfg.enable_var_length_encoding = 0;
        vm_cfg.enable_register_spilling = 0;
        vm_cfg.enable_self_modifying_code = 0;
        vm_cfg.enable_conditional_obfuscation = 0;
        vm_cfg.enable_indirect_calls = 0;
        vm_cfg.enable_vram = use_vram;
        vm_cfg.vram_size = use_vram_auto ? 0 : vram_size;
        vm_cfg.enable_vram_garble = use_vram_garble;
        vm_cfg.vram_garble_min_interval = vram_garble_min;
        vm_cfg.vram_garble_max_interval = vram_garble_max;

        ret = vm_compile_source_ex(vm_src, vm_src_len, &vm_prog, &vm_cfg);
        if (ret == EXIT_OK && use_vram && use_vram_auto) {
            // Auto-size: compute size based on instruction count
            int auto_size = 4096;
            if (vm_prog.count > 0) {
                auto_size = vm_prog.count * 16;
                // Round up to next power of 2
                int p = 1;
                while (p < auto_size) p <<= 1;
                auto_size = p > 4096 ? p : 4096;
            }
            vm_cfg.vram_size = auto_size;
            // Re-encode size in flags
            vm_program_free(&vm_prog);
            vm_program_init(&vm_prog);
            ret = vm_compile_source_ex(vm_src, vm_src_len, &vm_prog, &vm_cfg);
        }
        if (ret != EXIT_OK) {
            fprintf(stderr, "[vm] error: VM compilation failed\n");
            file_buffer_free(&buf); free(obf_buf.data);
            free(exec_buf.data); free(vm_buf_src.data);
            return ret;
        }
        
        if (vm_obf_enabled) {
            protect::vm_obfuscate_program(&vm_prog);
        }

        ret = vm_serialize(&vm_prog, &vm_buf);
        if (ret != EXIT_OK) {
            vm_program_free(&vm_prog);
            file_buffer_free(&buf); free(obf_buf.data);
            free(exec_buf.data); free(vm_buf_src.data);
            return ret;
        }

        // ── VM AEAD Encryption ─────────────────────────────────────────────
        // Derive VM key from user key using PBKDF2 with a random salt.
        // This ensures: 1) attacker only needs one key, 2) uses proper AEAD.
        //
        // Format output: [salt(16)] [nonce(24)] [ciphertext] [tag(16)]
        // Total overhead: 56 bytes (vs 32 bytes for XOR+HMAC)

        unsigned char vm_salt[16];
        unsigned char vm_nonce[24];
        unsigned char vm_key[32];  // Derived key

        if (RAND_bytes(vm_salt, sizeof(vm_salt)) != 1 ||
            RAND_bytes(vm_nonce, sizeof(vm_nonce)) != 1) {
            free(obf_buf.data);
            free(exec_buf.data);
            free(vm_buf_src.data);
            free(vm_buf.data);
            vm_program_free(&vm_prog);
            file_buffer_free(&buf);
            return EXIT_ERR_CRYPTO;
        }

        // Derive VM key directly from user key + VM salt (same pbkdf2 as main payload)
        {
            unsigned char derived[64];
            if (PKCS5_PBKDF2_HMAC((char*)key, (int)key_len,
                            vm_salt, sizeof(vm_salt),
                            100000, EVP_sha256(),
                            sizeof(derived), derived) != 1) {
                free(obf_buf.data);
                free(exec_buf.data);
                free(vm_buf_src.data);
                free(vm_buf.data);
                vm_program_free(&vm_prog);
                file_buffer_free(&buf);
                return EXIT_ERR_CRYPTO;
            }
            memcpy(vm_key, derived, sizeof(vm_key));
            // Zero intermediate key material
            memset(derived, 0, sizeof(derived));
        }

        size_t vm_blob_size = vm_buf.size;
        unsigned char *vm_blob = vm_buf.data;

        // Compress VM blob if enabled
        if (compress_algo != COMPRESS_ID_NONE) {
            Buffer vm_compressed = {0};
            ret = compress_data(vm_blob, vm_blob_size, compress_algo, compress_level, &vm_compressed);
            if (ret != EXIT_OK) {
                free(vm_blob); memset(vm_key, 0, sizeof(vm_key));
                vm_program_free(&vm_prog);
                file_buffer_free(&buf); free(obf_buf.data);
                free(exec_buf.data); free(vm_buf_src.data);
                return ret;
            }
            free(vm_blob);  // Free original vm_buf.data
            vm_blob = vm_compressed.data;
            vm_blob_size = vm_compressed.size;
            vm_buf.data = vm_blob;  // Keep vm_buf.data in sync
        }

        // AEAD encryption: XChaCha20-Poly1305 with pre-derived key
        // Format: [salt(16)] [nonce(24)] [ciphertext] [tag(16)]
        #define VM_XNONCE_HALF 16
        #define VM_TAG_SIZE 16
        #define VM_SALT_SIZE 16
        #define VM_NONCE_SIZE 24

        EVP_CIPHER_CTX *ectx = EVP_CIPHER_CTX_new();
        if (!ectx) {
            memset(vm_key, 0, sizeof(vm_key));
            free(vm_blob); vm_program_free(&vm_prog);
            file_buffer_free(&buf); free(obf_buf.data);
            free(exec_buf.data); free(vm_buf_src.data);
            return EXIT_ERR_CRYPTO;
        }

        unsigned char subkey[32];
        unsigned char chacha_nonce[12] = {0};
        // hchacha20: nonce[0:4] unused, nonce[4:12] used as XChaCha nonce
        memcpy(chacha_nonce + 4, vm_nonce + VM_XNONCE_HALF, 8);

        // Inline hchacha20 to derive subkey from vm_key + vm_nonce
        {
            uint32_t state[16];
            static const uint32_t constants[4] = {
                0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
            };
            #define LE32(p) ((uint32_t)(p)[0] | ((uint32_t)(p)[1] << 8) | \
                            ((uint32_t)(p)[2] << 16) | ((uint32_t)(p)[3] << 24))
            #define LE32E(p, v) ((p)[0] = (v), (p)[1] = (v) >> 8, \
                                (p)[2] = (v) >> 16, (p)[3] = (v) >> 24)
            #define QROUND(X, a, b, c, d) do { \
                (a) += (b); (d) ^= (a); (d) = ((d) << 16) | ((d) >> 16); \
                (c) += (d); (b) ^= (c); (b) = ((b) << 12) | ((b) >> 20); \
                (a) += (b); (d) ^= (a); (d) = ((d) << 8) | ((d) >> 24); \
                (c) += (d); (b) ^= (c); (b) = ((b) << 7) | ((b) >> 25); \
            } while (0)
            state[0] = constants[0]; state[1] = constants[1]; state[2] = constants[2]; state[3] = constants[3];
            state[4] = LE32(vm_key + 0); state[5] = LE32(vm_key + 4);
            state[6] = LE32(vm_key + 8); state[7] = LE32(vm_key + 12);
            state[8] = LE32(vm_key + 16); state[9] = LE32(vm_key + 20);
            state[10] = LE32(vm_key + 24); state[11] = LE32(vm_key + 28);
            state[12] = LE32(vm_nonce + 0); state[13] = LE32(vm_nonce + 4);
            state[14] = LE32(vm_nonce + 8); state[15] = LE32(vm_nonce + 12);
            uint32_t x[16]; memcpy(x, state, sizeof(x));
            for (int _i = 0; _i < 10; _i++) {
                QROUND(x, x[0], x[4], x[8], x[12]);
                QROUND(x, x[1], x[5], x[9], x[13]);
                QROUND(x, x[2], x[6], x[10], x[14]);
                QROUND(x, x[3], x[7], x[11], x[15]);
                QROUND(x, x[0], x[5], x[10], x[15]);
                QROUND(x, x[1], x[6], x[11], x[12]);
                QROUND(x, x[2], x[7], x[8], x[13]);
                QROUND(x, x[3], x[4], x[9], x[14]);
            }
            LE32E(subkey + 0, x[0]); LE32E(subkey + 4, x[1]);
            LE32E(subkey + 8, x[2]); LE32E(subkey + 12, x[3]);
            LE32E(subkey + 16, x[12]); LE32E(subkey + 20, x[13]);
            LE32E(subkey + 24, x[14]); LE32E(subkey + 28, x[15]);
            #undef LE32
            #undef LE32E
            #undef QROUND
        }

        if (EVP_EncryptInit_ex(ectx, EVP_chacha20_poly1305(), NULL,
                               subkey, chacha_nonce) != 1) {
            EVP_CIPHER_CTX_free(ectx);
            memset(vm_key, 0, sizeof(vm_key));
            free(vm_blob); free(vm_buf.data); vm_program_free(&vm_prog);
            file_buffer_free(&buf); free(obf_buf.data);
            free(exec_buf.data); free(vm_buf_src.data);
            return EXIT_ERR_CRYPTO;
        }

        size_t cipher_out_size = vm_blob_size + VM_TAG_SIZE;
        unsigned char *cipher_out = (unsigned char *)malloc(VM_SALT_SIZE + VM_NONCE_SIZE + cipher_out_size);
        if (!cipher_out) {
            EVP_CIPHER_CTX_free(ectx);
            memset(vm_key, 0, sizeof(vm_key));
            free(vm_blob); free(vm_buf.data); vm_program_free(&vm_prog);
            file_buffer_free(&buf); free(obf_buf.data);
            free(exec_buf.data); free(vm_buf_src.data);
            return EXIT_ERR_CRYPTO;
        }

        memcpy(cipher_out, vm_salt, VM_SALT_SIZE);
        memcpy(cipher_out + VM_SALT_SIZE, vm_nonce, VM_NONCE_SIZE);

        int cipher_len = 0;
        if (EVP_EncryptUpdate(ectx, cipher_out + VM_SALT_SIZE + VM_NONCE_SIZE,
                              &cipher_len, vm_blob, (int)vm_blob_size) != 1) {
            EVP_CIPHER_CTX_free(ectx);
            memset(vm_key, 0, sizeof(vm_key));
            free(cipher_out); free(vm_blob); free(vm_buf.data); vm_program_free(&vm_prog);
            file_buffer_free(&buf); free(obf_buf.data);
            free(exec_buf.data); free(vm_buf_src.data);
            return EXIT_ERR_CRYPTO;
        }

        int final_len = 0;
        EVP_EncryptFinal_ex(ectx, cipher_out + VM_SALT_SIZE + VM_NONCE_SIZE + cipher_len, &final_len);
        cipher_len += final_len;

        unsigned char poly_tag[16];
        EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_AEAD_GET_TAG, 16, poly_tag);
        EVP_CIPHER_CTX_free(ectx);
        memset(vm_key, 0, sizeof(vm_key));
        memcpy(cipher_out + VM_SALT_SIZE + VM_NONCE_SIZE + cipher_len, poly_tag, 16);
        // Note: vm_blob is the only allocated source data now (already freed original vm_buf.data on compression)
        free(vm_blob);

        vm_buf.data = cipher_out;
        vm_buf.size = VM_SALT_SIZE + VM_NONCE_SIZE + cipher_len + 16;

        #undef VM_XNONCE_HALF
        #undef VM_TAG_SIZE
        #undef VM_SALT_SIZE
        #undef VM_NONCE_SIZE

        // Convert salt to hex for stub (no key stored — key derived at runtime)
        vm_xor_key_hex = (char *)malloc(33);
        if (!vm_xor_key_hex) {
            free(vm_buf.data); vm_program_free(&vm_prog);
            file_buffer_free(&buf); free(obf_buf.data);
            free(exec_buf.data); free(vm_buf_src.data);
            return EXIT_ERR_CRYPTO;
        }
        for (int i = 0; i < 16; i++) sprintf(vm_xor_key_hex + i * 2, "%02x", vm_salt[i]);
        vm_xor_key_hex[32] = '\0';

        // VM nonce stored as hex (needed for decryption)
        vm_nonce_hex = (char *)malloc(49);
        if (!vm_nonce_hex) {
            free(vm_xor_key_hex);
            free(vm_buf.data); vm_program_free(&vm_prog);
            file_buffer_free(&buf); free(obf_buf.data);
            free(exec_buf.data); free(vm_buf_src.data);
            return EXIT_ERR_CRYPTO;
        }
        for (int i = 0; i < 24; i++) sprintf(vm_nonce_hex + i * 2, "%02x", vm_nonce[i]);
        vm_nonce_hex[48] = '\0';

        // Note: vm_enc_hex is now just salt (no layer1 obfuscation needed since key is derived)
        // Legacy stubs might still expect vm_enc_hex — provide it for compatibility
        if (layer1_computed) {
            // Obscure the salt slightly for legacy compatibility (not security-critical)
            std::string vm_obf_hex;
            vm_obf_hex.reserve(32);
            for (int vi = 0; vi < 16; vi++) {
                unsigned char b = vm_salt[vi];
                b ^= layer1_key[vi % 16];
                b ^= layer1_env_byte;
                vm_obf_hex += std::format("{:02x}", b);
            }
            ml_key_data.vm_enc_hex = vm_obf_hex;
        }

        printf("[vm] XChaCha20-Poly1305 AEAD encryption applied\n");

        printf("[vm] compiled %zu bytes -> %zu bytes VM (%d instrs, %d consts, %d names)\n",
               vm_src_len, vm_buf.size, vm_prog.count, vm_prog.const_count, vm_prog.name_count);

        // Build header: version=2 for VM mode
        unsigned char hdr[HEADER_SIZE] = {2, (unsigned char)compress_algo, (unsigned char)sa_id, 0};
        ptsz = HEADER_SIZE + vm_buf.size;
        pt = (unsigned char *)malloc(ptsz);
        if (!pt) {
            free(vm_buf.data); vm_program_free(&vm_prog);
            file_buffer_free(&buf); free(obf_buf.data);
            free(exec_buf.data); free(vm_buf_src.data);
            return EXIT_ERR_CRYPTO;
        }
        memcpy(pt, hdr, HEADER_SIZE);
        memcpy(pt + HEADER_SIZE, vm_buf.data, vm_buf.size);
        vm_program_free(&vm_prog);
    } else {
        // Normal mode: compress source
        Buffer comp = {0};
        ret = compress_data(src_data, src_size, compress_algo, compress_level, &comp);
        if (ret != EXIT_OK) {
            file_buffer_free(&buf); free(obf_buf.data);
            return ret;
        }

        unsigned char hdr[HEADER_SIZE] = {1, (unsigned char)compress_algo, (unsigned char)sa_id, 0};
        ptsz = HEADER_SIZE + comp.size;
        pt = (unsigned char *)malloc(ptsz);
        if (!pt) { free(comp.data); file_buffer_free(&buf); free(obf_buf.data); return EXIT_ERR_CRYPTO; }
        memcpy(pt, hdr, HEADER_SIZE);
        memcpy(pt + HEADER_SIZE, comp.data, comp.size);
        free(comp.data);
    }

    Buffer enc = {0};
    switch (algo) {
        case ALGO_AES_ECB:
            ret = aes_encrypt(pt, ptsz, (const unsigned char *)key, key_len, AES_ECB, &enc);
            break;
        case ALGO_AES_CBC:
            ret = aes_encrypt(pt, ptsz, (const unsigned char *)key, key_len, AES_CBC, &enc);
            break;
        case ALGO_AES_CTR:
            ret = aes_encrypt(pt, ptsz, (const unsigned char *)key, key_len, AES_CTR, &enc);
            break;
        case ALGO_AES_GCM:
            ret = aes_encrypt(pt, ptsz, (const unsigned char *)key, key_len, AES_GCM, &enc);
            break;
        case ALGO_CHACHA20:
            ret = chacha20_encrypt(pt, ptsz, (const unsigned char *)key, key_len, &enc);
            break;
        case ALGO_CHACHA20_POLY1305:
            ret = chacha20_poly1305_encrypt(pt, ptsz, (const unsigned char *)key, key_len, &enc);
            break;
        case ALGO_XCHACHA20_POLY1305:
            ret = xchacha20_poly1305_encrypt(pt, ptsz, (const unsigned char *)key, key_len, &enc);
            break;
        case ALGO_XOR:
            ret = xor_encrypt_protect(pt, ptsz, (const unsigned char *)key, key_len, &enc);
            break;
        case ALGO_ROLLING_XOR:
            ret = rolling_xor_encrypt_protect(pt, ptsz, (const unsigned char *)key, key_len, &enc);
            break;
        case ALGO_MULTI_PASS_XOR:
            ret = multi_pass_xor_encrypt_protect(pt, ptsz, (const unsigned char *)key, key_len, &enc);
            break;
        case ALGO_PRNG_XOR:
            ret = prng_xor_encrypt_protect(pt, ptsz, (const unsigned char *)key, key_len, &enc);
            break;
        case ALGO_BASE64:
            ret = base64_encode(pt, ptsz, &enc);
            break;
        case ALGO_BASE32:
            ret = base32_encode(pt, ptsz, &enc);
            break;
        case ALGO_BASE85:
            ret = base85_encode(pt, ptsz, &enc);
            break;
        case ALGO_ASCII85:
            ret = ascii85_encode(pt, ptsz, &enc);
            break;
        case ALGO_HEX:
            ret = hex_encode(pt, ptsz, &enc);
            break;
        default:
            ret = EXIT_ERR_INTERNAL;
            break;
    }
    free(pt);
    if (ret != EXIT_OK) { file_buffer_free(&buf); free(obf_buf.data); free(exec_buf.data); free(vm_buf_src.data); free(vm_buf.data); return ret; }

    Buffer b64 = {0};
    ret = base64_encode(enc.data, enc.size, &b64);
    free(enc.data);
    if (ret != EXIT_OK) { file_buffer_free(&buf); free(obf_buf.data); free(exec_buf.data); free(vm_buf_src.data); free(vm_buf.data); return ret; }

    std::string algo_id_s = std::to_string(sa_id);
    const char *algo_id = algo_id_s.c_str();

    // ── Multi-layer key obfuscation (reuses pre-computed layer1_key) ──
    std::string obf_key;
    size_t obf_len = 0;
    if (algo_needs_key(algo)) {
        // Re-derive with a new salt — but preserve original layer1_key for VM key obfuscation
        // Save and restore layer1_key around the re-derivation
        unsigned char saved_layer1[16];
        memcpy(saved_layer1, layer1_key, 16);
        unsigned char salt[16];
        unsigned char layer2[16], layer3[16];
        RAND_bytes(salt, 16);
        protect::derive_sub_keys((const unsigned char *)key, key_len,
                        salt, 16,
                        layer1_key, 16, layer2, 16, layer3, 16);
        // Restore original layer1_key (used for VM obfuscation)
        memcpy(layer1_key, saved_layer1, 16);
        
        // Encrypt key through 3 layers
        std::string enc_hex = protect::key_obfuscate_multi(
            std::string_view(key, key_len),
            salt, layer1_key, layer2, layer3);
        
        // Build string pool
        std::string pool_csv;
        std::vector<int> pool_indices_vec;
        pool_csv = protect::build_string_pool(enc_hex, pool_indices_vec);
        std::string pool_indices_str;
        for (size_t pi = 0; pi < pool_indices_vec.size(); pi++) {
            if (pi > 0) pool_indices_str += ",";
            pool_indices_str += std::to_string(pool_indices_vec[pi]);
        }
        
        // Salt as hex
        std::string salt_hex;
        for (int si = 0; si < 16; si++)
            salt_hex += std::format("{:02x}", salt[si]);
        
        // Layer1 key as hex (same as pre-computed)
        std::string layer1_hex;
        for (int si = 0; si < 16; si++)
            layer1_hex += std::format("{:02x}", layer1_key[si]);
        
        // Populate multi-layer key struct
        ml_key_data.salt_hex = salt_hex;
        ml_key_data.layer1_hex = layer1_hex;
        ml_key_data.enc_key_hex = enc_hex;
        ml_key_data.pool_csv = pool_csv;
        ml_key_data.pool_indices = pool_indices_str;
        ml_key_data.env_payload = std::format("{:02x}", layer1_env_byte);
        ml_key_data.extra1 = std::to_string(xor_byte);
        ml_key_data.extra2 = std::format("{:02x}", (unsigned char)(xor_byte ^ 0xA5));
        
        ml_key_ptr = &ml_key_data;
        
        // Keep simple obfuscation as fallback
        obf_key = protect::key_obfuscate(std::string_view(key, key_len), xor_byte);
        obf_len = obf_key.size();
    }

    char anti_buf[65536];  // 64KB to fit all anti-analysis codes
    // ── build anti-analysis buffer ──
    size_t anti_pos = 0;
    bool anti_truncated = false;
    auto try_copy_anti = [&](const char *code, const char *name) {
        size_t sl = strlen(code);
        if (anti_pos + sl < sizeof(anti_buf)) {
            memcpy(anti_buf + anti_pos, code, sl);
            anti_pos += sl;
        } else {
            fprintf(stderr, "warning: anti_buf overflow, truncating %s (%zu bytes)\n", name, sl);
            anti_truncated = true;
        }
    };
    if (use_debug) try_copy_anti(protect::ANTI_DEBUG_CODE_PTR, "anti_debug");
    if (use_hook) try_copy_anti(protect::ANTI_HOOK_CODE_PTR, "anti_hook");
    if (use_frida) try_copy_anti(protect::ANTI_FRIDA_CODE_PTR, "anti_frida");
    if (use_inline) try_copy_anti(protect::ANTI_INLINE_HOOK_CODE_PTR, "anti_inline");
    if (use_plt) try_copy_anti(protect::ANTI_PLT_HOOK_CODE_PTR, "anti_plt");
    if (use_syscall) try_copy_anti(protect::ANTI_SYSCALL_HOOK_CODE_PTR, "anti_syscall");
    if (use_mem_integrity) try_copy_anti(protect::ANTI_MEM_INTEGRITY_CODE_PTR, "anti_mem_integrity");
    anti_buf[anti_pos] = '\0';
    const char *anti_code = anti_buf;
    size_t anti_len = anti_pos;

    // ── base64-encode exec_source for VM mode ──
    Buffer exec_b64 = {0};
    if (use_vm && exec_buf.data && exec_buf.size > 0) {
        base64_encode((unsigned char *)exec_buf.data, exec_buf.size, &exec_b64);
    }

    // ── generate polymorphic stub ──
    Buffer stub_buf = {0};
    srand((unsigned)(time(NULL) ^ (uintptr_t)&stub_buf));
    ret = protect::generate_stub((const char *)b64.data, b64.size,
                           algo_id, obf_key.c_str(), obf_len,
                           anti_code, anti_len, xor_byte, compress_algo,
                           use_vm, use_scramble,
                           vm_xor_key_hex, vm_obf_algo,
                           vm_nonce_hex,
                           (const char *)(exec_b64.data ? exec_b64.data : (unsigned char*)""),
                           &stub_buf, obf_density,
                           ml_key_ptr, use_antidump);
    free(b64.data); free(vm_xor_key_hex); free(vm_nonce_hex);
    free(exec_b64.data);

    if (ret != EXIT_OK) {
        file_buffer_free(&buf); free(obf_buf.data); free(exec_buf.data); free(vm_buf_src.data);
        return ret;
    }

    printf("[protect] %s (%s) %zu bytes -> %s (%zu bytes)\n",
           input, algo_name(algo), buf.size, output, stub_buf.size);

    // Write to temp file then atomic rename to avoid partial write corruption
    std::string tmp_path = std::string(output) + ".tmp.XXXXXX";
    int tmp_fd = mkstemp(tmp_path.data());
    if (tmp_fd < 0) {
        fprintf(stderr, "error: cannot create temp file for '%s': %s\n", output, strerror(errno));
        free(stub_buf.data); file_buffer_free(&buf); free(obf_buf.data); free(exec_buf.data); free(vm_buf_src.data);
        return EXIT_ERR_FILE;
    }
    FILE *f = fdopen(tmp_fd, "w");
    if (!f) {
        close(tmp_fd);
        unlink(tmp_path.c_str());
        fprintf(stderr, "error: cannot open temp file for '%s'\n", output);
        free(stub_buf.data); file_buffer_free(&buf); free(obf_buf.data); free(exec_buf.data); free(vm_buf_src.data);
        return EXIT_ERR_FILE;
    }
    size_t written = fwrite(stub_buf.data, 1, stub_buf.size, f);
    if (fflush(f) != 0 || ferror(f)) {
        fclose(f);
        unlink(tmp_path.c_str());
        fprintf(stderr, "error: failed to write '%s'\n", tmp_path.c_str());
        free(stub_buf.data); file_buffer_free(&buf); free(obf_buf.data); free(exec_buf.data); free(vm_buf_src.data);
        return EXIT_ERR_FILE;
    }
    fclose(f);

    free(stub_buf.data); file_buffer_free(&buf); free(obf_buf.data); free(exec_buf.data); free(vm_buf_src.data);

    if (written != stub_buf.size) {
        unlink(tmp_path.c_str());
        fprintf(stderr, "error: incomplete write to '%s'\n", output);
        return EXIT_ERR_FILE;
    }

    // Atomic rename
    if (rename(tmp_path.c_str(), output) != 0) {
        unlink(tmp_path.c_str());
        fprintf(stderr, "error: cannot rename temp file to '%s': %s\n", output, strerror(errno));
        return EXIT_ERR_FILE;
    }
    return EXIT_OK;
}
