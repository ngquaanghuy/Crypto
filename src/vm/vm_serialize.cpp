#include "vm/vm.h"
#include "vm/vm_serialize.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>

// ─── Serialize (with VM header, constant encryption & CFI table) ───
// Format: [op_key: 32 bytes] [header: 32 bytes] [opmap: 256 bytes] [flags: 4 bytes]
//         [const_key: 16 bytes if enabled] [CFI table if enabled] [consts] [names] [code]
// The op_key is used by _vm_deserialize(_data) to XOR-decode the instruction bytes at runtime.
ExitCode vm_serialize(const VmProgram *prog, Buffer *out) {
    if (!prog || !out) return EXIT_ERR_ARGS;

    int flags = prog->flags | VM_SER_FLAG_HAS_HEADER;
    bool encrypt_consts = (flags & VM_SER_FLAG_CONST_ENCRYPTED) != 0;
    bool has_cfi = (flags & VM_SER_FLAG_CFI_ENABLED) != 0;

    const size_t op_key_size = 32;  // 32-byte XOR key for instruction obfuscation
    const size_t hdr_sz = VM_HEADER_SIZE;
    size_t map_size = 256;
    size_t flags_dup_size = 4;  // duplicate flags after opmap for legacy fallback
    size_t const_key_size = encrypt_consts ? VM_CONST_KEY_SIZE : 0;
    size_t cfi_table_size = has_cfi ? (size_t)(4 + prog->cfi_num_blocks * 12) : 0;

    size_t consts_size = 4;
    for (int i = 0; i < prog->const_count; i++) {
        consts_size += 1 + 4;
        if (prog->const_strs[i])
            consts_size += strlen(prog->const_strs[i]);
    }

    size_t names_size = 4;
    for (int i = 0; i < prog->name_count; i++) {
        names_size += 2;
        if (prog->names[i])
            names_size += strlen(prog->names[i]);
    }

    size_t code_section_size;
    bool is_vl = (flags & (VM_SER_FLAG_VL_ENCODED | VM_SER_FLAG_POLY_ENCODING)) != 0 && prog->vl_code;

    if (is_vl) {
        code_section_size = 4 + (size_t)prog->vl_code_len;
    } else {
        code_section_size = 4 + (size_t)prog->count * VM_INSTR_SIZE;
    }

    size_t total = op_key_size + hdr_sz + map_size + flags_dup_size + const_key_size
                  + cfi_table_size + consts_size + names_size + code_section_size;
    out->data = (unsigned char *)malloc(total);
    if (!out->data) return EXIT_ERR_CRYPTO;

    // ─── Generate and write random op_key (32 bytes) ───
    unsigned char op_key[op_key_size];
    if (RAND_bytes(op_key, (int)op_key_size) != 1) {
        free(out->data);
        out->data = nullptr;
        return EXIT_ERR_CRYPTO;
    }
    memcpy(out->data, op_key, op_key_size);

    // ─── Compute section offsets (shifted by op_key_size) ───
    size_t off_opmap = op_key_size + hdr_sz;
    size_t off_flags = off_opmap + 256;
    size_t off_const_key = off_flags + 4;
    size_t off_cfi = off_const_key + const_key_size;
    size_t off_consts = off_cfi + cfi_table_size;
    size_t off_names = off_consts + consts_size;
    size_t off_code = off_names + names_size;

    // ─── Write VM header (32 bytes) ───
    VmHeader hdr;
    hdr.magic   = VM_HEADER_MAGIC;
    hdr.flags   = (uint32_t)flags;
    hdr.entry_point = 0;  // always start at 0 for now
    hdr.const_offset  = (uint32_t)off_consts;
    hdr.names_offset  = (uint32_t)off_names;
    hdr.code_offset   = (uint32_t)off_code;
    hdr.opmap_offset  = (uint32_t)off_opmap;
    hdr.total_size    = (uint32_t)(total - op_key_size);  // total without op_key prefix
    memcpy(out->data + op_key_size, &hdr, hdr_sz);

    size_t pos = off_opmap;

    // Opcode map (256 bytes)
    if (prog->opcode_map) {
        memcpy(out->data + pos, prog->opcode_map, 256);
    } else {
        memset(out->data + pos, 0, 256);
    }
    pos += 256;

    // Flags (4 bytes) — duplicate after opmap for legacy fallback
    uint32_t flags_val = (uint32_t)flags;
    memcpy(out->data + pos, &flags_val, 4);
    pos += 4;

    // Constant encryption key (if enabled)
    if (encrypt_consts) {
        memcpy(out->data + pos, prog->const_key, VM_CONST_KEY_SIZE);
        pos += VM_CONST_KEY_SIZE;
    }

    // CFI checksum table (if enabled)
    if (has_cfi) {
        uint32_t nb = (uint32_t)prog->cfi_num_blocks;
        memcpy(out->data + pos, &nb, 4); pos += 4;
        for (int i = 0; i < prog->cfi_num_blocks; i++) {
            uint32_t start = (uint32_t)prog->cfi_block_starts[i];
            uint32_t len = (uint32_t)prog->cfi_block_lengths[i];
            uint32_t csum = prog->cfi_checksums[i];
            memcpy(out->data + pos, &start, 4); pos += 4;
            memcpy(out->data + pos, &len, 4); pos += 4;
            memcpy(out->data + pos, &csum, 4); pos += 4;
        }
    }

    // Const count + data (XOR-encrypt string constants if enabled)
    pos = off_consts;
    uint32_t cc = (uint32_t)prog->const_count;
    memcpy(out->data + pos, &cc, 4); pos += 4;
    for (int i = 0; i < prog->const_count; i++) {
        out->data[pos++] = prog->const_types[i];
        size_t sl = prog->const_strs[i] ? strlen(prog->const_strs[i]) : 0;
        uint32_t sl32 = (uint32_t)sl;
        memcpy(out->data + pos, &sl32, 4); pos += 4;
        if (sl > 0) {
            if (encrypt_consts && prog->const_types[i] == 4) {
                for (size_t j = 0; j < sl; j++) {
                    out->data[pos + j] = (uint8_t)(prog->const_strs[i][j] ^
                                                    prog->const_key[j % VM_CONST_KEY_SIZE]);
                }
            } else {
                memcpy(out->data + pos, prog->const_strs[i], sl);
            }
            pos += sl;
        }
    }

    // Name count + data (plaintext, not encrypted)
    pos = off_names;
    uint32_t nc = (uint32_t)prog->name_count;
    memcpy(out->data + pos, &nc, 4); pos += 4;
    for (int i = 0; i < prog->name_count; i++) {
        size_t sl = prog->names[i] ? strlen(prog->names[i]) : 0;
        uint16_t sl16 = (uint16_t)sl;
        memcpy(out->data + pos, &sl16, 2); pos += 2;
        if (sl > 0) {
            memcpy(out->data + pos, prog->names[i], sl); pos += sl;
        }
    }

    // Code section
    pos = off_code;
    if (is_vl) {
        uint32_t code_sz = (uint32_t)prog->vl_code_len;
        memcpy(out->data + pos, &code_sz, 4); pos += 4;
        memcpy(out->data + pos, prog->vl_code, code_sz);
        pos += code_sz;
    } else {
        uint32_t ic = (uint32_t)prog->count;
        memcpy(out->data + pos, &ic, 4); pos += 4;

        // ─── XOR-encode instruction bytes with op_key (Python _vm_decode_fixed expects this) ───
        for (int i = 0; i < prog->count; i++) {
            size_t base = i * VM_INSTR_SIZE;
            // Encode first 4 bytes (op, rd, rs1, rs2) with corresponding key bytes
            for (int j = 0; j < 4; j++) {
                out->data[pos + base + j] = ((uint8_t*)prog->instrs)[base + j] ^ op_key[base + j];
            }
            // Encode imm (bytes 4-7) - matches Python's key[4..7] per-byte XOR
            uint32_t imm_val;
            memcpy(&imm_val, (uint8_t*)prog->instrs + base + 4, 4);
            // XOR each byte with corresponding key byte 4-7
            uint8_t* enc_imm = (uint8_t*)&imm_val;
            enc_imm[0] ^= op_key[base + 4];
            enc_imm[1] ^= op_key[base + 5];
            enc_imm[2] ^= op_key[base + 6];
            enc_imm[3] ^= op_key[base + 7];
            memcpy(out->data + pos + base + 4, &imm_val, 4);
        }
        pos += (size_t)prog->count * VM_INSTR_SIZE;
    }

    out->size = pos;
    return EXIT_OK;
}

// ─── Deserialize (with VM header, constant decryption & CFI table) ───
ExitCode vm_deserialize(const unsigned char *data, size_t size,
                         VmProgram *prog) {
    vm_program_init(prog);

    const size_t op_key_size = 32;  // Must match vm_serialize
    unsigned char op_key[op_key_size] = {0};  // Zero-filled for legacy default
    bool new_format = false;  // True if blob has op_key prefix
    unsigned char *op_key_ptr = op_key;  // Points to where key actually is

    size_t pos = 0;

    // ─── Detect format: check for VM header magic at position 0 (legacy) ───
    bool has_header = false;
    size_t off_opmap, off_const_key, off_cfi, off_consts, off_names, off_code;
    size_t off_flags;
    uint32_t hdr_flags = 0;
    bool encrypt_consts = false, has_cfi = false, is_vl = false;
    uint8_t const_key_arr[VM_CONST_KEY_SIZE] = {0};

    if (size >= VM_HEADER_SIZE) {
        uint32_t magic;
        memcpy(&magic, data, 4);
        if (magic == VM_HEADER_MAGIC) {
            // Legacy format (no op_key prefix)
            has_header = true;
            VmHeader hdr;
            memcpy(&hdr, data, VM_HEADER_SIZE);
            hdr_flags = hdr.flags;
            prog->flags = (int)hdr_flags;
            off_opmap  = hdr.opmap_offset;
            off_consts = hdr.const_offset;
            off_names  = hdr.names_offset;
            off_code   = hdr.code_offset;
            off_flags  = off_opmap + 256;
            off_const_key = off_flags + 4;

            is_vl = (hdr_flags & (VM_SER_FLAG_VL_ENCODED | VM_SER_FLAG_POLY_ENCODING)) != 0;
            encrypt_consts = (hdr_flags & VM_SER_FLAG_CONST_ENCRYPTED) != 0;
            has_cfi = (hdr_flags & VM_SER_FLAG_CFI_ENABLED) != 0;
            off_cfi = off_const_key + (encrypt_consts ? VM_CONST_KEY_SIZE : 0);
        }
    }

    // Check for new format (op_key prefix) if not legacy
    if (!has_header && size >= op_key_size + VM_HEADER_SIZE) {
        uint32_t magic;
        memcpy(&magic, data + op_key_size, 4);
        if (magic == VM_HEADER_MAGIC) {
            // New format with op_key prefix
            new_format = true;
            memcpy(op_key, data, op_key_size);  // Read op_key
            pos = op_key_size;
            has_header = true;

            VmHeader hdr;
            memcpy(&hdr, data + pos, VM_HEADER_SIZE);
            hdr_flags = hdr.flags;
            prog->flags = (int)hdr_flags;
            off_opmap  = hdr.opmap_offset;
            off_consts = hdr.const_offset;
            off_names  = hdr.names_offset;
            off_code   = hdr.code_offset;
            off_flags  = off_opmap + 256;
            off_const_key = off_flags + 4;

            is_vl = (hdr_flags & (VM_SER_FLAG_VL_ENCODED | VM_SER_FLAG_POLY_ENCODING)) != 0;
            encrypt_consts = (hdr_flags & VM_SER_FLAG_CONST_ENCRYPTED) != 0;
            has_cfi = (hdr_flags & VM_SER_FLAG_CFI_ENABLED) != 0;
            off_cfi = off_const_key + (encrypt_consts ? VM_CONST_KEY_SIZE : 0);
        }
    }

    if (!has_header) {
        // Legacy sequential format (no header magic)
        off_opmap = 0;
        off_flags = 256;
        off_const_key = off_flags + 4;

        if (size >= 260) {
            uint32_t fv;
            memcpy(&fv, data + 256, 4);
            hdr_flags = fv;
            prog->flags = (int)fv;
        }
        is_vl = (hdr_flags & (VM_SER_FLAG_VL_ENCODED | VM_SER_FLAG_POLY_ENCODING)) != 0;
        encrypt_consts = (hdr_flags & VM_SER_FLAG_CONST_ENCRYPTED) != 0;
        has_cfi = (hdr_flags & VM_SER_FLAG_CFI_ENABLED) != 0;
        off_cfi = off_const_key + (encrypt_consts ? VM_CONST_KEY_SIZE : 0);
        off_consts = off_cfi + (has_cfi ? (4 + 12) : 0);
        off_names = 0;
        off_code = 0;
    }

    // ─── Opcode map ───
    if (off_opmap + 256 > size) return EXIT_ERR_CRYPTO;
    prog->opcode_map = (uint8_t *)malloc(256);
    if (!prog->opcode_map) return EXIT_ERR_CRYPTO;
    memcpy(prog->opcode_map, data + off_opmap, 256);

    // Flags already read from header

    // Constant encryption key (if present)
    if (encrypt_consts) {
        if (off_const_key + VM_CONST_KEY_SIZE > size) return EXIT_ERR_CRYPTO;
        memcpy(const_key_arr, data + off_const_key, VM_CONST_KEY_SIZE);
        memcpy(prog->const_key, const_key_arr, VM_CONST_KEY_SIZE);
    }

    // CFI table (if present)
    if (has_cfi) {
        if (off_cfi + 4 > size) return EXIT_ERR_CRYPTO;
        uint32_t nb;
        memcpy(&nb, data + off_cfi, 4);
        size_t cfi_pos = off_cfi + 4;
        prog->cfi_num_blocks = (int)nb;
        if (nb > 0 && nb <= VM_CFI_MAX_BLOCKS) {
            prog->cfi_checksums = (uint32_t *)calloc(nb, sizeof(uint32_t));
            prog->cfi_block_starts = (int *)calloc(nb, sizeof(int));
            prog->cfi_block_lengths = (int *)calloc(nb, sizeof(int));
            if (!prog->cfi_checksums || !prog->cfi_block_starts || !prog->cfi_block_lengths)
                return EXIT_ERR_CRYPTO;
            for (uint32_t i = 0; i < nb; i++) {
                if (cfi_pos + 12 > size) return EXIT_ERR_CRYPTO;
                uint32_t s, l, c;
                memcpy(&s, data + cfi_pos, 4); cfi_pos += 4;
                memcpy(&l, data + cfi_pos, 4); cfi_pos += 4;
                memcpy(&c, data + cfi_pos, 4); cfi_pos += 4;
                prog->cfi_block_starts[i] = (int)s;
                prog->cfi_block_lengths[i] = (int)l;
                prog->cfi_checksums[i] = c;
            }
        }
        if (!has_header) {
            // Legacy: CFI table ends where consts begin
            off_consts = cfi_pos;
        }
    } else if (!has_header) {
        // Legacy, no CFI: consts start right after const_key area
        size_t ck_end = off_const_key + (encrypt_consts ? VM_CONST_KEY_SIZE : 0);
        off_consts = ck_end;
    }

    // If no header offsets, compute them as running sequential scan (legacy)
    if (!has_header) {
        // Scan consts to find names offset, then names to find code offset
        // But we need to know all sizes first. Use the known sequential layout.
        // We already have off_consts. Read consts, then compute names/code offsets.
    }

    // ─── Constants ───
    pos = off_consts;
    if (pos + 4 > size) return EXIT_ERR_CRYPTO;
    uint32_t cc;
    memcpy(&cc, data + pos, 4); pos += 4;
    prog->const_count = (int)cc;
    if (cc > 0) {
        prog->const_types = (uint8_t *)malloc(cc);
        prog->const_strs = (char **)calloc(cc, sizeof(char *));
        if (!prog->const_types || !prog->const_strs)
            return EXIT_ERR_CRYPTO;
        for (uint32_t i = 0; i < cc; i++) {
            if (pos + 1 > size) return EXIT_ERR_CRYPTO;
            prog->const_types[i] = data[pos++];
            if (pos + 4 > size) return EXIT_ERR_CRYPTO;
            uint32_t sl;
            memcpy(&sl, data + pos, 4); pos += 4;
            if (pos + sl > size) return EXIT_ERR_CRYPTO;
            if (sl > 0) {
                prog->const_strs[i] = (char *)malloc(sl + 1);
                if (!prog->const_strs[i]) return EXIT_ERR_CRYPTO;
                if (encrypt_consts && prog->const_types[i] == 4) {
                    for (uint32_t j = 0; j < sl; j++) {
                        prog->const_strs[i][j] = (char)(data[pos + j] ^
                                                        const_key_arr[j % VM_CONST_KEY_SIZE]);
                    }
                } else {
                    memcpy(prog->const_strs[i], data + pos, sl);
                }
                prog->const_strs[i][sl] = '\0';
                pos += sl;
            }
        }
    }

    // ─── Names ───
    if (!has_header) {
        // Legacy: names follow consts sequentially
        off_names = pos;
    }
    pos = off_names;
    if (pos + 4 > size) return EXIT_ERR_CRYPTO;
    uint32_t nc;
    memcpy(&nc, data + pos, 4); pos += 4;
    prog->name_count = (int)nc;
    if (nc > 0) {
        prog->names = (char **)calloc(nc, sizeof(char *));
        if (!prog->names) return EXIT_ERR_CRYPTO;
        for (uint32_t i = 0; i < nc; i++) {
            if (pos + 2 > size) return EXIT_ERR_CRYPTO;
            uint16_t sl;
            memcpy(&sl, data + pos, 2); pos += 2;
            if (pos + sl > size) return EXIT_ERR_CRYPTO;
            if (sl > 0) {
                prog->names[i] = (char *)malloc(sl + 1);
                if (!prog->names[i]) return EXIT_ERR_CRYPTO;
                memcpy(prog->names[i], data + pos, sl);
                prog->names[i][sl] = '\0';
                pos += sl;
            }
        }
    }

    // ─── Code section ───
    if (!has_header) {
        // Legacy: code follows names sequentially
        off_code = pos;
    }
    pos = off_code;
    if (is_vl) {
        if (pos + 4 > size) return EXIT_ERR_CRYPTO;
        uint32_t code_sz;
        memcpy(&code_sz, data + pos, 4); pos += 4;
        if (pos + code_sz > size) return EXIT_ERR_CRYPTO;
        prog->vl_code = (uint8_t *)malloc(code_sz);
        if (!prog->vl_code && code_sz > 0) return EXIT_ERR_CRYPTO;
        memcpy(prog->vl_code, data + pos, code_sz);
        prog->vl_code_len = (int)code_sz;
        pos += code_sz;
        prog->count = 0;
        prog->instrs = NULL;
    } else {
        if (pos + 4 > size) return EXIT_ERR_CRYPTO;
        uint32_t ic;
        memcpy(&ic, data + pos, 4); pos += 4;
        prog->count = (int)ic;
        if (ic > 0) {
            size_t instr_bytes = (size_t)ic * VM_INSTR_SIZE;
            if (pos + instr_bytes > size) return EXIT_ERR_CRYPTO;

            // Instructions are stored as raw bytes (Python _vm_decode_fixed handles XOR decode)
            // We just copy them directly
            prog->instrs = (VmInstr *)malloc(instr_bytes);
            if (!prog->instrs) return EXIT_ERR_CRYPTO;
            memcpy(prog->instrs, data + pos, instr_bytes);

            pos += instr_bytes;
        }
    }

    return EXIT_OK;
}

/* ─── VM Serialize (done) ─────────────────────────────── */
/* Note: vm_encrypt_blob is deprecated - VM blob encryption
 * now happens in protect.cpp using proper key derivation.
 * Keeping this stub for API compatibility only. */
int vm_encrypt_blob(const unsigned char *plaintext, int plaintext_len,
                           unsigned char **ciphertext, int *ciphertext_len) {
    (void)plaintext;
    (void)plaintext_len;
    (void)ciphertext;
    (void)ciphertext_len;
    return -1; /* Deprecated: returns error */
}
