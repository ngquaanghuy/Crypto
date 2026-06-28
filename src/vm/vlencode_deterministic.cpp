#include "vm/vm.h"
#include <cstdlib>
#include <cstring>
#include <vector>

// ─── Variable-Length Encoder (original, deterministic) ──────
size_t vm_encode_var_length(uint8_t *out, size_t out_max,
                            uint8_t canonical_op,
                            uint8_t rd, uint8_t rs1, uint8_t rs2,
                            int32_t imm) {
    if (!out || out_max < 2) return 0;

    bool short_ok = (rs2 == 0 && imm == 0 && canonical_op < 16);
    bool med_ok = (rs2 == 0 && imm >= -32768 && imm <= 32767 && canonical_op < 32);

    if (short_ok && out_max >= 2) {
        out[0] = (uint8_t)(0x00 | (canonical_op & 0x0F));
        out[1] = (uint8_t)(((rd & 0x0F) << 4) | (rs1 & 0x0F));
        return 2;
    }
    else if (med_ok && out_max >= 4) {
        out[0] = (uint8_t)(0x40 | (canonical_op & 0x1F));
        out[1] = (uint8_t)(((rd & 0x0F) << 4) | (rs1 & 0x0F));
        uint16_t imm16 = (uint16_t)(imm & 0xFFFF);
        out[2] = (uint8_t)(imm16 & 0xFF);
        out[3] = (uint8_t)((imm16 >> 8) & 0xFF);
        return 4;
    }
    else if (out_max >= 9) {
        out[0] = (uint8_t)0x80;
        out[1] = canonical_op;
        out[2] = rd;
        out[3] = rs1;
        out[4] = rs2;
        out[5] = (uint8_t)(imm & 0xFF);
        out[6] = (uint8_t)((imm >> 8) & 0xFF);
        out[7] = (uint8_t)((imm >> 16) & 0xFF);
        out[8] = (uint8_t)((imm >> 24) & 0xFF);
        return 9;
    }

    return 0;
}

size_t vm_decode_var_length(const uint8_t *code, size_t code_len,
                            VmDecodedInstr *dec) {
    if (!code || !dec || code_len < 2) return 0;

    uint8_t tag = code[0];
    int cls = (tag >> 6) & 0x3;

    memset(dec, 0, sizeof(*dec));

    if (cls == 0 && code_len >= 2) {
        dec->op_shuf = tag & 0x0F;
        dec->rd = (code[1] >> 4) & 0x0F;
        dec->rs1 = code[1] & 0x0F;
        dec->imm = 0;
        dec->size = 2;
        return 2;
    }
    else if (cls == 1 && code_len >= 4) {
        dec->op_shuf = tag & 0x1F;
        dec->rd = (code[1] >> 4) & 0x0F;
        dec->rs1 = code[1] & 0x0F;
        dec->rs2 = 0;
        uint16_t imm16 = (uint16_t)(code[2] | ((uint16_t)code[3] << 8));
        dec->imm = (int16_t)imm16;
        dec->size = 4;
        return 4;
    }
    else if (cls == 2 && code_len >= 9) {
        dec->op_shuf = code[1];
        dec->rd = code[2];
        dec->rs1 = code[3];
        dec->rs2 = code[4];
        dec->imm = (int32_t)(code[5] | ((uint32_t)code[6] << 8) |
                              ((uint32_t)code[7] << 16) | ((uint32_t)code[8] << 24));
        dec->size = 9;
        return 9;
    }
    else if (cls == 3 && code_len >= 10) {
        int num_blocks = tag & 0x0F;
        if (num_blocks == 0) num_blocks = 1;
        size_t total = (size_t)(2 + num_blocks * 8);
        if (code_len < total) return 0;
        dec->op_shuf = code[1];
        dec->rd = code[2];
        dec->rs1 = code[3];
        dec->rs2 = code[4];
        dec->imm = (int32_t)(code[5] | ((uint32_t)code[6] << 8) |
                              ((uint32_t)code[7] << 16) | ((uint32_t)code[8] << 24));
        dec->size = (int)total;
        return total;
    }

    return 0;
}
