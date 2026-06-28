#include "vm/vm.h"
#include <cstdlib>
#include <cstring>
#include <vector>

// ─── Polymorphic Encoder ──────────────────────────────────
// Encodes the same instruction in 2-3 different bit layouts.
// Variant selection is deterministic: (op+rd+rs1+rs2+imm+poly_seed) % num_variants
size_t vm_encode_polymorphic(uint8_t *out, size_t out_max,
                             uint8_t canonical_op,
                             uint8_t rd, uint8_t rs1, uint8_t rs2,
                             int32_t imm, int variant_id, int poly_seed) {
    if (!out || out_max < 2) return 0;

    int num_variants;
    bool short_ok = (rs2 == 0 && imm == 0);
    bool med_ok = (rs2 == 0 && imm >= -32768 && imm <= 32767);

    if (short_ok) num_variants = 3;
    else if (med_ok) num_variants = 2;
    else num_variants = 2;

    int sel = (variant_id >= 0) ? variant_id :
              (int)(((uint32_t)(canonical_op + rd + rs1 + rs2 + imm + poly_seed)) % num_variants);

    // ─── SHORT variants (rs2=0, imm=0) ────────────────────
    if (short_ok) {
        if (sel == 0 && out_max >= 2) {
            out[0] = (uint8_t)(0x00 | (canonical_op & 0x0F));
            out[1] = (uint8_t)(((rd & 0x0F) << 4) | (rs1 & 0x0F));
            return 2;
        }
        else if (sel == 1 && out_max >= 3) {
            // [TT00_RORD][RS14_OOOO] - interleaved reg/op
            out[0] = (uint8_t)(0x00 | ((rd & 0x03) << 2) | ((canonical_op >> 2) & 0x03));
            out[1] = (uint8_t)(((rd >> 2) & 0x03) | ((rs1 & 0x0F) << 2) |
                               ((canonical_op & 0x03) << 6));
            out[2] = (uint8_t)((canonical_op >> 4) & 0x0F);
            return 3;
        }
        else if (sel == 2 && out_max >= 3) {
            // [TT00_SSSS][OORR_RRRD] - scattered op, merged regs
            int scat = (canonical_op * 7 + poly_seed) & 0xFF;
            out[0] = (uint8_t)(0x00 | (scat & 0x0F));
            out[1] = (uint8_t)(((canonical_op & 0x03) << 6) | ((rd & 0x0F) << 2) | ((rs1 >> 2) & 0x03));
            out[2] = (uint8_t)(((rs1 & 0x03) << 6) | ((scat >> 4) & 0x0F) | ((canonical_op >> 2) & 0x30));
            return 3;
        }
        // fallback
        out[0] = (uint8_t)(0x00 | (canonical_op & 0x0F));
        out[1] = (uint8_t)(((rd & 0x0F) << 4) | (rs1 & 0x0F));
        return 2;
    }

    // ─── MEDIUM variants (rs2=0, 16-bit imm) ──────────────
    if (med_ok) {
        uint16_t imm16 = (uint16_t)(imm & 0xFFFF);
        if (sel == 0 && out_max >= 4) {
            out[0] = (uint8_t)(0x40 | (canonical_op & 0x1F));
            out[1] = (uint8_t)(((rd & 0x0F) << 4) | (rs1 & 0x0F));
            out[2] = (uint8_t)(imm16 & 0xFF);
            out[3] = (uint8_t)((imm16 >> 8) & 0xFF);
            return 4;
        }
        else if (sel == 1 && out_max >= 4) {
            // Lower 5 bits of imm in tag byte, bit 5 set = 1 to distinguish from variant 0
            out[0] = (uint8_t)(0x60 | (imm16 & 0x1F));  // bit 5 = 1 (variant 1 marker)
            out[1] = (uint8_t)(((rd & 0x0F) << 4) | (rs1 & 0x0F));
            out[2] = (uint8_t)(((imm16 >> 5) & 0xFF));
            out[3] = (uint8_t)(((canonical_op & 0x1F) << 3) | ((imm16 >> 13) & 0x07));
            return 4;
        }
        // fallback (also handles any remaining case)
        out[0] = (uint8_t)(0x40 | (canonical_op & 0x1F));
        out[1] = (uint8_t)(((rd & 0x0F) << 4) | (rs1 & 0x0F));
        out[2] = (uint8_t)(imm16 & 0xFF);
        out[3] = (uint8_t)((imm16 >> 8) & 0xFF);
        return 4;
    }

    // ─── LONG variants (full format, any opcode/regs/imm) ──
    if (out_max >= 9) {
        uint32_t imm32 = (uint32_t)imm;
        if (sel == 0 || out_max < 10) {
            out[0] = (uint8_t)0x80;
            out[1] = canonical_op;
            out[2] = rd;
            out[3] = rs1;
            out[4] = rs2;
            out[5] = (uint8_t)(imm32 & 0xFF);
            out[6] = (uint8_t)((imm32 >> 8) & 0xFF);
            out[7] = (uint8_t)((imm32 >> 16) & 0xFF);
            out[8] = (uint8_t)((imm32 >> 24) & 0xFF);
            return 9;
        }
        else if (sel == 1 && out_max >= 9) {
            out[0] = (uint8_t)0x84; // variant 1 tag: TT10_0001
            out[1] = rd;
            out[2] = canonical_op;
            out[3] = rs2;
            out[4] = rs1;
            out[5] = (uint8_t)(imm32 & 0xFF);
            out[6] = (uint8_t)((imm32 >> 8) & 0xFF);
            out[7] = (uint8_t)((imm32 >> 16) & 0xFF);
            out[8] = (uint8_t)((imm32 >> 24) & 0xFF);
            return 9;
        }
        else if (sel == 2 && out_max >= 10) {
            // Variant 2: 10B with split opcode, swapped imm bytes
            out[0] = (uint8_t)0x88; // variant 2 tag: TT10_0010
            out[1] = canonical_op;
            out[2] = rs2;
            out[3] = rd;
            out[4] = rs1;
            out[5] = (uint8_t)((imm32 >> 16) & 0xFF);
            out[6] = (uint8_t)((imm32 >> 24) & 0xFF);
            out[7] = (uint8_t)(imm32 & 0xFF);
            out[8] = (uint8_t)((imm32 >> 8) & 0xFF);
            out[9] = (uint8_t)(poly_seed & 0xFF) ^ 0xAA; // alignment-breaking filler
            return 10;
        }
        // fallback
        out[0] = (uint8_t)0x80;
        out[1] = canonical_op;
        out[2] = rd;
        out[3] = rs1;
        out[4] = rs2;
        out[5] = (uint8_t)(imm32 & 0xFF);
        out[6] = (uint8_t)((imm32 >> 8) & 0xFF);
        out[7] = (uint8_t)((imm32 >> 16) & 0xFF);
        out[8] = (uint8_t)((imm32 >> 24) & 0xFF);
        return 9;
    }

    return 0;
}

// ─── Polymorphic Decoder ──────────────────────────────────
// Detects variant based on tag byte bits and decodes accordingly.
size_t vm_decode_polymorphic(const uint8_t *code, size_t code_len,
                             VmDecodedInstr *dec) {
    if (!code || !dec || code_len < 2) return 0;

    uint8_t tag = code[0];
    int cls = (tag >> 6) & 0x3;
    memset(dec, 0, sizeof(*dec));

    if (cls == 0) {
        // Short class — check variant by size and bit pattern
        if (code_len >= 2) {
            // Try standard short decode (variant 0): tag & 0x0F = op
            uint8_t test_op = tag & 0x0F;
            uint8_t test_rd = (code[1] >> 4) & 0x0F;
            uint8_t test_rs1 = code[1] & 0x0F;
            // Check if this looks like valid variant 0 (reasonable reg values)
            if (test_rd < 64 && test_rs1 < 64 && (code_len == 2 || (code[2] & 0xC0) != 0)) {
                // Variant 0
                dec->op_shuf = test_op;
                dec->rd = test_rd;
                dec->rs1 = test_rs1;
                dec->size = 2;
                return 2;
            }
        }
        if (code_len >= 3) {
            // Try variant 1: [TT00_RORD][RS14_OOOO]
            uint8_t op_reconstructed =
                ((code[2] & 0x0F) << 4)     // op[7:4]
                | ((tag & 0x03) << 2)       // op[3:2]
                | ((code[1] >> 6) & 0x03);  // op[1:0]
            uint8_t rd_reconstructed =
                ((code[1] & 0x03) << 2)     // rd[4:3]
                | ((tag >> 2) & 0x03);      // rd[1:0]
            uint8_t rs1_reconstructed =
                (code[1] >> 2) & 0x0F;      // rs1[3:0]
            if (rd_reconstructed < 64) {
                dec->op_shuf = op_reconstructed;
                dec->rd = rd_reconstructed;
                dec->rs1 = rs1_reconstructed;
                dec->size = 3;
                return 3;
            }
        }
        if (code_len >= 3) {
            // Try variant 2: [TT00_SSSS][OORR_RRRD]
            uint8_t scat = tag & 0x0F;
            uint8_t op_lo = (code[1] >> 6) & 0x03;
            uint8_t rd_bits = (code[1] >> 2) & 0x0F;
            uint8_t rs1_hi = code[1] & 0x03;
            uint8_t rs1_lo = (code[2] >> 6) & 0x03;
            uint8_t scat_hi = (code[2] >> 2) & 0x0F;
            uint8_t op_hi = code[2] & 0x30;
            uint8_t op = ((scat_hi << 4) | op_hi | op_lo) & 0xFF;
            if (rd_bits < 64) {
                dec->op_shuf = op;
                dec->rd = rd_bits;
                dec->rs1 = (rs1_hi << 2) | rs1_lo;
                dec->size = 3;
                return 3;
            }
        }
        // Absolute fallback
        dec->op_shuf = tag & 0x0F;
        dec->rd = (code[1] >> 4) & 0x0F;
        dec->rs1 = code[1] & 0x0F;
        dec->size = 2;
        return 2;
    }
    else if (cls == 1) {
        // Medium class — use tag bit 5 to disambiguate variants
        bool variant_bit = (tag & 0x20) != 0;

        if (!variant_bit && code_len >= 4) {
            // Variant 0: standard [TT01_OOOOO], bit 5 = 0
            dec->op_shuf = tag & 0x1F;
            dec->rd = (code[1] >> 4) & 0x0F;
            dec->rs1 = code[1] & 0x0F;
            uint16_t imm16 = (uint16_t)(code[2] | ((uint16_t)code[3] << 8));
            dec->imm = (int16_t)imm16;
            dec->size = 4;
            return 4;
        }
        else if (variant_bit && code_len >= 4) {
            // Variant 1: imm in tag, bit 5 = 1
            uint8_t op1 = (code[3] >> 3) & 0x1F;
            dec->op_shuf = op1;
            dec->rd = (code[1] >> 4) & 0x0F;
            dec->rs1 = code[1] & 0x0F;
            uint16_t imm_lo = tag & 0x1F;
            uint16_t imm_hi = (uint16_t)(code[2] | ((uint16_t)(code[3] & 0x07) << 8));
            uint16_t imm16_1 = (uint16_t)((imm_hi << 5) | imm_lo);
            dec->imm = (int16_t)imm16_1;
            dec->size = 4;
            return 4;
        }
        // Fallback to variant 0
        dec->op_shuf = tag & 0x1F;
        dec->rd = (code[1] >> 4) & 0x0F;
        dec->rs1 = code[1] & 0x0F;
        uint16_t imm16 = (uint16_t)(code[2] | ((uint16_t)code[3] << 8));
        dec->imm = (int16_t)imm16;
        dec->size = 4;
        return 4;
    }
    else if (cls == 2) {
        // Long class — tag lower bits indicate variant
        if (code_len >= 9) {
            int long_variant = (tag >> 2) & 0x0F;
            if (long_variant == 0 && code_len >= 9) {
                dec->op_shuf = code[1];
                dec->rd = code[2];
                dec->rs1 = code[3];
                dec->rs2 = code[4];
                dec->imm = (int32_t)(code[5] | ((uint32_t)code[6] << 8) |
                                     ((uint32_t)code[7] << 16) | ((uint32_t)code[8] << 24));
                dec->size = 9;
                return 9;
            }
            else if (long_variant == 1 && code_len >= 9) {
                dec->op_shuf = code[2];
                dec->rd = code[1];
                dec->rs1 = code[4];
                dec->rs2 = code[3];
                dec->imm = (int32_t)(code[5] | ((uint32_t)code[6] << 8) |
                                     ((uint32_t)code[7] << 16) | ((uint32_t)code[8] << 24));
                dec->size = 9;
                return 9;
            }
            else if (long_variant == 2 && code_len >= 10) {
                dec->op_shuf = code[1];
                dec->rd = code[3];
                dec->rs1 = code[4];
                dec->rs2 = code[2];
                dec->imm = (int32_t)(code[7] | ((uint32_t)code[8] << 8) |
                                     ((uint32_t)code[5] << 16) | ((uint32_t)code[6] << 24));
                dec->size = 10;
                return 10;
            }
        }
        // Fallback to standard decode
        if (code_len >= 9) {
            dec->op_shuf = code[1];
            dec->rd = code[2];
            dec->rs1 = code[3];
            dec->rs2 = code[4];
            dec->imm = (int32_t)(code[5] | ((uint32_t)code[6] << 8) |
                                  ((uint32_t)code[7] << 16) | ((uint32_t)code[8] << 24));
            dec->size = 9;
            return 9;
        }
    }
    else if (cls == 3) {
        // Extended
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
