#include "vm/vm.h"
#include <cstdlib>
#include <cstring>
#include <vector>
#include <algorithm>
#include <cstdint>

// ─── Lightweight XOR-based checksum ──────────────────────────
static uint32_t compute_xor_checksum(const uint8_t *data, int len) {
    uint32_t sum = 0xFFFFFFFF;
    for (int i = 0; i < len; i++) {
        sum ^= (uint32_t)data[i];
        sum = (sum << 7) | (sum >> 25);
        sum ^= (sum >> 13);
    }
    return sum ^ 0xFFFFFFFF;
}

// ─── Basic block analysis on fixed-size VmInstr array ──────
// Returns list of instruction indices that are block starts
static std::vector<int> find_block_starts(VmInstr *instrs, int count) {
    std::vector<int> starts;
    if (count == 0) return starts;

    // Block 0 starts at instruction 0
    starts.push_back(0);

    // Track jump targets
    std::vector<bool> is_target((size_t)count, false);
    for (int i = 0; i < count; i++) {
        int op = instrs[i].op;
        if (op == VM_JMP || op == VM_JMP_IF_TRUE || op == VM_JMP_IF_FALSE ||
            op == VM_JMP_EQ || op == VM_JMP_NE || op == VM_JMP_LT ||
            op == VM_JMP_LE || op == VM_JMP_GT || op == VM_JMP_GE ||
            op == VM_JMP_IF_TRUE_OBF || op == VM_JMP_IF_FALSE_OBF ||
            op == VM_JMP_INDIRECT || op == VM_FOR_ITER) {
            int target = instrs[i].imm;
            if (target >= 0 && target < count)
                is_target[(size_t)target] = true;
            // Fall-through: instruction after jump starts a new block
            if (i + 1 < count)
                is_target[(size_t)(i + 1)] = true;
        }
        if (op == VM_RETURN) {
            if (i + 1 < count)
                is_target[(size_t)(i + 1)] = true;
        }
    }

    for (int i = 1; i < count; i++) {
        if (is_target[(size_t)i])
            starts.push_back(i);
    }

    // Sort and deduplicate
    std::sort(starts.begin(), starts.end());
    starts.erase(std::unique(starts.begin(), starts.end()), starts.end());

    return starts;
}

// ─── CFI Pass ──────────────────────────────────────────────
// Computes block checksums and inserts CFI_CHECK instructions.
// Operates on fixed-size VmInstr array BEFORE VL encoding.
ExitCode vm_pass_cfi(VmProgram *prog, VmCompileConfig *cfg) {
    if (!prog || !cfg) return EXIT_ERR_ARGS;
    if (!prog->instrs || prog->count == 0) return EXIT_OK;

    // Use VL-encoded code if available (post-encoding), else use fixed-size instrs
    bool use_vl = (prog->vl_code && prog->vl_code_len > 0);

    // Compute block starts from fixed-size instrs
    std::vector<int> block_starts = find_block_starts(prog->instrs, prog->count);

    // Compute block lengths and checksums
    int num_blocks = (int)block_starts.size();
    if (num_blocks == 0 || num_blocks > VM_CFI_MAX_BLOCKS) return EXIT_OK;

    std::vector<int> block_lengths((size_t)num_blocks, 0);
    std::vector<uint32_t> block_checksums((size_t)num_blocks, 0);

    for (int bi = 0; bi < num_blocks; bi++) {
        int start = block_starts[bi];
        int end = (bi + 1 < num_blocks) ? block_starts[bi + 1] : prog->count;
        int len = end - start;
        block_lengths[bi] = len;

        if (use_vl) {
            // Map instruction range to VL code byte range
            VmDecodedInstr dec;
            int byte_pos = 0;
            int instr_idx = 0;
            int block_byte_start = -1;
            int block_byte_end = -1;

            while (byte_pos < prog->vl_code_len && instr_idx < prog->count) {
                size_t consumed = vm_decode_var_length(
                    prog->vl_code + byte_pos,
                    (size_t)(prog->vl_code_len - byte_pos),
                    &dec);
                if (consumed == 0) break;
                if (instr_idx == start)
                    block_byte_start = byte_pos;
                if (instr_idx == end) {
                    block_byte_end = byte_pos;
                    break;
                }
                byte_pos += (int)consumed;
                instr_idx++;
            }
            if (block_byte_end < 0)
                block_byte_end = byte_pos;

            if (block_byte_start >= 0 && block_byte_end > block_byte_start) {
                block_checksums[bi] = compute_xor_checksum(
                    prog->vl_code + block_byte_start,
                    block_byte_end - block_byte_start);
            }
        } else {
            // Compute checksum over fixed-size instructions
            uint8_t buf[256 * 8];
            int buf_len = 0;
            for (int j = start; j < end && j < prog->count; j++) {
                memcpy(buf + buf_len, &prog->instrs[j], sizeof(VmInstr));
                buf_len += (int)sizeof(VmInstr);
            }
            block_checksums[bi] = compute_xor_checksum(buf, buf_len);
        }
    }

    // At compile time, insert VM_CFI_CHECK instructions at block entries
    // We insert them just before the first instruction of each block
    // by prepending a CFI_CHECK before each block start.
    int extra_instrs = num_blocks;
    std::vector<VmInstr> new_instrs;
    new_instrs.reserve((size_t)prog->count + (size_t)extra_instrs);

    int bi = 0;
    for (int i = 0; i < prog->count; i++) {

        // Insert CFI_CHECK before block start (skip block 0 start which is instr 0)
        if (bi < num_blocks && i == block_starts[bi] && bi > 0 &&
            block_starts[bi] > 0) {
            VmInstr cfi;
            cfi.op = VM_CFI_CHECK;
            cfi.rd = (uint8_t)(block_checksums[bi] & 0xFF);
            cfi.rs1 = (uint8_t)((block_checksums[bi] >> 8) & 0xFF);
            cfi.rs2 = (uint8_t)((block_checksums[bi] >> 16) & 0xFF);
            cfi.imm = (int32_t)((block_checksums[bi] >> 24) & 0xFF);
            new_instrs.push_back(cfi);
        }

        new_instrs.push_back(prog->instrs[i]);

        // Also insert CFI_CHECK before the next block if appropriate
        if (bi + 1 < num_blocks && i + 1 == block_starts[bi + 1]) {
            bi++;
            // CHECK inserted at top of loop for next iteration
        }
    }

    // Also check block 0 at a strategic point
    {
        VmInstr cfi;
        cfi.op = VM_CFI_CHECK;
        cfi.rd = (uint8_t)(block_checksums[0] & 0xFF);
        cfi.rs1 = (uint8_t)((block_checksums[0] >> 8) & 0xFF);
        cfi.rs2 = (uint8_t)((block_checksums[0] >> 16) & 0xFF);
        cfi.imm = (int32_t)((block_checksums[0] >> 24) & 0xFF);
        // Insert after first few instructions of block 0
        int insert_after = std::min(3, prog->count);
        new_instrs.insert(new_instrs.begin() + insert_after, cfi);
    }

    // Store CFI data for serialization
    prog->cfi_num_blocks = num_blocks;
    prog->cfi_checksums = (uint32_t *)malloc((size_t)num_blocks * sizeof(uint32_t));
    prog->cfi_block_starts = (int *)malloc((size_t)num_blocks * sizeof(int));
    prog->cfi_block_lengths = (int *)malloc((size_t)num_blocks * sizeof(int));
    if (!prog->cfi_checksums || !prog->cfi_block_starts || !prog->cfi_block_lengths)
        return EXIT_ERR_CRYPTO;

    for (int i = 0; i < num_blocks; i++) {
        prog->cfi_checksums[i] = block_checksums[i];
        prog->cfi_block_starts[i] = block_starts[i];
        prog->cfi_block_lengths[i] = block_lengths[i];
    }

    // Replace instruction array
    VmInstr *nd = (VmInstr *)realloc(prog->instrs,
                                      new_instrs.size() * sizeof(VmInstr));
    if (nd || new_instrs.size() == 0) {
        if (nd) prog->instrs = nd;
        memcpy(prog->instrs, new_instrs.data(),
               new_instrs.size() * sizeof(VmInstr));
        prog->count = (int)new_instrs.size();
    }

    prog->flags |= VM_SER_FLAG_CFI_ENABLED;

    return EXIT_OK;
}
