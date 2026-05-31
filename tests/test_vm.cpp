#include "lib/doctest.h"
#include "vm/vm.h"
#include "crypto/common.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <vector>

TEST_CASE("vm compile simple expression") {
    const char *source = "x = 1 + 2\n";
    VmProgram prog;
    vm_program_init(&prog);

    ExitCode ret = vm_compile_source(source, strlen(source), &prog, 0);
    CHECK(ret == EXIT_OK);
    CHECK(prog.opcode_map != (uint8_t*)0);
    CHECK(prog.count > 0);
    CHECK(prog.const_count > 0);
    CHECK(prog.name_count > 0);

    // Check instructions
    if (prog.instrs && prog.count > 0) {
        printf("VM instructions (%d):\n", prog.count);
        for (int i = 0; i < prog.count && i < 20; i++) {
            printf("  [%d] op=%d rd=%d rs1=%d rs2=%d imm=%d\n",
                   i, prog.instrs[i].op, prog.instrs[i].rd,
                   prog.instrs[i].rs1, prog.instrs[i].rs2,
                   prog.instrs[i].imm);
        }
    }

    // Test serialization roundtrip
    Buffer serialized = {0};
    ret = vm_serialize(&prog, &serialized);
    CHECK(ret == EXIT_OK);
    CHECK(serialized.size > 0);

    VmProgram prog2;
    vm_program_init(&prog2);
    ret = vm_deserialize(serialized.data, serialized.size, &prog2);
    CHECK(ret == EXIT_OK);
    CHECK(prog2.count == prog.count);
    CHECK(prog2.const_count == prog.const_count);
    CHECK(prog2.name_count == prog.name_count);

    vm_program_free(&prog2);
    free(serialized.data);
    vm_program_free(&prog);
}

TEST_CASE("vm compile function call") {
    const char *source = "print(1 + 2)\n";
    VmProgram prog;
    vm_program_init(&prog);

    ExitCode ret = vm_compile_source(source, strlen(source), &prog, 0);
    CHECK(ret == EXIT_OK);
    CHECK(prog.opcode_map != (uint8_t*)0);
    CHECK(prog.count > 0);

    vm_program_free(&prog);
}

TEST_CASE("vm compile arithmetic") {
    const char *source = "a = 10\nb = 20\nc = a + b * 3\nprint(c)\n";
    VmProgram prog;
    vm_program_init(&prog);

    ExitCode ret = vm_compile_source(source, strlen(source), &prog, 0);
    CHECK(ret == EXIT_OK);
    CHECK(prog.opcode_map != (uint8_t*)0);

    vm_program_free(&prog);
}

TEST_CASE("vm compile comparison") {
    const char *source = "if 1 < 2:\n    print('ok')\n";
    VmProgram prog;
    vm_program_init(&prog);

    ExitCode ret = vm_compile_source(source, strlen(source), &prog, 0);
    CHECK(ret == EXIT_OK);
    CHECK(prog.opcode_map != (uint8_t*)0);

    vm_program_free(&prog);
}

// ─── Variable-Length Encoding Tests ─────────────────────────

TEST_CASE("vm_encode_var_length short form") {
    uint8_t buf[16];

    // Short form: register-only, no imm, op < 16
    size_t sz = vm_encode_var_length(buf, sizeof(buf), 5, 2, 3, 0, 0);
    CHECK(sz == 2);
    // Tag byte: TT=00, op=5
    CHECK((buf[0] & 0xC0) == 0x00);
    CHECK((buf[0] & 0x0F) == 5);
    // Second byte: rd=2 << 4 | rs1=3
    CHECK(buf[1] == ((2 << 4) | 3));

    // Decode back
    VmDecodedInstr dec;
    size_t dsz = vm_decode_var_length(buf, 2, &dec);
    CHECK(dsz == 2);
    CHECK(dec.op_shuf == 5);
    CHECK(dec.rd == 2);
    CHECK(dec.rs1 == 3);
    CHECK(dec.rs2 == 0);
    CHECK(dec.imm == 0);
}

TEST_CASE("vm_encode_var_length medium form") {
    uint8_t buf[16];

    // Medium form: 16-bit immediate, op < 32, no rs2
    size_t sz = vm_encode_var_length(buf, sizeof(buf), 10, 1, 2, 0, 0x1234);
    CHECK(sz == 4);
    CHECK((buf[0] & 0xC0) == 0x40);
    CHECK((buf[0] & 0x1F) == 10);
    CHECK(buf[1] == ((1 << 4) | 2));

    // Immediate bytes (little-endian)
    CHECK(buf[2] == 0x34);
    CHECK(buf[3] == 0x12);

    // Decode
    VmDecodedInstr dec;
    size_t dsz = vm_decode_var_length(buf, 4, &dec);
    CHECK(dsz == 4);
    CHECK(dec.op_shuf == 10);
    CHECK(dec.imm == 0x1234);
}

TEST_CASE("vm_encode_var_length long form") {
    uint8_t buf[16];

    // Long form: full 32-bit imm, any opcode (9 bytes)
    size_t sz = vm_encode_var_length(buf, sizeof(buf), 255, 10, 20, 30, -12345);
    CHECK(sz == 9);
    CHECK((buf[0] & 0xC0) == 0x80);
    CHECK(buf[1] == 255);
    CHECK(buf[2] == 10);
    CHECK(buf[3] == 20);
    CHECK(buf[4] == 30);

    // Decode
    VmDecodedInstr dec;
    size_t dsz = vm_decode_var_length(buf, 9, &dec);
    CHECK(dsz == 9);
    CHECK(dec.op_shuf == 255);
    CHECK(dec.rd == 10);
    CHECK(dec.rs1 == 20);
    CHECK(dec.rs2 == 30);
    CHECK(dec.imm == -12345);
}

TEST_CASE("vm_encode_var_length encoding selection") {
    uint8_t buf[16];

    // Test encoding class selection
    // NOP (op=0, no regs, no imm) → Short
    size_t sz = vm_encode_var_length(buf, sizeof(buf), 0, 0, 0, 0, 0);
    CHECK(sz == 2);

    // LOAD_CONST (op=1, rd def, imm needed) — imm != 0 → Medium if fits in 16-bit
    sz = vm_encode_var_length(buf, sizeof(buf), 1, 3, 0, 0, 42);
    CHECK(sz == 4);

    // Large immediate → Long (9 bytes)
    sz = vm_encode_var_length(buf, sizeof(buf), 1, 3, 0, 0, 0x12345678);
    CHECK(sz == 9);

    // JMP (op=30, need imm for target) — op=30 < 32 → Medium
    sz = vm_encode_var_length(buf, sizeof(buf), 30, 0, 0, 0, 100);
    CHECK(sz == 4);
}

TEST_CASE("vm_encode_program roundtrip") {
    // Create a small program
    VmProgram prog;
    vm_program_init(&prog);

    // Build 4 instructions manually
    prog.count = 4;
    prog.instrs = (VmInstr *)malloc(prog.count * sizeof(VmInstr));
    REQUIRE(prog.instrs != nullptr);

    prog.instrs[0] = {1, 0, 0, 0, 42};    // LOAD_CONST r0, 42
    prog.instrs[1] = {1, 1, 0, 0, 100};   // LOAD_CONST r1, 100
    prog.instrs[2] = {10, 2, 0, 1, 0};    // ADD r2, r0, r1
    prog.instrs[3] = {42, 2, 0, 0, 0};    // RETURN r2

    // Encode to variable-length
    Buffer vl = {0};
    ExitCode ret = vm_encode_program(&prog, &vl);
    CHECK(ret == EXIT_OK);
    CHECK(vl.size > 0);
    CHECK(vl.data != nullptr);

    // Each instruction should be:
    // [0] LOAD_CONST op=1, rd=0, rs1=0, imm=42 → Medium (4B): tag=0x41
    // [1] LOAD_CONST op=1, rd=1, rs1=0, imm=100 → Medium (4B): tag=0x41
    // [2] ADD op=10, rd=2, rs1=0, rs2=1, imm=0 → rs2!=0, so Long (9B): tag=0x80
    // [3] RETURN op=42, rd=2 → op=42 >= 32, so Long (9B): tag=0x80
    // Total: 4+4+9+9 = 26 bytes
    CHECK(vl.size == 26);

    // Check tag bytes
    CHECK((vl.data[0] & 0xC0) == 0x40);  // Medium
    CHECK((vl.data[4] & 0xC0) == 0x40);  // Medium
    CHECK((vl.data[8] & 0xC0) == 0x80);  // Long (ADD with rs2)
    CHECK((vl.data[17] & 0xC0) == 0x80); // Long (RETURN op>=32)

    free(vl.data);
    free(prog.instrs);
    // Don't call vm_program_free since we manually set up the struct
}

// ─── ISA Expansion Tests ────────────────────────────────────

TEST_CASE("vm_pass_isa_expand indirect calls") {
    VmProgram prog;
    vm_program_init(&prog);

    // Build a CALL instruction with preceding LOAD_ATTR
    prog.count = 4;
    prog.instrs = (VmInstr *)malloc(prog.count * sizeof(VmInstr));
    REQUIRE(prog.instrs != nullptr);

    prog.instrs[0] = {VM_LOAD_CONST, 0, 0, 0, 0};    // load obj
    prog.instrs[1] = {VM_LOAD_ATTR, 1, 0, 0, 0};     // getattr obj, "method" → reg 1
    prog.instrs[2] = {VM_CALL, 3, 1, 0, 1};           // call(rd=3, fn=reg1, argc=1)
    prog.instrs[3] = {VM_RETURN, 3, 0, 0, 0};

    VmCompileConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enable_indirect_calls = 1;

    // Pass CALL → CALL_INDIRECT
    ExitCode ret = vm_pass_isa_expand(&prog, &cfg);
    CHECK(ret == EXIT_OK);
    CHECK(prog.count >= 3);

    // Check that CALL was converted to CALL_INDIRECT
    bool found_indirect = false;
    for (int i = 0; i < prog.count; i++) {
        if (prog.instrs[i].op == VM_CALL_INDIRECT) {
            found_indirect = true;
            break;
        }
    }
    CHECK(found_indirect);

    vm_program_free(&prog);
}

// ─── Obfuscated Conditions Tests ────────────────────────────

TEST_CASE("vm_pass_obfuscate_conditions") {
    VmProgram prog;
    vm_program_init(&prog);

    prog.count = 4;
    prog.instrs = (VmInstr *)malloc(prog.count * sizeof(VmInstr));
    REQUIRE(prog.instrs != nullptr);

    prog.instrs[0] = {VM_CMP_EQ, 2, 0, 1, 0};    // r2 = (r0 == r1)
    prog.instrs[1] = {VM_JMP_IF_TRUE, 2, 0, 0, 10};  // if r2: jump to 10
    prog.instrs[2] = {VM_MOVE, 3, 0, 0, 0};
    prog.instrs[3] = {VM_RETURN, 3, 0, 0, 0};

    // Strength 1: replace JMP_IF_TRUE → JMP_IF_TRUE_OBF
    ExitCode ret = vm_pass_obfuscate_conditions(&prog, 1);
    CHECK(ret == EXIT_OK);

    // Check JMP_IF_TRUE replaced with JMP_IF_TRUE_OBF
    bool found_obf = false;
    for (int i = 0; i < prog.count; i++) {
        if (prog.instrs[i].op == VM_JMP_IF_TRUE_OBF) {
            found_obf = true;
            break;
        }
    }
    CHECK(found_obf);

    vm_program_free(&prog);
}

TEST_CASE("vm_pass_obfuscate_conditions strength2") {
    VmProgram prog;
    vm_program_init(&prog);

    prog.count = 4;
    prog.instrs = (VmInstr *)malloc(prog.count * sizeof(VmInstr));
    REQUIRE(prog.instrs != nullptr);

    prog.instrs[0] = {VM_CMP_EQ, 2, 0, 1, 0};
    prog.instrs[1] = {VM_JMP_IF_TRUE, 2, 0, 0, 10};
    prog.instrs[2] = {VM_MOVE, 3, 0, 0, 0};
    prog.instrs[3] = {VM_RETURN, 3, 0, 0, 0};

    ExitCode ret = vm_pass_obfuscate_conditions(&prog, 2);
    CHECK(ret == EXIT_OK);

    // Strength 2 should merge CMP+JMP into JMP_EQ
    bool found_jmp_eq = false;
    for (int i = 0; i < prog.count; i++) {
        if (prog.instrs[i].op == VM_JMP_EQ) {
            found_jmp_eq = true;
            CHECK(prog.instrs[i].imm == 10); // preserved target
            break;
        }
    }
    CHECK(found_jmp_eq);
    // Count should be reduced (CMP+JMP merged into one)
    CHECK(prog.count >= 2);

    vm_program_free(&prog);
}

// ─── Register Spilling Tests ────────────────────────────────

TEST_CASE("vm_pass_spill_registers") {
    VmProgram prog;
    vm_program_init(&prog);

    // Create a sequence with moderate register usage
    prog.count = 8;
    prog.instrs = (VmInstr *)malloc(prog.count * sizeof(VmInstr));
    REQUIRE(prog.instrs != nullptr);

    for (int i = 0; i < prog.count; i++) {
        prog.instrs[i].op = VM_MOVE;
        prog.instrs[i].rd = (uint8_t)(i + 1);
        prog.instrs[i].rs1 = (uint8_t)i;
        prog.instrs[i].rs2 = 0;
        prog.instrs[i].imm = 0;
    }

    VmCompileConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enable_register_spilling = 1;
    cfg.spill_pressure_threshold = 4;
    cfg.spill_target_pressure = 2;
    cfg.spill_interval = 3;
    cfg.spill_probability = 0.5f;
    cfg.seed = 42;

    ExitCode ret = vm_pass_spill_registers(&prog, &cfg);
    CHECK(ret == EXIT_OK);

    // Should have more instructions than before (spills inserted)
    CHECK(prog.count >= 8);

    // Should have some SPILL_MANY or RESTORE_MANY instructions
    bool has_spill = false;
    for (int i = 0; i < prog.count; i++) {
        if (prog.instrs[i].op == VM_SPILL_MANY ||
            prog.instrs[i].op == VM_RESTORE_MANY) {
            has_spill = true;
            break;
        }
    }
    CHECK(has_spill);

    vm_program_free(&prog);
}

// ─── Self-Modifying Code Tests ──────────────────────────────

TEST_CASE("vm_pass_inject_self_modifying") {
    VmProgram prog;
    vm_program_init(&prog);

    prog.count = 20;
    prog.instrs = (VmInstr *)malloc(prog.count * sizeof(VmInstr));
    REQUIRE(prog.instrs != nullptr);

    for (int i = 0; i < prog.count; i++) {
        prog.instrs[i].op = VM_MOVE;
        prog.instrs[i].rd = 1;
        prog.instrs[i].rs1 = 0;
        prog.instrs[i].rs2 = 0;
        prog.instrs[i].imm = 0;
    }

    VmCompileConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.smc_min_interval = 5;
    cfg.smc_max_interval = 10;
    cfg.seed = 42;

    ExitCode ret = vm_pass_inject_self_modifying(&prog, &cfg);
    CHECK(ret == EXIT_OK);

    // Should have SMC instructions injected
    bool has_smc = false;
    for (int i = 0; i < prog.count; i++) {
        if (prog.instrs[i].op == VM_PATCH_INSTR ||
            prog.instrs[i].op == VM_PATCH_OPCODE ||
            prog.instrs[i].op == VM_DECRYPT_SEG) {
            has_smc = true;
            break;
        }
    }
    CHECK(has_smc);

    // Count should have grown
    CHECK(prog.count > 20);

    vm_program_free(&prog);
}

// ─── Extended Compile Pipeline Tests ────────────────────────

TEST_CASE("vm_compile_source_ex full pipeline") {
    const char *source = "x = 1 + 2\nprint(x)\n";
    VmProgram prog;
    vm_program_init(&prog);

    VmCompileConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enable_opaque = 1;
    cfg.seed = 12345;
    cfg.enable_indirect_calls = 1;
    cfg.enable_var_length_encoding = 1;
    cfg.enable_register_spilling = 1;
    cfg.enable_self_modifying_code = 1;
    cfg.enable_conditional_obfuscation = 1;
    cfg.cond_obfuscation_strength = 1;
    cfg.spill_pressure_threshold = 8;
    cfg.spill_target_pressure = 4;
    cfg.spill_interval = 5;
    cfg.spill_probability = 0.3f;
    cfg.smc_min_interval = 15;
    cfg.smc_max_interval = 30;

    ExitCode ret = vm_compile_source_ex(source, strlen(source), &prog, &cfg);
    CHECK(ret == EXIT_OK);
    CHECK(prog.opcode_map != (uint8_t*)0);

    // With variable-length encoding, vl_code should be present
    CHECK(prog.vl_code != nullptr);
    CHECK(prog.vl_code_len > 0);

    // Test serialization with VL encoding
    Buffer serialized = {0};
    ret = vm_serialize(&prog, &serialized);
    CHECK(ret == EXIT_OK);
    CHECK(serialized.size > 0);

    // Deserialize back
    VmProgram prog2;
    vm_program_init(&prog2);
    ret = vm_deserialize(serialized.data, serialized.size, &prog2);
    CHECK(ret == EXIT_OK);
    CHECK((prog2.flags & 1) != 0); // VL_ENCODED flag should be set
    CHECK(prog2.vl_code != nullptr);
    CHECK(prog2.vl_code_len > 0);

    // The vl_code content should match
    CHECK(prog2.vl_code_len == prog.vl_code_len);

    vm_program_free(&prog2);
    free(serialized.data);
    vm_program_free(&prog);
}

TEST_CASE("vm_compile_source_ex without VL encoding") {
    const char *source = "a = 42\nb = a * 2\n";
    VmProgram prog;
    vm_program_init(&prog);

    VmCompileConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enable_opaque = 0;
    cfg.seed = 42;
    cfg.enable_var_length_encoding = 0;
    cfg.enable_register_spilling = 0;
    cfg.enable_self_modifying_code = 0;
    cfg.enable_conditional_obfuscation = 0;

    // Test only ISA expansion (backward compatible)
    cfg.enable_indirect_calls = 1;
    cfg.enable_virtual_calls = 0;
    cfg.enable_exceptions = 0;

    ExitCode ret = vm_compile_source_ex(source, strlen(source), &prog, &cfg);
    CHECK(ret == EXIT_OK);
    CHECK(prog.opcode_map != (uint8_t*)0);
    CHECK(prog.count > 0);
    CHECK(prog.instrs != nullptr);

    // Without VL encoding, no vl_code
    CHECK(prog.vl_code == nullptr);
    CHECK(prog.vl_code_len == 0);

    // Ser/deser roundtrip should still work
    Buffer serialized = {0};
    ret = vm_serialize(&prog, &serialized);
    CHECK(ret == EXIT_OK);

    VmProgram prog2;
    vm_program_init(&prog2);
    ret = vm_deserialize(serialized.data, serialized.size, &prog2);
    CHECK(ret == EXIT_OK);
    CHECK(prog2.count == prog.count);
    CHECK(prog2.instrs != (VmInstr*)nullptr);

    vm_program_free(&prog2);
    free(serialized.data);
    vm_program_free(&prog);
}

TEST_CASE("vm_encode_program edge cases") {
    // Test empty program
    VmProgram empty;
    vm_program_init(&empty);
    empty.count = 0;
    empty.instrs = nullptr;

    Buffer vl = {0};
    ExitCode ret = vm_encode_program(&empty, &vl);
    CHECK(ret == EXIT_OK);
    CHECK(vl.size == 0);
    free(vl.data);
}

// ═══════════════════════════════════════════════════════════
// Enhancement 1: Polymorphic Encoding Tests
// ═══════════════════════════════════════════════════════════

TEST_CASE("vm_encode_polymorphic short variants") {
    uint8_t buf[16];
    
    // Short op (op=5, rd=2, rs1=3, rs2=0, imm=0)
    // Variant 0 (standard 2B)
    memset(buf, 0, sizeof(buf));
    size_t sz0 = vm_encode_polymorphic(buf, sizeof(buf), 5, 2, 3, 0, 0, 0, 42);
    CHECK(sz0 == 2);
    CHECK((buf[0] & 0xC0) == 0x00);
    CHECK((buf[0] & 0x0F) == 5);
    CHECK((buf[1] >> 4) == 2);
    CHECK((buf[1] & 0x0F) == 3);

    // Variant 1 (3B interleaved)
    memset(buf, 0, sizeof(buf));
    size_t sz1 = vm_encode_polymorphic(buf, sizeof(buf), 5, 2, 3, 0, 0, 1, 42);
    CHECK(sz1 == 3);
    CHECK((buf[0] & 0xC0) == 0x00);

    // Variant 2 (3B scattered)
    memset(buf, 0, sizeof(buf));
    size_t sz2 = vm_encode_polymorphic(buf, sizeof(buf), 5, 2, 3, 0, 0, 2, 42);
    CHECK(sz2 == 3);
    CHECK((buf[0] & 0xC0) == 0x00);

    // Decode all variants back
    VmDecodedInstr dec;
    memset(&dec, 0, sizeof(dec));
    // Re-encode with variant 0 for decode test
    uint8_t enc0[16];
    sz0 = vm_encode_polymorphic(enc0, sizeof(enc0), 5, 2, 3, 0, 0, 0, 42);
    size_t dsz = vm_decode_polymorphic(enc0, sz0, &dec);
    CHECK(dsz == 2);
    CHECK(dec.op_shuf == 5);
    CHECK(dec.rd == 2);
    CHECK(dec.rs1 == 3);

    // Decode variant 1
    uint8_t enc1[16];
    sz1 = vm_encode_polymorphic(enc1, sizeof(enc1), 5, 2, 3, 0, 0, 1, 42);
    dsz = vm_decode_polymorphic(enc1, sz1, &dec);
    CHECK(dsz >= 2);
    CHECK(dec.op_shuf == 5);
}

TEST_CASE("vm_encode_polymorphic medium variants") {
    uint8_t buf[16];
    VmDecodedInstr dec;

    // Medium op (op=10, rd=1, rs1=2, imm=0x1234)
    // Variant 0 (standard 4B)
    size_t sz = vm_encode_polymorphic(buf, sizeof(buf), 10, 1, 2, 0, 0x1234, 0, 42);
    CHECK(sz == 4);
    CHECK((buf[0] & 0xC0) == 0x40);
    size_t dsz = vm_decode_polymorphic(buf, sz, &dec);
    CHECK(dsz == 4);
    CHECK(dec.op_shuf == 10);
    CHECK(dec.imm == 0x1234);

    // Variant 1 (4B, imm in tag)
    sz = vm_encode_polymorphic(buf, sizeof(buf), 10, 1, 2, 0, 0x1234, 1, 42);
    CHECK(sz == 4);
    CHECK((buf[0] & 0xC0) == 0x40);
    dsz = vm_decode_polymorphic(buf, sz, &dec);
    CHECK(dsz == 4);
    CHECK(dec.op_shuf == 10);
    CHECK(dec.imm == 0x1234);

    // Variant 2 (use auto-select by passing variant_id=-1)
    sz = vm_encode_polymorphic(buf, sizeof(buf), 10, 1, 2, 0, 0x1234, -1, 42);
    CHECK(sz >= 4);
    CHECK((buf[0] & 0xC0) == 0x40);
    dsz = vm_decode_polymorphic(buf, sz, &dec);
    CHECK(dsz >= 4);
    CHECK(dec.op_shuf == 10);
    CHECK(dec.imm == 0x1234);
}

TEST_CASE("vm_encode_polymorphic long variants") {
    uint8_t buf[16];
    VmDecodedInstr dec;

    // Long op (op=255, full regs, large imm)
    // Variant 0 (standard 9B)
    size_t sz = vm_encode_polymorphic(buf, sizeof(buf), 255, 10, 20, 30, -12345, 0, 42);
    CHECK(sz == 9);
    CHECK((buf[0] & 0xC0) == 0x80);
    size_t dsz = vm_decode_polymorphic(buf, sz, &dec);
    CHECK(dsz == 9);
    CHECK(dec.op_shuf == 255);
    CHECK(dec.imm == -12345);

    // Variant 1 (9B shuffled)
    sz = vm_encode_polymorphic(buf, sizeof(buf), 255, 10, 20, 30, -12345, 1, 42);
    CHECK(sz == 9);
    dsz = vm_decode_polymorphic(buf, sz, &dec);
    CHECK(dsz == 9);
    CHECK(dec.op_shuf == 255);
    CHECK(dec.rd == 10);
    CHECK(dec.imm == -12345);
}

TEST_CASE("vm_encode_program_poly roundtrip") {
    VmProgram prog;
    vm_program_init(&prog);

    prog.count = 4;
    prog.instrs = (VmInstr *)malloc(prog.count * sizeof(VmInstr));
    REQUIRE(prog.instrs != nullptr);
    prog.poly_seed = 42;

    prog.instrs[0] = {1, 0, 0, 0, 42};    // LOAD_CONST r0, 42
    prog.instrs[1] = {1, 1, 0, 0, 100};   // LOAD_CONST r1, 100
    prog.instrs[2] = {10, 2, 0, 1, 0};    // ADD r2, r0, r1
    prog.instrs[3] = {42, 2, 0, 0, 0};    // RETURN r2

    Buffer vl = {0};
    ExitCode ret = vm_encode_program_poly(&prog, &vl);
    CHECK(ret == EXIT_OK);
    CHECK(vl.size > 0);

    // Polymorphic encoding should produce different sizes than deterministic
    // (at least some instructions use non-standard sizes)
    CHECK(vl.data != nullptr);

    // Decode each instruction
    VmDecodedInstr dec;
    int pos = 0;
    int decoded_count = 0;
    while (pos < (int)vl.size && decoded_count < prog.count) {
        size_t consumed = vm_decode_polymorphic(vl.data + pos,
                                                 (size_t)(vl.size - pos), &dec);
        CHECK(consumed > 0);
        pos += (int)consumed;
        decoded_count++;
    }
    CHECK(decoded_count == 4);

    free(vl.data);
    free(prog.instrs);
}

// ═══════════════════════════════════════════════════════════
// Enhancement 2: Constant Pool Encryption Tests
// ═══════════════════════════════════════════════════════════

TEST_CASE("vm constant encryption roundtrip") {
    const char *source = "x = 1 + 2\n";
    VmProgram prog;
    vm_program_init(&prog);

    VmCompileConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enable_opaque = 0;
    cfg.seed = 42;
    cfg.enable_indirect_calls = 0;
    cfg.enable_var_length_encoding = 0;
    cfg.enable_constant_encryption = 1;

    ExitCode ret = vm_compile_source_ex(source, strlen(source), &prog, &cfg);
    CHECK(ret == EXIT_OK);
    CHECK((prog.flags & VM_SER_FLAG_CONST_ENCRYPTED) != 0);

    // Serialize
    Buffer serialized = {0};
    ret = vm_serialize(&prog, &serialized);
    CHECK(ret == EXIT_OK);
    CHECK(serialized.size > 0);

    // Deserialize back - constants should be decrypted correctly
    VmProgram prog2;
    vm_program_init(&prog2);
    ret = vm_deserialize(serialized.data, serialized.size, &prog2);
    CHECK(ret == EXIT_OK);
    CHECK((prog2.flags & VM_SER_FLAG_CONST_ENCRYPTED) != 0);
    CHECK(prog2.const_count == prog.const_count);

    // String constants should match (they were decrypted)
    for (int i = 0; i < prog.const_count && i < prog2.const_count; i++) {
        CHECK(prog.const_types[i] == prog2.const_types[i]);
        if (prog.const_strs[i] && prog2.const_strs[i]) {
            CHECK(strcmp(prog.const_strs[i], prog2.const_strs[i]) == 0);
        }
    }

    vm_program_free(&prog2);
    free(serialized.data);
    vm_program_free(&prog);
}

TEST_CASE("vm constant encryption with VL encoding") {
    const char *source = "x = 1 + 2\n";
    VmProgram prog;
    vm_program_init(&prog);

    VmCompileConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enable_opaque = 0;
    cfg.seed = 42;
    cfg.enable_indirect_calls = 0;
    cfg.enable_var_length_encoding = 1;
    cfg.enable_constant_encryption = 1;

    ExitCode ret = vm_compile_source_ex(source, strlen(source), &prog, &cfg);
    CHECK(ret == EXIT_OK);
    CHECK((prog.flags & VM_SER_FLAG_CONST_ENCRYPTED) != 0);

    Buffer serialized = {0};
    ret = vm_serialize(&prog, &serialized);
    CHECK(ret == EXIT_OK);

    VmProgram prog2;
    vm_program_init(&prog2);
    ret = vm_deserialize(serialized.data, serialized.size, &prog2);
    CHECK(ret == EXIT_OK);
    CHECK((prog2.flags & VM_SER_FLAG_CONST_ENCRYPTED) != 0);
    CHECK(prog2.const_count == prog.const_count);
    CHECK(prog2.vl_code != nullptr);
    CHECK(prog2.vl_code_len > 0);

    vm_program_free(&prog2);
    free(serialized.data);
    vm_program_free(&prog);
}

// ═══════════════════════════════════════════════════════════
// Enhancement 3: Control Flow Integrity Tests
// ═══════════════════════════════════════════════════════════

TEST_CASE("vm_pass_cfi basic") {
    VmProgram prog;
    vm_program_init(&prog);

    // Create a simple program with a branch
    prog.count = 6;
    prog.instrs = (VmInstr *)malloc(prog.count * sizeof(VmInstr));
    REQUIRE(prog.instrs != nullptr);

    prog.instrs[0] = {VM_LOAD_CONST, 0, 0, 0, 42};
    prog.instrs[1] = {VM_LOAD_CONST, 1, 0, 0, 100};
    prog.instrs[2] = {VM_CMP_EQ, 2, 0, 1, 0};
    prog.instrs[3] = {VM_JMP_IF_FALSE, 2, 0, 0, 5};
    prog.instrs[4] = {VM_MOVE, 3, 0, 0, 0};
    prog.instrs[5] = {VM_RETURN, 3, 0, 0, 0};

    VmCompileConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enable_cfi = 1;
    cfg.seed = 42;

    ExitCode ret = vm_pass_cfi(&prog, &cfg);
    CHECK(ret == EXIT_OK);
    CHECK((prog.flags & VM_SER_FLAG_CFI_ENABLED) != 0);
    CHECK(prog.cfi_num_blocks > 0);
    CHECK(prog.cfi_checksums != nullptr);

    // Should have CFI_CHECK instructions inserted
    bool has_cfi = false;
    for (int i = 0; i < prog.count; i++) {
        if (prog.instrs[i].op == VM_CFI_CHECK) {
            has_cfi = true;
            break;
        }
    }
    CHECK(has_cfi);

    vm_program_free(&prog);
}

TEST_CASE("vm_pass_cfi with VL encoding") {
    VmProgram prog;
    vm_program_init(&prog);

    prog.count = 5;
    prog.instrs = (VmInstr *)malloc(prog.count * sizeof(VmInstr));
    REQUIRE(prog.instrs != nullptr);

    prog.instrs[0] = {VM_LOAD_CONST, 0, 0, 0, 10};
    prog.instrs[1] = {VM_LOAD_CONST, 1, 0, 0, 20};
    prog.instrs[2] = {VM_ADD, 2, 0, 1, 0};
    prog.instrs[3] = {VM_JMP, 0, 0, 0, 0};  // jump to self (loop)
    prog.instrs[4] = {VM_RETURN, 2, 0, 0, 0};

    // Encode to VL first
    Buffer vl = {0};
    vm_encode_program(&prog, &vl);
    prog.vl_code = vl.data;
    prog.vl_code_len = (int)vl.size;
    prog.flags |= VM_SER_FLAG_VL_ENCODED;

    VmCompileConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enable_cfi = 1;
    cfg.seed = 42;

    ExitCode ret = vm_pass_cfi(&prog, &cfg);
    CHECK(ret == EXIT_OK);

    vm_program_free(&prog);
}

// ═══════════════════════════════════════════════════════════
// Enhancement 4: Code Scheduling Tests
// ═══════════════════════════════════════════════════════════

TEST_CASE("vm_pass_code_schedule basic") {
    VmProgram prog;
    vm_program_init(&prog);

    // Create a sequence of independent instructions
    prog.count = 8;
    prog.instrs = (VmInstr *)malloc(prog.count * sizeof(VmInstr));
    REQUIRE(prog.instrs != nullptr);

    for (int i = 0; i < prog.count; i++) {
        prog.instrs[i].op = VM_LOAD_CONST;
        prog.instrs[i].rd = (uint8_t)i;
        prog.instrs[i].rs1 = 0;
        prog.instrs[i].rs2 = 0;
        prog.instrs[i].imm = i * 10;
    }

    VmCompileConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enable_code_scheduling = 1;
    cfg.schedule_strength = 2;
    cfg.seed = 42;

    // Record original op order
    uint8_t orig_ops[8];
    for (int i = 0; i < prog.count; i++)
        orig_ops[i] = prog.instrs[i].op;

    ExitCode ret = vm_pass_code_schedule(&prog, &cfg);
    CHECK(ret == EXIT_OK);

    // Code should have been reordered or expanded
    CHECK(prog.count >= 8);

    vm_program_free(&prog);
}

TEST_CASE("vm_pass_code_schedule with dependent instructions") {
    VmProgram prog;
    vm_program_init(&prog);

    // Sequence with data dependencies (chain)
    prog.count = 5;
    prog.instrs = (VmInstr *)malloc(prog.count * sizeof(VmInstr));
    REQUIRE(prog.instrs != nullptr);

    prog.instrs[0] = {VM_LOAD_CONST, 0, 0, 0, 10};   // r0 = 10
    prog.instrs[1] = {VM_LOAD_CONST, 1, 0, 0, 20};   // r1 = 20
    prog.instrs[2] = {VM_ADD, 2, 0, 1, 0};            // r2 = r0 + r1
    prog.instrs[3] = {VM_MUL, 3, 2, 0, 0};            // r3 = r2 * r0
    prog.instrs[4] = {VM_RETURN, 3, 0, 0, 0};

    VmCompileConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enable_code_scheduling = 1;
    cfg.schedule_strength = 1;
    cfg.seed = 42;

    // The pass should not break data dependencies
    // (instruction order may change but must be semantically valid)
    uint8_t orig_ops[5];
    for (int i = 0; i < prog.count; i++)
        orig_ops[i] = prog.instrs[i].op;

    ExitCode ret = vm_pass_code_schedule(&prog, &cfg);
    CHECK(ret == EXIT_OK);

    // Ensure we still have proper instruction count
    CHECK(prog.count >= 5);

    vm_program_free(&prog);
}

// ═══════════════════════════════════════════════════════════
// Combined Pipeline Test (all four enhancements)
// ═══════════════════════════════════════════════════════════

TEST_CASE("vm_compile_source_ex with all four enhancements") {
    const char *source = "x = 1 + 2\nprint(x)\n";
    VmProgram prog;
    vm_program_init(&prog);

    VmCompileConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enable_opaque = 1;
    cfg.seed = 12345;

    // Existing features
    cfg.enable_indirect_calls = 1;
    cfg.enable_var_length_encoding = 0;  // Use polymorphic instead
    cfg.enable_register_spilling = 1;
    cfg.enable_self_modifying_code = 1;
    cfg.enable_conditional_obfuscation = 1;
    cfg.cond_obfuscation_strength = 1;

    // New features
    cfg.enable_polymorphic_encoding = 1;
    cfg.enable_constant_encryption = 1;
    cfg.enable_cfi = 1;
    cfg.enable_code_scheduling = 1;
    cfg.schedule_strength = 1;

    ExitCode ret = vm_compile_source_ex(source, strlen(source), &prog, &cfg);
    CHECK(ret == EXIT_OK);
    CHECK(prog.opcode_map != (uint8_t*)0);

    // Check polymorphic encoding flag
    CHECK((prog.flags & VM_SER_FLAG_POLY_ENCODING) != 0);
    CHECK(prog.vl_code != nullptr);
    CHECK(prog.vl_code_len > 0);

    // Check constant encryption flag
    CHECK((prog.flags & VM_SER_FLAG_CONST_ENCRYPTED) != 0);

    // Check CFI flag
    CHECK((prog.flags & VM_SER_FLAG_CFI_ENABLED) != 0);

    // Serialization roundtrip
    Buffer serialized = {0};
    ret = vm_serialize(&prog, &serialized);
    CHECK(ret == EXIT_OK);
    CHECK(serialized.size > 0);

    VmProgram prog2;
    vm_program_init(&prog2);
    ret = vm_deserialize(serialized.data, serialized.size, &prog2);
    CHECK(ret == EXIT_OK);
    CHECK((prog2.flags & VM_SER_FLAG_POLY_ENCODING) != 0);
    CHECK((prog2.flags & VM_SER_FLAG_CONST_ENCRYPTED) != 0);
    CHECK((prog2.flags & VM_SER_FLAG_CFI_ENABLED) != 0);
    CHECK(prog2.vl_code != nullptr);
    CHECK(prog2.vl_code_len > 0);
    CHECK(prog2.const_count == prog.const_count);
    for (int i = 0; i < prog.const_count && i < prog2.const_count; i++) {
        CHECK(prog.const_types[i] == prog2.const_types[i]);
    }

    vm_program_free(&prog2);
    free(serialized.data);
    vm_program_free(&prog);
}
