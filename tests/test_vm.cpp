#include "lib/doctest.h"
#include "vm/vm.h"
#include "crypto/common.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

TEST_CASE("vm compile simple expression") {
    const char *source = "x = 1 + 2\n";
    VmProgram prog;
    vm_program_init(&prog);

    ExitCode ret = vm_compile_source(source, strlen(source), &prog, 0);
    CHECK(ret == EXIT_OK);
    CHECK(prog.hot_src != (char*)0);
    CHECK(prog.count > 0);
    CHECK(prog.const_count > 0);
    CHECK(prog.name_count > 0);

    // Check hot source contains the reconstructed code
    if (prog.hot_src) {
        printf("hot src: %s\n", prog.hot_src);
        CHECK(strstr(prog.hot_src, "x") != (char*)0);
    }

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
    CHECK(prog.hot_src != (char*)0);
    CHECK(prog.count > 0);

    if (prog.hot_src) {
        printf("hot src: %s\n", prog.hot_src);
        CHECK(strstr(prog.hot_src, "print") != (char*)0);
    }

    vm_program_free(&prog);
}

TEST_CASE("vm compile arithmetic") {
    const char *source = "a = 10\nb = 20\nc = a + b * 3\nprint(c)\n";
    VmProgram prog;
    vm_program_init(&prog);

    ExitCode ret = vm_compile_source(source, strlen(source), &prog, 0);
    CHECK(ret == EXIT_OK);

    if (prog.hot_src) {
        printf("hot src: %s\n", prog.hot_src);
        CHECK(strstr(prog.hot_src, "print") != (char*)0);
    }

    vm_program_free(&prog);
}

TEST_CASE("vm compile comparison") {
    const char *source = "if 1 < 2:\n    print('ok')\n";
    VmProgram prog;
    vm_program_init(&prog);

    ExitCode ret = vm_compile_source(source, strlen(source), &prog, 0);
    CHECK(ret == EXIT_OK);

    if (prog.hot_src) {
        printf("hot src: %s\n", prog.hot_src);
    }

    vm_program_free(&prog);
}


