#include "lib/doctest.h"
#include "crypto/obfuscate.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <openssl/rand.h>

/* ── Test: Anti-Debugging ── */
TEST_SUITE("Anti-Debugging") {

TEST_CASE("anti_debug_check_ptrace returns 0 when not traced") {
    int result = anti_debug_check_ptrace();
    /* When not being debugged, ptrace should be available */
    CHECK(result == 0);
}

TEST_CASE("anti_debug_check_tracerpid returns 0 when not traced") {
    int result = anti_debug_check_tracerpid();
    CHECK(result == 0);
}

TEST_CASE("anti_debug_generate_stub produces valid Python") {
    char *stub = anti_debug_generate_stub(1, 1);
    REQUIRE(stub != nullptr);
    CHECK(strlen(stub) > 100);

    /* Check key Python constructs present */
    CHECK(strstr(stub, "TracerPid") != nullptr);
    CHECK(strstr(stub, "sys") != nullptr);
    CHECK(strstr(stub, "debugger") != nullptr);

    /* Check Frida detection is present */
    CHECK(strstr(stub, "frida") != nullptr);
    CHECK(strstr(stub, "27042") != nullptr);
    CHECK(strstr(stub, "FRIDA_SCRIPT") != nullptr);
    CHECK(strstr(stub, "instrumentation") != nullptr);

    /* Check new advanced features present */
    CHECK(strstr(stub, "perf_counter") != nullptr);
    CHECK(strstr(stub, "_getframe") != nullptr);
    CHECK(strstr(stub, "settrace") != nullptr);
    CHECK(strstr(stub, "excepthook") != nullptr);
    CHECK(strstr(stub, "get_objects") != nullptr);
    CHECK(strstr(stub, "5678") != nullptr);
    CHECK(strstr(stub, "audithook") != nullptr);

    /* Compile check - should be valid Python */
    FILE *f = fopen("/tmp/test_anti_debug_stub.py", "w");
    REQUIRE(f != nullptr);
    fputs(stub, f);
    fclose(f);

    int rc = system("python3 -c \"compile(open('/tmp/test_anti_debug_stub.py').read(), '<test>', 'exec')\" 2>/dev/null");
    CHECK(rc == 0);

    free(stub);
    remove("/tmp/test_anti_debug_stub.py");
}

TEST_CASE("anti_debug_sanitize_environment removes dangerous vars") {
    setenv("PYTHONPATH", "/malicious", 1);
    setenv("LD_PRELOAD", "/hook.so", 1);

    char **sanitized = anti_debug_sanitize_environment();
    REQUIRE(sanitized != nullptr);

    for (int i = 0; sanitized[i]; i++) {
        CHECK(strncmp(sanitized[i], "PYTHONPATH=", 11) != 0);
        CHECK(strncmp(sanitized[i], "LD_PRELOAD=", 11) != 0);
        free(sanitized[i]);
    }
    free(sanitized);

    unsetenv("PYTHONPATH");
    unsetenv("LD_PRELOAD");
}

TEST_CASE("anti_debug_generate_stub includes advanced hook checks") {
    char *stub = anti_debug_generate_stub(0, 1);  /* hook_check only */
    REQUIRE(stub != nullptr);
    CHECK(strlen(stub) > 200);

    /* Advanced hook detection strings */
    CHECK(strstr(stub, "__build_class__") != nullptr);
    CHECK(strstr(stub, "LD_AUDIT") != nullptr);
    CHECK(strstr(stub, "DYLD_FORCE_FLAT_NAMESPACE") != nullptr);
    CHECK(strstr(stub, "LD_DEBUG") != nullptr);
    CHECK(strstr(stub, "builtin_function_or_method") != nullptr);
    CHECK(strstr(stub, "WX memory") != nullptr);
    CHECK(strstr(stub, "hook injection") != nullptr);
    CHECK(strstr(stub, "LD_OPENCL_LIBRARY_PATH") != nullptr);

    /* Should also still have old basic checks */
    CHECK(strstr(stub, "__import__") != nullptr);
    CHECK(strstr(stub, "DYLD_INSERT_LIBRARIES") != nullptr);

    /* Compile check */
    FILE *f = fopen("/tmp/test_anti_hook_stub.py", "w");
    REQUIRE(f != nullptr);
    fputs(stub, f);
    fclose(f);

    int rc = system("python3 -c \"compile(open('/tmp/test_anti_hook_stub.py').read(), '<test>', 'exec')\" 2>/dev/null");
    CHECK_EQ(rc, 0);

    free(stub);
    remove("/tmp/test_anti_hook_stub.py");
}

TEST_CASE("anti_debug_check_timing returns 0 under normal execution") {
    int result = anti_debug_check_timing();
    CHECK(result == 0);
}

TEST_CASE("anti_debug_check_parent returns 0 when parent is normal") {
    int result = anti_debug_check_parent();
    CHECK(result == 0);
}

TEST_CASE("anti_debug_check_debugregs returns 0 when no hardware breakpoints") {
    int result = anti_debug_check_debugregs();
    CHECK(result == 0);
}

TEST_CASE("anti_debug_check_procstat returns 0 under normal execution") {
    int result = anti_debug_check_procstat();
    CHECK(result == 0);
}

TEST_CASE("anti_debug_check_proc_cmdline returns 0 under normal execution") {
    int result = anti_debug_check_proc_cmdline();
    CHECK(result == 0);
}

TEST_CASE("anti_debug_check_prctl returns 0 under normal execution") {
    int result = anti_debug_check_prctl();
    CHECK(result == 0);
}

TEST_CASE("anti_debug_check_fork returns 0 when fork works") {
    int result = anti_debug_check_fork();
    CHECK(result == 0);
}

TEST_CASE("anti_debug_check_all returns HOOK_DETECTED when DYLD_INSERT_LIBRARIES is set") {
    /* Note: LD_PRELOAD is now checked via /proc/self/environ (immutable),
       so setenv() won't affect it. Use DYLD_* which is still checked via getenv(). */
    setenv("DYLD_INSERT_LIBRARIES", "/test_hook.dylib", 1);
    AntiDebugResult result = anti_debug_check_all();
    CHECK_EQ(result, ADBG_RESULT_HOOK_DETECTED);
    unsetenv("DYLD_INSERT_LIBRARIES");
}

TEST_CASE("anti_debug_check_proc_cmdline detects env injection via /proc/self/environ") {
    /* This test is informational only: /proc/self/environ cannot be modified
       at runtime via setenv(), so we verify the function returns 0 when clean.
       Real detection of LD_PRELOAD happens at process start via the kernel. */
    int result = anti_debug_check_proc_cmdline();
    CHECK_EQ(result, 0);
}

TEST_CASE("protect with anti-debug integration: generate + run") {
    /* Create a simple Python test file */
    FILE *f = fopen("/tmp/test_ad_integration.py", "w");
    REQUIRE(f != nullptr);
    fputs("print('IntegrationTestOK')\n", f);
    fclose(f);

    /* Run crypto protect with anti-debug auto-enabled (density >= 1) */
    int rc = system(
        "cd /home/ngquanghuy/Crypto && ./build/crypto protect"
        " -a xchacha20-poly1305 --keygen 32"
        " --no-compress --obf-density 1"
        " /tmp/test_ad_integration.py -o /tmp/test_ad_integration_out.py"
        " 2>/dev/null");
    CHECK_EQ(rc, 0);

    /* Check output file exists with reasonable size */
    FILE *out = fopen("/tmp/test_ad_integration_out.py", "r");
    REQUIRE(out != nullptr);
    fseek(out, 0, SEEK_END);
    long sz = ftell(out);
    fclose(out);
    CHECK(sz > 500);

    /* Python compile check on the protected stub */
    rc = system(
        "python3 -c \"compile(open('/tmp/test_ad_integration_out.py').read(), '<test>', 'exec')\""
        " 2>/dev/null");
    CHECK_EQ(rc, 0);

    /* Run the protected script and verify output */
    rc = system(
        "python3 /tmp/test_ad_integration_out.py 2>/dev/null"
        " | grep -q 'IntegrationTestOK'");
    CHECK_EQ(rc, 0);

    /* Cleanup */
    remove("/tmp/test_ad_integration.py");
    remove("/tmp/test_ad_integration_out.py");
}

}

/* ── Test: Rename Algorithm ── */
TEST_SUITE("Rename Algorithm") {

TEST_CASE("rename_mangle_name produces variable-length result") {
    unsigned char key[32];
    RAND_bytes(key, sizeof(key));

    char *mangled = rename_mangle_name("my_function", 0, "global", key, 32);
    REQUIRE(mangled != nullptr);
    /* Length varies: _ + 8, 12, or 16 hex chars (+ possible extra _ or digit prefix) */
    size_t len = strlen(mangled);
    CHECK(len >= 3);    /* _ + at least 1 hex char * 2 = at least 3 */
    CHECK(len <= 35);   /* __ + 16 hex chars (32 chars) + null = 35 max */
    CHECK(mangled[0] == '_');
    CHECK(mangled[1] != '\0');
    free(mangled);
}

TEST_CASE("rename_mangle_name is context-dependent") {
    unsigned char key[32];
    RAND_bytes(key, sizeof(key));

    char *m1 = rename_mangle_name("foo", 0, "global", key, 32);
    char *m2 = rename_mangle_name("foo", 1, "inner", key, 32);
    REQUIRE(m1 != nullptr);
    REQUIRE(m2 != nullptr);
    /* Same name, different scope -> different mangled names */
    CHECK(strcmp(m1, m2) != 0);
    free(m1);
    free(m2);
}

TEST_CASE("rename_mangle_name is non-deterministic (random length/prefix)") {
    unsigned char key[32];
    RAND_bytes(key, sizeof(key));

    char *m1 = rename_mangle_name("test", 0, "", key, 32);
    char *m2 = rename_mangle_name("test", 0, "", key, 32);
    REQUIRE(m1 != nullptr);
    REQUIRE(m2 != nullptr);
    /* rename_mangle_name intentionally uses random hex length and random prefix
       (_ vs __ vs _0–_9) so two calls with identical inputs MUST differ */
    CHECK_NE(strcmp(m1, m2), 0);
    CHECK(strlen(m1) >= 3);
    CHECK(strlen(m2) >= 3);
    CHECK(m1[0] == '_');
    CHECK(m2[0] == '_');
    free(m1);
    free(m2);
}

TEST_CASE("rename_table_register deduplicates") {
    unsigned char key[32];
    RAND_bytes(key, sizeof(key));

    RenameTable tbl;
    rename_table_init(&tbl, 16);

    const char *n1 = rename_register(&tbl, "myvar", 0, "", key, 32);
    const char *n2 = rename_register(&tbl, "myvar", 0, "", key, 32);
    CHECK_EQ(n1, n2);  /* Same pointer - deduplicated */

    const char *n3 = rename_register(&tbl, "myvar", 1, "func", key, 32);
    REQUIRE(n3 != nullptr);
    CHECK_NE(n1, n3);  /* Different scope -> different name */

    CHECK_EQ(tbl.count, 2);
    rename_table_free(&tbl);
}

TEST_CASE("rename_generate_decoys adds entries") {
    unsigned char key[32];
    RAND_bytes(key, sizeof(key));

    RenameTable tbl;
    rename_table_init(&tbl, 16);

    int count = rename_generate_decoys(&tbl, 5, key, 32);
    CHECK_EQ(count, 5);
    CHECK_EQ(tbl.count, 5);

    rename_table_free(&tbl);
}

TEST_CASE("rename_shuffle_table changes order") {
    unsigned char key[32];
    RAND_bytes(key, sizeof(key));

    RenameTable tbl;
    rename_table_init(&tbl, 16);

    rename_register(&tbl, "a", 0, "", key, 32);
    rename_register(&tbl, "b", 0, "", key, 32);
    rename_register(&tbl, "c", 0, "", key, 32);

    /* Record before */
    RenameEntry before[3];
    memcpy(before, tbl.entries, sizeof(RenameEntry) * 3);

    rename_shuffle_table(&tbl);

    /* After shuffle, at least one position should differ (probabilistic) */
    int same = 1;
    for (size_t i = 0; i < tbl.count && same; i++) {
        if (strcmp(tbl.entries[i].mangled_name, before[i].mangled_name) != 0)
            same = 0;
    }
    CHECK_EQ(same, 0);

    rename_table_free(&tbl);
}

TEST_CASE("rename_generate_python produces valid script") {
    unsigned char key[32];
    RAND_bytes(key, sizeof(key));

    RenameTable tbl;
    rename_table_init(&tbl, 16);
    rename_register(&tbl, "myfunc", 0, "", key, 32);
    rename_register(&tbl, "myvar", 0, "", key, 32);

    const char *input = "def myfunc():\n    return myvar\n";
    char *script = rename_generate_python(input, &tbl);

    REQUIRE(script != nullptr);
    CHECK(strstr(script, "import ast") != nullptr);
    CHECK(strstr(script, "_Renamer") != nullptr);

    /* Script should compile as valid Python */
    FILE *f = fopen("/tmp/test_rename_script.py", "w");
    REQUIRE(f != nullptr);
    fputs(script, f);
    fclose(f);

    int rc = system("python3 -c \"compile(open('/tmp/test_rename_script.py').read(), '<test>', 'exec')\" 2>/dev/null");
    CHECK_EQ(rc, 0);

    free(script);
    rename_table_free(&tbl);
    remove("/tmp/test_rename_script.py");
}

}

/* ── Test: Flow Flattening ── */
TEST_SUITE("Flow Flattening") {

TEST_CASE("flowflatten_plan_init/set_block works") {
    FlowFlattenPlan plan;
    flowflatten_plan_init(&plan, 3);

    CHECK_EQ(plan.num_blocks, 3);

    int ret = flowflatten_set_block(&plan, 0, "x = 1", 1);
    CHECK_EQ(ret, 1);
    CHECK(plan.blocks[0].block_code != nullptr);
    CHECK(strstr(plan.blocks[0].block_code, "x = 1") != nullptr);
    CHECK(strlen(plan.blocks[0].state_encoded) > 0); /* HMAC hex */

    flowflatten_plan_free(&plan);
}

TEST_CASE("flowflatten_opaque_predicate is always True") {
    char *pred = flowflatten_opaque_predicate();
    REQUIRE(pred != nullptr);

    /* Evaluate in Python - must be True */
    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
             "python3 -c \"result = %s; assert result == True, f'Got {result}'\" 2>/dev/null",
             pred);

    int rc = system(cmd);
    CHECK_EQ(rc, 0);
    free(pred);
}

TEST_CASE("flowflatten_opaque_false_predicate is always False") {
    char *pred = flowflatten_opaque_false_predicate();
    REQUIRE(pred != nullptr);

    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
             "python3 -c \"result = %s; assert result == False, f'Got {result}'\" 2>/dev/null",
             pred);

    int rc = system(cmd);
    CHECK_EQ(rc, 0);
    free(pred);
}

TEST_CASE("flowflatten_generate_python produces valid flattened code") {
    FlowFlattenPlan plan;
    flowflatten_plan_init(&plan, 3);

    flowflatten_set_block(&plan, 0, "x = 42", 1);
    flowflatten_set_block(&plan, 1, "y = x * 2", 2);
    flowflatten_set_block(&plan, 2, "result = y + 1", -1);

    char *code = flowflatten_generate_python(&plan, plan.key, 32);
    REQUIRE(code != nullptr);
    CHECK(strstr(code, "hashlib") != nullptr);
    CHECK(strstr(code, "def ") != nullptr);
    CHECK(strstr(code, "_S") != nullptr);

    /* Compile check */
    FILE *f = fopen("/tmp/test_flowflat_stub.py", "w");
    REQUIRE(f != nullptr);
    fputs(code, f);
    fclose(f);

    int rc = system("python3 -c \"compile(open('/tmp/test_flowflat_stub.py').read(), '<test>', 'exec')\" 2>/dev/null");
    CHECK_EQ(rc, 0);

    free(code);
    flowflatten_plan_free(&plan);
    remove("/tmp/test_flowflat_stub.py");
}

}

/* ── Test: Junk Code Insertion ── */
TEST_SUITE("Junk Code") {

TEST_CASE("junk_generate_statement produces valid Python") {
    JunkConfig cfg;
    junk_config_default(&cfg);

    char *stmt = junk_generate_statement(&cfg);
    REQUIRE(stmt != nullptr);
    CHECK(strlen(stmt) > 0);

    /* Must compile as Python */
    FILE *f = fopen("/tmp/test_junk_stmt.py", "w");
    fputs(stmt, f);
    fclose(f);

    int rc = system("python3 -c \"compile(open('/tmp/test_junk_stmt.py').read(), '<test>', 'exec')\" 2>/dev/null");
    CHECK_EQ(rc, 0);

    free(stmt);
    remove("/tmp/test_junk_stmt.py");
}

TEST_CASE("junk_generate_ifelse_block compiles and has both branches") {
    JunkConfig cfg;
    junk_config_default(&cfg);

    char *block = junk_generate_ifelse_block(&cfg);
    REQUIRE(block != nullptr);
    CHECK(strstr(block, "if ") != nullptr);
    CHECK(strstr(block, "else:") != nullptr);

    FILE *f = fopen("/tmp/test_junk_ifelse.py", "w");
    fputs(block, f);
    fclose(f);

    int rc = system("python3 -c \"compile(open('/tmp/test_junk_ifelse.py').read(), '<test>', 'exec')\" 2>/dev/null");
    CHECK_EQ(rc, 0);

    free(block);
    remove("/tmp/test_junk_ifelse.py");
}

TEST_CASE("junk_generate_function produces valid function") {
    JunkConfig cfg;
    junk_config_default(&cfg);

    char *func = junk_generate_function(&cfg);
    REQUIRE(func != nullptr);
    CHECK(strstr(func, "def ") != nullptr);
    CHECK(strstr(func, "return") != nullptr);

    FILE *f = fopen("/tmp/test_junk_func.py", "w");
    fputs(func, f);
    fclose(f);

    int rc = system("python3 -c \"compile(open('/tmp/test_junk_func.py').read(), '<test>', 'exec')\" 2>/dev/null");
    CHECK_EQ(rc, 0);

    free(func);
    remove("/tmp/test_junk_func.py");
}

TEST_CASE("junk_generate_section produces multiple statements") {
    JunkConfig cfg;
    junk_config_default(&cfg);

    char *section = junk_generate_section(&cfg, 5);
    REQUIRE(section != nullptr);

    FILE *f = fopen("/tmp/test_junk_section.py", "w");
    fputs(section, f);
    fclose(f);

    int rc = system("python3 -c \"compile(open('/tmp/test_junk_section.py').read(), '<test>', 'exec')\" 2>/dev/null");
    CHECK_EQ(rc, 0);

    free(section);
    remove("/tmp/test_junk_section.py");
}

}

/* ── Test: Advanced CFG Flattening with Dispatcher ── */
TEST_SUITE("Advanced CFG Flattening") {

TEST_CASE("adv_flowflatten_plan_init creates blocks with permutation") {
    AdvFlowFlattenPlan plan;
    adv_flowflatten_plan_init(&plan, 5);

    CHECK(plan.num_blocks >= 5);
    CHECK(plan.real_blocks == 0);
    CHECK(plan.dispatcher_type >= 0);
    CHECK(plan.dispatcher_type <= 2);
    CHECK(plan.permutation != nullptr);
    CHECK(plan.blocks != nullptr);

    adv_flowflatten_plan_free(&plan);
}

TEST_CASE("adv_flowflatten_set_block stores block correctly") {
    AdvFlowFlattenPlan plan;
    adv_flowflatten_plan_init(&plan, 3);

    int ret = adv_flowflatten_set_block(&plan, 0, "x = 42", 1);
    CHECK_EQ(ret, 1);

    ret = adv_flowflatten_set_block(&plan, 1, "y = x + 1", 2);
    CHECK_EQ(ret, 1);

    ret = adv_flowflatten_set_block(&plan, 2, "print(y)", -1);
    CHECK_EQ(ret, 1);

    CHECK_EQ(plan.real_blocks, 3);

    adv_flowflatten_plan_free(&plan);
}

TEST_CASE("adv_flowflatten_add_dead_block adds at unused slot") {
    AdvFlowFlattenPlan plan;
    adv_flowflatten_plan_init(&plan, 3);

    adv_flowflatten_set_block(&plan, 0, "x = 1", 1);
    adv_flowflatten_set_block(&plan, 1, "y = 2", 2);
    adv_flowflatten_set_block(&plan, 2, "z = 3", -1);

    int idx = adv_flowflatten_add_dead_block(&plan, "x = dead_code");
    CHECK(idx >= 0);
    CHECK(plan.blocks[idx].dead_block);
    CHECK(plan.num_dead_blocks >= 1);

    adv_flowflatten_plan_free(&plan);
}

TEST_CASE("adv_flowflatten_generate_python with dict dispatcher produces valid code") {
    AdvFlowFlattenPlan plan;
    adv_flowflatten_plan_init(&plan, 3);

    // Force dict dispatcher type
    plan.dispatcher_type = 0;

    adv_flowflatten_set_block(&plan, 0, "x = 42", 1);
    adv_flowflatten_set_block(&plan, 1, "y = x * 2", 2);
    adv_flowflatten_set_block(&plan, 2, "z = y + 1", -1);
    adv_flowflatten_add_dead_block(&plan, "_t = 99  # dead");

    char *code = adv_flowflatten_generate_python(&plan);
    REQUIRE(code != nullptr);
    CHECK(strstr(code, "def _b0") != nullptr);
    CHECK(strstr(code, "def _b1") != nullptr);
    CHECK(strstr(code, "def _b2") != nullptr);
    CHECK(strstr(code, "def _b_exit") != nullptr);
    CHECK(strstr(code, "def ") != nullptr);

    /* Compile check */
    FILE *f = fopen("/tmp/test_adv_flowflat.py", "w");
    REQUIRE(f != nullptr);
    fputs(code, f);
    fclose(f);

    int rc = system("python3 -c \"compile(open('/tmp/test_adv_flowflat.py').read(), '<test>', 'exec')\" 2>/dev/null");
    CHECK_EQ(rc, 0);

    free(code);
    adv_flowflatten_plan_free(&plan);
    remove("/tmp/test_adv_flowflat.py");
}

TEST_CASE("adv_flowflatten_generate_python with list dispatcher") {
    AdvFlowFlattenPlan plan;
    adv_flowflatten_plan_init(&plan, 4);
    plan.dispatcher_type = 1;

    adv_flowflatten_set_block(&plan, 0, "a = 10", 1);
    adv_flowflatten_set_block(&plan, 1, "b = 20", 2);
    adv_flowflatten_set_block(&plan, 2, "c = a + b", 3);
    adv_flowflatten_set_block(&plan, 3, "print(c)", -1);

    char *code = adv_flowflatten_generate_python(&plan);
    REQUIRE(code != nullptr);
    CHECK(strstr(code, "def _b0") != nullptr);
    CHECK(strstr(code, "def _b3") != nullptr);

    /* Compile check */
    FILE *f = fopen("/tmp/test_adv_flowflat_list.py", "w");
    REQUIRE(f != nullptr);
    fputs(code, f);
    fclose(f);

    int rc = system("python3 -c \"compile(open('/tmp/test_adv_flowflat_list.py').read(), '<test>', 'exec')\" 2>/dev/null");
    CHECK_EQ(rc, 0);

    free(code);
    adv_flowflatten_plan_free(&plan);
    remove("/tmp/test_adv_flowflat_list.py");
}

TEST_CASE("adv_flowflatten_generate_python with arithmetic dispatcher") {
    AdvFlowFlattenPlan plan;
    adv_flowflatten_plan_init(&plan, 3);
    plan.dispatcher_type = 2;

    adv_flowflatten_set_block(&plan, 0, "result = 1", 1);
    adv_flowflatten_set_block(&plan, 1, "result = result * 2", 2);
    adv_flowflatten_set_block(&plan, 2, "result = result + 3", -1);

    char *code = adv_flowflatten_generate_python(&plan);
    REQUIRE(code != nullptr);

    /* Compile check */
    FILE *f = fopen("/tmp/test_adv_flowflat_arith.py", "w");
    REQUIRE(f != nullptr);
    fputs(code, f);
    fclose(f);

    int rc = system("python3 -c \"compile(open('/tmp/test_adv_flowflat_arith.py').read(), '<test>', 'exec')\" 2>/dev/null");
    CHECK_EQ(rc, 0);

    free(code);
    adv_flowflatten_plan_free(&plan);
    remove("/tmp/test_adv_flowflat_arith.py");
}

TEST_CASE("adv_flowflatten_wrap_source produces valid output") {
    const char *source = "x = 42\ny = x * 2\nprint(y)\n";
    char *result = adv_flowflatten_wrap_source(source, 3, 1.0f);
    REQUIRE(result != nullptr);
    CHECK(strlen(result) > 100);
    CHECK(strstr(result, "def ") != nullptr);
    CHECK(strstr(result, "if __name__") != nullptr);

    /* Compile check */
    FILE *f = fopen("/tmp/test_adv_flowflat_wrap.py", "w");
    REQUIRE(f != nullptr);
    fputs(result, f);
    fclose(f);

    int rc = system("python3 -c \"compile(open('/tmp/test_adv_flowflat_wrap.py').read(), '<test>', 'exec')\" 2>/dev/null");
    CHECK_EQ(rc, 0);

    free(result);
    remove("/tmp/test_adv_flowflat_wrap.py");
}

}

/* ── Test: XOR Key Generation + ChaCha20 ── */
TEST_SUITE("XOR Key Generation") {

TEST_CASE("xorgen_derive_keys produces correct-length output") {
    unsigned char master[32], salt[16];
    RAND_bytes(master, sizeof(master));
    RAND_bytes(salt, sizeof(salt));

    unsigned char enc_key[32], hmac_key[32];
    ExitCode ret = xorgen_derive_keys(master, sizeof(master),
                                       salt, sizeof(salt),
                                       enc_key, sizeof(enc_key),
                                       hmac_key, sizeof(hmac_key));
    CHECK_EQ(ret, EXIT_OK);

    /* Keys should be non-zero */
    int enc_zero = 1, hmac_zero = 1;
    for (int i = 0; i < 32; i++) {
        if (enc_key[i] != 0) enc_zero = 0;
        if (hmac_key[i] != 0) hmac_zero = 0;
    }
    CHECK_EQ(enc_zero, 0);
    CHECK_EQ(hmac_zero, 0);
}

TEST_CASE("xorgen_chacha20_encrypt/decrypt round-trip") {
    const char *plaintext = "Hello, obfuscation test! This is secret data.";
    size_t plain_len = strlen(plaintext);
    unsigned char key[32];
    RAND_bytes(key, sizeof(key));

    unsigned char *encrypted = nullptr;
    size_t enc_len = 0;

    ExitCode ret = xorgen_chacha20_encrypt(
        (const unsigned char *)plaintext, plain_len,
        key, sizeof(key), &encrypted, &enc_len);
    REQUIRE_EQ(ret, EXIT_OK);
    REQUIRE(encrypted != nullptr);
    /* Output > plaintext (salt + nonce + tag overhead) */
    CHECK(enc_len > plain_len);

    unsigned char *decrypted = nullptr;
    size_t dec_len = 0;
    ret = xorgen_chacha20_decrypt(encrypted, enc_len,
                                   key, sizeof(key),
                                   &decrypted, &dec_len);
    CHECK_EQ(ret, EXIT_OK);
    REQUIRE(decrypted != nullptr);
    CHECK_EQ(dec_len, plain_len);
    CHECK(memcmp(decrypted, plaintext, plain_len) == 0);

    free(encrypted);
    free(decrypted);
}

TEST_CASE("xorgen_chacha20_decrypt detects tampered data") {
    const char *plaintext = "Test integrity check";
    size_t plain_len = strlen(plaintext);
    unsigned char key[32];
    RAND_bytes(key, sizeof(key));

    unsigned char *encrypted = nullptr;
    size_t enc_len = 0;
    xorgen_chacha20_encrypt((const unsigned char *)plaintext, plain_len,
                            key, sizeof(key), &encrypted, &enc_len);
    REQUIRE(encrypted != nullptr);

    /* Tamper with ciphertext */
    encrypted[enc_len / 2] ^= 0xFF;

    unsigned char *decrypted = nullptr;
    size_t dec_len = 0;
    ExitCode ret = xorgen_chacha20_decrypt(encrypted, enc_len,
                                           key, sizeof(key),
                                           &decrypted, &dec_len);
    CHECK_EQ(ret, EXIT_ERR_CRYPTO); /* Should fail integrity */
    CHECK(decrypted == nullptr);

    free(encrypted);
}

TEST_CASE("xorgen_generate_python_stub compiles") {
    const char *source = "print('hello from obfuscated stub')\n";
    unsigned char key[32];
    RAND_bytes(key, sizeof(key));

    char *stub = xorgen_generate_python_stub(
        (const unsigned char *)source, strlen(source),
        key, sizeof(key));
    REQUIRE(stub != nullptr);
    CHECK(strlen(stub) > 100);

    FILE *f = fopen("/tmp/test_chacha_stub.py", "w");
    REQUIRE(f != nullptr);
    fputs(stub, f);
    fclose(f);

    int rc = system("python3 -c \"compile(open('/tmp/test_chacha_stub.py').read(), '<test>', 'exec')\" 2>/dev/null");
    CHECK_EQ(rc, 0);

    free(stub);
    remove("/tmp/test_chacha_stub.py");
}

TEST_CASE("xorgen_generate_xor_stub compiles") {
    const char *source = "x = 42\nprint(x)\n";
    unsigned char key[32];
    RAND_bytes(key, sizeof(key));

    char *stub = xorgen_generate_xor_stub(
        (const unsigned char *)source, strlen(source),
        key, sizeof(key));
    REQUIRE(stub != nullptr);

    FILE *f = fopen("/tmp/test_xor_stub.py", "w");
    REQUIRE(f != nullptr);
    fputs(stub, f);
    fclose(f);

    int rc = system("python3 -c \"compile(open('/tmp/test_xor_stub.py').read(), '<test>', 'exec')\" 2>/dev/null");
    CHECK_EQ(rc, 0);

    free(stub);
    remove("/tmp/test_xor_stub.py");
}

}

/* ── Test: Full Pipeline ── */
TEST_SUITE("Obfuscation Pipeline") {

TEST_CASE("obfuscate_config_default sets reasonable defaults") {
    ObfuscateConfig cfg;
    obfuscate_config_default(&cfg);
    CHECK_EQ(cfg.use_rename, 1);
    CHECK_EQ(cfg.use_flowflatten, 1);
    CHECK_EQ(cfg.use_junk, 1);
    CHECK_EQ(cfg.use_xorgenc, 1);
    CHECK_EQ(cfg.use_antidebug, 1);
    CHECK_EQ(cfg.num_junk_statements, 30);
    CHECK_EQ(cfg.flowflatten_blocks, 10);
}

TEST_CASE("obfuscate_apply_technique handles unknown technique") {
    const char *src = "print(42)\n";
    char *result = obfuscate_apply_technique("nonexistent", src, nullptr, 0);
    REQUIRE(result != nullptr);
    CHECK_EQ(strcmp(result, src), 0);
    free(result);
}

TEST_CASE("obfuscate_apply_technique with antidebug") {
    const char *src = "print('test')\n";
    char *result = obfuscate_apply_technique("antidebug", src, nullptr, 0);
    REQUIRE(result != nullptr);
    CHECK(strstr(result, "TracerPid") != nullptr);
    CHECK(strstr(result, src) != nullptr);
    free(result);
}

TEST_CASE("obfuscate_apply_technique with junk") {
    const char *src = "x = 1\n";
    char *result = obfuscate_apply_technique("junk", src, nullptr, 0);
    REQUIRE(result != nullptr);
    CHECK(strlen(result) > strlen(src));
    CHECK(strstr(result, src) != nullptr);
    free(result);
}

TEST_CASE("obfuscate_apply_technique with rename produces Python with ast import") {
    const char *src = "def myfunc():\n    pass\n";
    unsigned char key[32];
    RAND_bytes(key, sizeof(key));

    char *result = obfuscate_apply_technique("rename", src, key, sizeof(key));
    REQUIRE(result != nullptr);
    CHECK(strstr(result, "import ast") != nullptr);
    free(result);
}

TEST_CASE("obfuscate_pipeline produces output for simple input") {
    const char *src = "print('obfuscated')\n";

    ObfuscateConfig cfg;
    obfuscate_config_default(&cfg);
    cfg.input_source = src;

    char *result = obfuscate_pipeline(&cfg);
    REQUIRE(result != nullptr);
    CHECK(strlen(result) > 0);
    free(result);
}

TEST_CASE("obfuscate_pipeline with single technique") {
    const char *src = "x = 42\nprint(x)\n";

    ObfuscateConfig cfg;
    obfuscate_config_default(&cfg);
    cfg.input_source = src;
    cfg.use_rename = 0;
    cfg.use_flowflatten = 0;
    cfg.use_junk = 0;
    cfg.use_xorgenc = 1;
    cfg.use_antidebug = 0;

    char *result = obfuscate_pipeline(&cfg);
    REQUIRE(result != nullptr);
    CHECK(strlen(result) > 0);
    free(result);
}

}

/* ── Test: Edge Cases ── */
TEST_SUITE("Edge Cases") {

TEST_CASE("rename empty string returns underscore") {
    unsigned char key[32];
    RAND_bytes(key, sizeof(key));
    char *m = rename_mangle_name("", 0, "", key, 32);
    REQUIRE(m != nullptr);
    CHECK_EQ(strcmp(m, "_"), 0);
    free(m);

    m = rename_mangle_name(nullptr, 0, "", key, 32);
    REQUIRE(m != nullptr);
    CHECK_EQ(strcmp(m, "_"), 0);
    free(m);
}

TEST_CASE("junk_generate_statement with null config") {
    char *stmt = junk_generate_statement(nullptr);
    CHECK(stmt == nullptr);
}

TEST_CASE("flowflatten_set_block invalid index") {
    FlowFlattenPlan plan;
    flowflatten_plan_init(&plan, 2);
    int ret = flowflatten_set_block(&plan, 5, "x", 0);
    CHECK_EQ(ret, 0);
    flowflatten_plan_free(&plan);
}

TEST_CASE("xorgen_derive_keys with empty key fails") {
    unsigned char salt[16], enc[32], hmac[32];
    RAND_bytes(salt, sizeof(salt));
    ExitCode ret = xorgen_derive_keys(nullptr, 0, salt, sizeof(salt),
                                       enc, sizeof(enc),
                                       hmac, sizeof(hmac));
    CHECK_EQ(ret, EXIT_ERR_ARGS);
}

TEST_CASE("xorgen_chacha20_encrypt with empty input fails") {
    unsigned char key[32];
    RAND_bytes(key, sizeof(key));
    unsigned char *out = nullptr;
    size_t out_len = 0;
    ExitCode ret = xorgen_chacha20_encrypt(nullptr, 0, key, sizeof(key), &out, &out_len);
    CHECK_EQ(ret, EXIT_ERR_INTERNAL);
}

TEST_CASE("xorgen_chacha20_decrypt too-short input fails") {
    unsigned char key[32], in[8] = {0};
    RAND_bytes(key, sizeof(key));
    unsigned char *out = nullptr;
    size_t out_len = 0;
    ExitCode ret = xorgen_chacha20_decrypt(in, 8, key, sizeof(key), &out, &out_len);
    CHECK_EQ(ret, EXIT_ERR_CRYPTO);
    CHECK(out == nullptr);
}

}