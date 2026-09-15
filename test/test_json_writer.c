#include "test_runner.h"
#include "engine.h"
#include <stdio.h>
#include <string.h>

/* --- engine_report_to_json writer tests (pure I/O, no process needed) --- */

static void read_file(const char* path, char* buf, size_t cap)
{
    FILE* f = fopen(path, "rb");
    ASSERT_TRUE(f != NULL);
    if (!f) { buf[0] = '\0'; return; }
    size_t n = fread(buf, 1, cap - 1, f);
    fclose(f);
    buf[n] = '\0';
}

static hook_report_t make_report(void)
{
    hook_report_t r;
    memset(&r, 0, sizeof(r));
    r.pid = 4242;
    snprintf(r.process_name, sizeof(r.process_name), "test.exe");
    r.modules_scanned = 7;
    r.scan_time_ms = 123;
    return r;
}

static void test_json_schema_version(void)
{
    hook_report_t r = make_report();
    const char* path = "test_json_out.tmp";
    ASSERT_EQ(engine_report_to_json(&r, path), 0);
    char buf[4096];
    read_file(path, buf, sizeof(buf));
    ASSERT_TRUE(strstr(buf, "\"schema_version\": 1") != NULL);
    remove(path);
}

static void test_json_escapes_quotes_and_backslashes(void)
{
    /* function name with characters that MUST be escaped in JSON */
    hook_report_t r = make_report();
    hook_entry_t h;
    memset(&h, 0, sizeof(h));
    snprintf(h.function_name, sizeof(h.function_name), "quo\"te\\back\nline\ttab");
    snprintf(h.module_name, sizeof(h.module_name), "mod.dll");
    h.type = HOOK_INLINE;
    r.hooks = &h;
    r.hook_count = 1;
    const char* path = "test_json_esc.tmp";
    ASSERT_EQ(engine_report_to_json(&r, path), 0);
    char buf[4096];
    read_file(path, buf, sizeof(buf));
    ASSERT_TRUE(strstr(buf, "quo\\\"te\\\\back\\nline\\ttab") != NULL);
    remove(path);
}

static void test_json_utf8_passthrough(void)
{
    /* UTF-8 bytes (Chinese) must pass through unescaped and untouched,
     * so the output stays valid UTF-8 JSON on any locale */
    hook_report_t r = make_report();
    snprintf(r.process_name, sizeof(r.process_name),
             "\xE6\xB5\x8B\xE8\xAF\x95.exe"); /* "测试.exe" */
    const char* path = "test_json_utf8.tmp";
    ASSERT_EQ(engine_report_to_json(&r, path), 0);
    char buf[4096];
    read_file(path, buf, sizeof(buf));
    ASSERT_TRUE(strstr(buf, "\xE6\xB5\x8B\xE8\xAF\x95.exe") != NULL);
    remove(path);
}

static void test_json_error_fields(void)
{
    hook_report_t r = make_report();
    r.error_code = ENGINE_ACCESS_DENIED;
    snprintf(r.error_msg, sizeof(r.error_msg), "OpenProcess failed");
    const char* path = "test_json_err.tmp";
    ASSERT_EQ(engine_report_to_json(&r, path), 0);
    char buf[4096];
    read_file(path, buf, sizeof(buf));
    ASSERT_TRUE(strstr(buf, "\"error_code\": -1") != NULL);
    ASSERT_TRUE(strstr(buf, "OpenProcess failed") != NULL);
    remove(path);
}

static void test_json_truncated_flag(void)
{
    hook_report_t r = make_report();
    r.truncated = true;
    const char* path = "test_json_trunc.tmp";
    ASSERT_EQ(engine_report_to_json(&r, path), 0);
    char buf[4096];
    read_file(path, buf, sizeof(buf));
    ASSERT_TRUE(strstr(buf, "\"truncated\": true") != NULL);
    remove(path);
}

static void test_json_null_and_bad_path(void)
{
    hook_report_t r = make_report();
    ASSERT_EQ(engine_report_to_json(NULL, "x.tmp"), -1);
    ASSERT_EQ(engine_report_to_json(&r, NULL), -1);
    /* directory as target path → write must fail, not report success */
    ASSERT_EQ(engine_report_to_json(&r, "."), -1);
}

static void test_json_reports_array(void)
{
    hook_report_t a = make_report();
    hook_report_t b = make_report();
    b.pid = 7;
    const hook_report_t* arr[2] = { &a, &b };
    const char* path = "test_json_arr.tmp";
    ASSERT_EQ(engine_reports_to_json(arr, 2, path), 0);
    char buf[4096];
    read_file(path, buf, sizeof(buf));
    ASSERT_TRUE(strstr(buf, "\"process_count\": 2") != NULL);
    ASSERT_TRUE(strstr(buf, "\"pid\": 4242") != NULL);
    ASSERT_TRUE(strstr(buf, "\"pid\": 7") != NULL);
    remove(path);
}

/* --- CSV / SARIF writers --- */

static void test_csv_basic(void)
{
    hook_report_t r = make_report();
    hook_entry_t h;
    memset(&h, 0, sizeof(h));
    snprintf(h.function_name, sizeof(h.function_name), "Contains,comma\"and\"quote");
    snprintf(h.module_name, sizeof(h.module_name), "mod.dll");
    h.type = HOOK_EAT;
    h.current_addr = 0x1234;
    h.original_addr = 0x5678;
    h.restorable = true;
    h.chain_depth = 2;
    r.hooks = &h;
    r.hook_count = 1;

    const char* path = "test_csv_basic.tmp";
    ASSERT_EQ(engine_report_to_csv(&r, path), 0);
    char buf[4096];
    read_file(path, buf, sizeof(buf));
    ASSERT_TRUE(strstr(buf, "pid,process_name,module,function,type,original_addr,current_addr,restorable,chain_depth") != NULL);
    /* commas and quotes in fields must be escaped via doubled quotes */
    ASSERT_TRUE(strstr(buf, "\"Contains,comma\"\"and\"\"quote\"") != NULL);
    ASSERT_TRUE(strstr(buf, "0x0000000000001234") != NULL);
    ASSERT_TRUE(strstr(buf, ",true,2") != NULL);
    /* data rows must carry the pid column as the first field */
    ASSERT_TRUE(strstr(buf, "\n4242,\"test.exe\"") != NULL);
    remove(path);
}

static void test_csv_field_count_matches_header(void)
{
    /* regression: data rows once lacked the pid column (8 fields vs 9) */
    hook_report_t r = make_report();
    hook_entry_t h;
    memset(&h, 0, sizeof(h));
    snprintf(h.function_name, sizeof(h.function_name), "plain");   /* no commas */
    snprintf(h.module_name, sizeof(h.module_name), "mod.dll");
    h.type = HOOK_EAT;
    r.hooks = &h;
    r.hook_count = 1;

    const char* path = "test_csv_cols.tmp";
    ASSERT_EQ(engine_report_to_csv(&r, path), 0);
    char buf[2048];
    read_file(path, buf, sizeof(buf));

    int header_fields = 1, row_fields = 1;
    const char* p;
    const char* line = strstr(buf, "\n") + 1;
    for (p = buf; *p && *p != '\n'; p++)
        if (*p == ',') header_fields++;
    for (p = line; *p && *p != '\n'; p++)
        if (*p == ',') row_fields++;
    ASSERT_EQ(header_fields, 9);
    ASSERT_EQ(row_fields, header_fields);
    ASSERT_TRUE(strncmp(line, "4242,", 5) == 0);
    remove(path);
}

static void test_csv_no_hooks(void)
{
    hook_report_t r = make_report();
    const char* path = "test_csv_empty.tmp";
    ASSERT_EQ(engine_report_to_csv(&r, path), 0);
    char buf[1024];
    read_file(path, buf, sizeof(buf));
    /* header only, exactly one line */
    ASSERT_TRUE(strstr(buf, "pid,process_name") != NULL);
    ASSERT_TRUE(strchr(buf, '\n') == strrchr(buf, '\n'));
    remove(path);
}

static void test_sarif_structure(void)
{
    hook_report_t r = make_report();
    hook_entry_t h;
    memset(&h, 0, sizeof(h));
    snprintf(h.function_name, sizeof(h.function_name), "quo\"te");
    snprintf(h.module_name, sizeof(h.module_name), "mod.dll");
    h.type = HOOK_IAT;
    h.current_addr = 0x99887766;
    r.hooks = &h;
    r.hook_count = 1;

    const char* path = "test_sarif.tmp";
    ASSERT_EQ(engine_report_to_sarif(&r, path), 0);
    char buf[4096];
    read_file(path, buf, sizeof(buf));
    ASSERT_TRUE(strstr(buf, "\"version\": \"2.1.0\"") != NULL);
    ASSERT_TRUE(strstr(buf, "\"name\": \"HookScanTool\"") != NULL);
    ASSERT_TRUE(strstr(buf, "\"ruleId\": \"HOOK-IAT\"") != NULL);
    ASSERT_TRUE(strstr(buf, "\"absoluteAddress\": 2575857510") != NULL); /* 0x99887766 */
    /* message must be escaped, not raw */
    ASSERT_TRUE(strstr(buf, "quo\\\"te") != NULL);
    remove(path);
}

static void test_sarif_and_csv_bad_paths(void)
{
    hook_report_t r = make_report();
    ASSERT_EQ(engine_report_to_csv(NULL, "x.tmp"), -1);
    ASSERT_EQ(engine_report_to_csv(&r, NULL), -1);
    ASSERT_EQ(engine_report_to_csv(&r, "."), -1);
    ASSERT_EQ(engine_report_to_sarif(NULL, "x.tmp"), -1);
    ASSERT_EQ(engine_report_to_sarif(&r, NULL), -1);
    ASSERT_EQ(engine_report_to_sarif(&r, "."), -1);
}

void register_tests_json_writer(void)
{
    REGISTER_TEST(json_schema_version);
    REGISTER_TEST(json_escapes_quotes_and_backslashes);
    REGISTER_TEST(json_utf8_passthrough);
    REGISTER_TEST(json_error_fields);
    REGISTER_TEST(json_truncated_flag);
    REGISTER_TEST(json_null_and_bad_path);
    REGISTER_TEST(json_reports_array);
    REGISTER_TEST(csv_basic);
    REGISTER_TEST(csv_field_count_matches_header);
    REGISTER_TEST(csv_no_hooks);
    REGISTER_TEST(sarif_structure);
    REGISTER_TEST(sarif_and_csv_bad_paths);
}
