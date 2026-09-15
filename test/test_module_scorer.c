#include "test_runner.h"
#include "module_scorer.h"
#include <string.h>
#include <windows.h>

/* module_score tests — passes module_info_t with various paths/names */
/* Note: is_trusted_path depends on GetWindowsDirectoryA/GetEnvironmentVariableA
 * at runtime, so the actual scores depend on the test machine's configuration. */

static void test_trusted_windows_path(void)
{
    module_info_t mod;
    memset(&mod, 0, sizeof(mod));

    /* Trusted: under Windows directory (actual path varies by machine) */
    strncpy(mod.name, "kernel32.dll", sizeof(mod.name) - 1);
    strncpy(mod.path, "C:\\Windows\\System32\\kernel32.dll", sizeof(mod.path) - 1);

    uint8_t score = module_score(&mod, true);
    ASSERT_TRUE(is_trusted_path(mod.path));
    /* Windows path = no untrusted penalty, no suspicious name, not WoW64 */
    /* Score should be 0 */
    ASSERT_EQ(score, 0);
}

static void test_trusted_program_files_path(void)
{
    module_info_t mod;
    memset(&mod, 0, sizeof(mod));

    strncpy(mod.name, "something.dll", sizeof(mod.name) - 1);
    strncpy(mod.path, "C:\\Program Files\\App\\something.dll", sizeof(mod.path) - 1);

    ASSERT_TRUE(is_trusted_path(mod.path));
    uint8_t score = module_score(&mod, true);
    ASSERT_EQ(score, 0);
}

static void test_untrusted_path_scores_30(void)
{
    module_info_t mod;
    memset(&mod, 0, sizeof(mod));

    strncpy(mod.name, "mylib.dll", sizeof(mod.name) - 1);
    strncpy(mod.path, "C:\\Users\\test\\AppData\\Local\\Temp\\mylib.dll", sizeof(mod.path) - 1);

    ASSERT_FALSE(is_trusted_path(mod.path));
    uint8_t score = module_score(&mod, true);
    /* Untrusted path = +30, no suspicious name, not WoW64 */
    ASSERT_EQ(score, 30);
}

static void test_suspicious_name_adds_40(void)
{
    module_info_t mod;
    memset(&mod, 0, sizeof(mod));

    /* Suspicious name, trusted path */
    strncpy(mod.name, "hook.dll", sizeof(mod.name) - 1);
    strncpy(mod.path, "C:\\Windows\\System32\\hook.dll", sizeof(mod.path) - 1);

    uint8_t score = module_score(&mod, true);
    /* Trusted path = 0 + suspicious name = 40 */
    ASSERT_EQ(score, 40);
}

static void test_combo_untrusted_plus_suspicious(void)
{
    module_info_t mod;
    memset(&mod, 0, sizeof(mod));

    strncpy(mod.name, "inject.dll", sizeof(mod.name) - 1);
    strncpy(mod.path, "C:\\Users\\test\\inject.dll", sizeof(mod.path) - 1);

    uint8_t score = module_score(&mod, true);
    /* Untrusted (+30) + suspicious name (+40) = 70 */
    ASSERT_EQ(score, 70);
}

static void test_suspicious_name_variants(void)
{
    /* Test all suspicious keywords: hook, inject, patch, spy, capture, intercept */
    const char* keywords[] = {"hook", "inject", "patch", "spy", "capture", "intercept"};

    for (int i = 0; i < 6; i++) {
        module_info_t mod;
        memset(&mod, 0, sizeof(mod));

        strncpy(mod.name, keywords[i], sizeof(mod.name) - 1);
        strncat(mod.name, ".dll", sizeof(mod.name) - strlen(mod.name) - 1);
        strncpy(mod.path, "C:\\Windows\\System32\\", sizeof(mod.path) - 1);
        strncat(mod.path, mod.name, sizeof(mod.path) - strlen(mod.path) - 1);

        uint8_t score = module_score(&mod, true);
        /* Trusted path = 0 + suspicious name = 40 */
        ASSERT_EQ(score, 40);
    }
}

static void test_wow64_in_64bit_process(void)
{
    module_info_t mod;
    memset(&mod, 0, sizeof(mod));

    strncpy(mod.name, "normal.dll", sizeof(mod.name) - 1);
    strncpy(mod.path, "C:\\Windows\\SysWOW64\\normal.dll", sizeof(mod.path) - 1);
    mod.is_wow64 = true;

    uint8_t score = module_score(&mod, true);
    /* Trusted path = 0 + WoW64 in 64-bit = 20 */
    ASSERT_EQ(score, 20);
}

static void test_score_capped_at_100(void)
{
    module_info_t mod;
    memset(&mod, 0, sizeof(mod));

    strncpy(mod.name, "hook_inject_spy.dll", sizeof(mod.name) - 1);
    strncpy(mod.path, "C:\\Users\\test\\hook_inject_spy.dll", sizeof(mod.path) - 1);
    mod.is_wow64 = true;

    uint8_t score = module_score(&mod, true);
    /* Untrusted (+30) + suspicious name (+40) + WoW64 (+20) = 90 */
    /* Not capped since < 100 */
    ASSERT_EQ(score, 90);
}

static void test_score_with_nuLL_mod(void)
{
    uint8_t score = module_score(NULL, true);
    ASSERT_EQ(score, 0);
}

static void test_is_trusted_path_null(void)
{
    ASSERT_FALSE(is_trusted_path(NULL));
    ASSERT_FALSE(is_trusted_path(""));
}

static void test_is_trusted_path_nested(void)
{
    /* Paths nested under Windows dir are also trusted */
    char path[MAX_PATH];
    strncpy(path, "C:\\Windows\\System32\\drivers\\etc\\something.dll", sizeof(path) - 1);
    ASSERT_TRUE(is_trusted_path(path));
}

void register_tests_module_scorer(void)
{
    REGISTER_TEST(trusted_windows_path);
    REGISTER_TEST(trusted_program_files_path);
    REGISTER_TEST(untrusted_path_scores_30);
    REGISTER_TEST(suspicious_name_adds_40);
    REGISTER_TEST(combo_untrusted_plus_suspicious);
    REGISTER_TEST(suspicious_name_variants);
    REGISTER_TEST(wow64_in_64bit_process);
    REGISTER_TEST(score_capped_at_100);
    REGISTER_TEST(score_with_nuLL_mod);
    REGISTER_TEST(is_trusted_path_null);
    REGISTER_TEST(is_trusted_path_nested);
}
