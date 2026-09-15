#include "test_runner.h"
#include <stdio.h>

int g_tests_run    = 0;
int g_tests_passed = 0;
int g_tests_failed = 0;

test_entry_t g_test_registry[MAX_TESTS];
int          g_test_count = 0;

void register_test_impl(const char* name, test_fn_t fn)
{
    if (g_test_count < MAX_TESTS) {
        g_test_registry[g_test_count].name = name;
        g_test_registry[g_test_count].fn   = fn;
        g_test_count++;
    }
}

/* Declare test suite registration functions from other translation units */
void register_tests_pe_parser(void);
void register_tests_module_scorer(void);
void register_tests_inline_matcher(void);
void register_tests_cli_args(void);
void register_tests_json_writer(void);
void register_tests_eat_match(void);
void register_tests_sigcheck(void);

int main(void)
{
    printf("HookScanTool Test Suite\n");
    printf("=======================\n\n");

    /* Register all test suites */
    register_tests_pe_parser();
    register_tests_module_scorer();
    register_tests_inline_matcher();
    register_tests_cli_args();
    register_tests_json_writer();
    register_tests_eat_match();
    register_tests_sigcheck();

    /* Run all registered tests */
    for (int i = 0; i < g_test_count; i++) {
        printf("[TEST] %s\n", g_test_registry[i].name);
        g_test_registry[i].fn();
    }

    printf("\n=======================\n");
    printf("Results: %d/%d passed, %d failed, %d total\n",
           g_tests_passed, g_tests_run,
           g_tests_failed, g_tests_run);

    return g_tests_failed > 0 ? 1 : 0;
}
