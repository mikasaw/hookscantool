#ifndef TEST_RUNNER_H
#define TEST_RUNNER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* Test framework — minimal, no external dependencies.
 *
 * Usage:
 *   // in test file:
 *   static void test_something(void) { ... }
 *   void register_tests_something(void) {
 *       REGISTER_TEST(something);
 *   }
 *
 * Each test file must have a register_tests_* function.
 * The runner declares and calls all registration functions.
 *
 * Test functions use ASSERT() for conditions,
 * ASSERT_STREQ() for string equality, ASSERT_EQ() for numbers.
 */

/* Global counters */
extern int g_tests_run;
extern int g_tests_passed;
extern int g_tests_failed;

#define MAX_TESTS 512

typedef void (*test_fn_t)(void);

typedef struct {
    const char* name;
    test_fn_t   fn;
} test_entry_t;

extern test_entry_t g_test_registry[MAX_TESTS];
extern int         g_test_count;

/* Register a test. Use: REGISTER_TEST(something) where test function is test_something */
#define REGISTER_TEST(name) \
    register_test_impl(#name, test_##name)

/* Internal registration helper (defined in test_runner.c) */
void register_test_impl(const char* name, test_fn_t fn);

#define ASSERT(cond) do { \
    g_tests_run++; \
    if (!(cond)) { \
        printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        g_tests_failed++; \
    } else { \
        g_tests_passed++; \
    } \
} while(0)

#define ASSERT_STREQ(a, b) do { \
    g_tests_run++; \
    if (strcmp((a), (b)) != 0) { \
        printf("  FAIL %s:%d: \"%s\" != \"%s\"\n", __FILE__, __LINE__, (a), (b)); \
        g_tests_failed++; \
    } else { \
        g_tests_passed++; \
    } \
} while(0)

#define ASSERT_EQ(a, b) do { \
    g_tests_run++; \
    if ((a) != (b)) { \
        printf("  FAIL %s:%d: %lld != %lld\n", __FILE__, __LINE__, \
               (long long)(a), (long long)(b)); \
        g_tests_failed++; \
    } else { \
        g_tests_passed++; \
    } \
} while(0)

#define ASSERT_NE(a, b) do { \
    g_tests_run++; \
    if ((a) == (b)) { \
        printf("  FAIL %s:%d: %lld == %lld\n", __FILE__, __LINE__, \
               (long long)(a), (long long)(b)); \
        g_tests_failed++; \
    } else { \
        g_tests_passed++; \
    } \
} while(0)

#define ASSERT_TRUE(cond) ASSERT(cond)
#define ASSERT_FALSE(cond) ASSERT(!(cond))

#endif /* TEST_RUNNER_H */
