#include "test_runner.h"
#include "args.h"

/* --- parse_pid --- */

static void test_pid_valid(void)
{
    uint32_t v = 0;
    ASSERT_TRUE(parse_pid("123", &v));
    ASSERT_EQ(v, 123);
}

static void test_pid_max_u32(void)
{
    uint32_t v = 0;
    ASSERT_TRUE(parse_pid("4294967295", &v));
    ASSERT_EQ(v, 4294967295u);
}

static void test_pid_overflow_u32(void)
{
    /* 2^32 must be rejected (regression: ERANGE used to be treated as success) */
    uint32_t v = 123;
    ASSERT_FALSE(parse_pid("4294967296", &v));
    ASSERT_EQ(v, 123); /* untouched on failure */
}

static void test_pid_overflow_u64(void)
{
    uint32_t v = 0;
    ASSERT_FALSE(parse_pid("99999999999999999999", &v));
}

static void test_pid_zero_rejected(void)
{
    uint32_t v = 0;
    ASSERT_FALSE(parse_pid("0", &v));
}

static void test_pid_negative_rejected(void)
{
    /* strtoull wraps negatives — must never come back as a plausible PID */
    uint32_t v = 0;
    ASSERT_FALSE(parse_pid("-5", &v));
}

static void test_pid_nonnumeric_rejected(void)
{
    uint32_t v = 0;
    ASSERT_FALSE(parse_pid("abc", &v));
}

static void test_pid_trailing_garbage_rejected(void)
{
    uint32_t v = 0;
    ASSERT_FALSE(parse_pid("123abc", &v));
    ASSERT_FALSE(parse_pid("0x10", &v));
}

static void test_pid_empty_and_null_rejected(void)
{
    uint32_t v = 0;
    ASSERT_FALSE(parse_pid("", &v));
    ASSERT_FALSE(parse_pid(NULL, &v));
}

static void test_pid_leading_space_rejected(void)
{
    uint32_t v = 0;
    ASSERT_FALSE(parse_pid(" 12", &v));
    ASSERT_FALSE(parse_pid("+12", &v));
}

/* --- parse_index --- */

static void test_index_valid(void)
{
    int v = -1;
    ASSERT_TRUE(parse_index("0", &v));
    ASSERT_EQ(v, 0);
    ASSERT_TRUE(parse_index("42", &v));
    ASSERT_EQ(v, 42);
}

static void test_index_int_max_ok(void)
{
    int v = -1;
    ASSERT_TRUE(parse_index("2147483647", &v));
    ASSERT_EQ(v, 2147483647);
}

static void test_index_above_int_max_rejected(void)
{
    int v = -1;
    ASSERT_FALSE(parse_index("2147483648", &v));
}

static void test_index_negative_rejected(void)
{
    int v = -1;
    ASSERT_FALSE(parse_index("-1", &v));
}

static void test_index_garbage_rejected(void)
{
    int v = -1;
    ASSERT_FALSE(parse_index("", &v));
    ASSERT_FALSE(parse_index("abc", &v));
    ASSERT_FALSE(parse_index(NULL, &v));
}

void register_tests_cli_args(void)
{
    REGISTER_TEST(pid_valid);
    REGISTER_TEST(pid_max_u32);
    REGISTER_TEST(pid_overflow_u32);
    REGISTER_TEST(pid_overflow_u64);
    REGISTER_TEST(pid_zero_rejected);
    REGISTER_TEST(pid_negative_rejected);
    REGISTER_TEST(pid_nonnumeric_rejected);
    REGISTER_TEST(pid_trailing_garbage_rejected);
    REGISTER_TEST(pid_empty_and_null_rejected);
    REGISTER_TEST(pid_leading_space_rejected);
    REGISTER_TEST(index_valid);
    REGISTER_TEST(index_int_max_ok);
    REGISTER_TEST(index_above_int_max_rejected);
    REGISTER_TEST(index_negative_rejected);
    REGISTER_TEST(index_garbage_rejected);
}
