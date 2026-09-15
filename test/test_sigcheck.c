#include "test_runner.h"
#include "sigcheck.h"
#include <stdio.h>
#include <string.h>

/* SHA256("abc") — the classic NIST test vector */
#define ABC_SHA256 "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

static void test_hash_known_vector(void)
{
    FILE* f = fopen("sig_hash_probe.bin", "wb");
    ASSERT_TRUE(f != NULL);
    if (!f) return;
    fwrite("abc", 1, 3, f);
    fclose(f);

    char hex[65] = {0};
    ASSERT_TRUE(sigcheck_hash_file("sig_hash_probe.bin", hex));
    ASSERT_STREQ(hex, ABC_SHA256);

    /* SHA256("") */
    f = fopen("sig_hash_empty.bin", "wb");
    fclose(f);
    ASSERT_TRUE(sigcheck_hash_file("sig_hash_empty.bin", hex));
    ASSERT_STREQ(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    remove("sig_hash_probe.bin");
    remove("sig_hash_empty.bin");
}

static void test_hash_missing_file(void)
{
    char hex[65] = {0};
    ASSERT_FALSE(sigcheck_hash_file("definitely_not_here_9f3b.bin", hex));
}

static void test_load_and_lookup(void)
{
    const char* path = "sig_db_probe.txt";
    FILE* f = fopen(path, "w");
    ASSERT_TRUE(f != NULL);
    if (!f) return;
    fprintf(f, "# comment line\n\n");
    fprintf(f, "%s TestHookDLL\n", ABC_SHA256);
    fprintf(f, "not-a-hash bad line ignored\n");
    fprintf(f, "%s uppercase-matches\n", "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD");
    fclose(f);

    int before = sigcheck_count();
    int added = sigcheck_load(path);
    ASSERT_EQ(added, 2);   /* comment and malformed line skipped */
    ASSERT_TRUE(sigcheck_count() == before + 2);

    /* lowercase digest from hashing matches uppercase DB entry (case-insensitive) */
    char hex[65] = {0};
    f = fopen("sig_hash_probe2.bin", "wb");
    fwrite("abc", 1, 3, f);
    fclose(f);
    ASSERT_TRUE(sigcheck_hash_file("sig_hash_probe2.bin", hex));
    const char* label = sigcheck_lookup(hex);
    ASSERT_TRUE(label != NULL);
    if (label) ASSERT_TRUE(strcmp(label, "TestHookDLL") == 0 || strcmp(label, "uppercase-matches") == 0);

    ASSERT_TRUE(sigcheck_lookup("0000000000000000000000000000000000000000000000000000000000000000") == NULL);
    ASSERT_TRUE(sigcheck_lookup(NULL) == NULL);
    ASSERT_TRUE(sigcheck_lookup("short") == NULL);

    remove(path);
    remove("sig_hash_probe2.bin");
}

void register_tests_sigcheck(void)
{
    REGISTER_TEST(hash_known_vector);
    REGISTER_TEST(hash_missing_file);
    REGISTER_TEST(load_and_lookup);
}
