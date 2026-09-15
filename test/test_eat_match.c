#include "test_runner.h"
#include "eat_scanner.h"
#include <stdlib.h>
#include <string.h>

/* --- eat_match_disk_rva: pure alias-matching logic --- */

/* Build a synthetic pe_image_t export table (names point at the entries
 * themselves; only name/rva matter to the matcher). */
static pe_image_t make_image(pe_export_t** out_exports, int count,
                             const char* const* names, const uint32_t* rvas)
{
    pe_image_t img;
    memset(&img, 0, sizeof(img));
    img.export_count = count;
    img.exports = (pe_export_t*)calloc((size_t)count, sizeof(pe_export_t));
    for (int i = 0; i < count; i++) {
        snprintf(img.exports[i].name, sizeof(img.exports[i].name), "%s", names[i]);
        img.exports[i].rva = rvas[i];
    }
    *out_exports = img.exports;
    return img;
}

static void test_match_alias_first_occurrence(void)
{
    const char* names[] = { "Foo", "Bar" };
    const uint32_t rvas[] = { 0x1000, 0x2000 };
    pe_export_t* owned;
    pe_image_t img = make_image(&owned, 2, names, rvas);

    uint32_t first = 0;
    ASSERT_EQ(eat_match_disk_rva(&img, "Foo", 0x1000, &first), EAT_MATCH_ALIAS);
    ASSERT_EQ(first, 0x1000);
    free(owned);
    pe_free(&img);
}

static void test_match_alias_second_occurrence(void)
{
    /* same name exported twice with different RVAs (msvcp_win style) */
    const char* names[] = { "Foo", "Bar", "Foo", "Foo" };
    const uint32_t rvas[] = { 0x1000, 0x2000, 0x3000, 0x4000 };
    pe_export_t* owned;
    pe_image_t img = make_image(&owned, 4, names, rvas);

    uint32_t first = 0;
    ASSERT_EQ(eat_match_disk_rva(&img, "Foo", 0x3000, &first), EAT_MATCH_ALIAS);
    ASSERT_EQ(first, 0x1000); /* first occurrence reported as original */
    ASSERT_EQ(eat_match_disk_rva(&img, "Foo", 0x4000, &first), EAT_MATCH_ALIAS);
    free(owned);
    pe_free(&img);
}

static void test_match_different_is_hook(void)
{
    const char* names[] = { "Foo" };
    const uint32_t rvas[] = { 0x1000 };
    pe_export_t* owned;
    pe_image_t img = make_image(&owned, 1, names, rvas);

    uint32_t first = 0;
    ASSERT_EQ(eat_match_disk_rva(&img, "Foo", 0x9000, &first), EAT_MATCH_DIFFERENT);
    ASSERT_EQ(first, 0x1000);
    free(owned);
    pe_free(&img);
}

static void test_match_not_found(void)
{
    const char* names[] = { "Foo" };
    const uint32_t rvas[] = { 0x1000 };
    pe_export_t* owned;
    pe_image_t img = make_image(&owned, 1, names, rvas);

    ASSERT_EQ(eat_match_disk_rva(&img, "Missing", 0x1000, NULL), EAT_MATCH_NOT_FOUND);
    ASSERT_EQ(eat_match_disk_rva(NULL, "Foo", 0x1000, NULL), EAT_MATCH_NOT_FOUND);
    free(owned);
    pe_free(&img);
}

void register_tests_eat_match(void)
{
    REGISTER_TEST(match_alias_first_occurrence);
    REGISTER_TEST(match_alias_second_occurrence);
    REGISTER_TEST(match_different_is_hook);
    REGISTER_TEST(match_not_found);
}
