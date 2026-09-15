#include "test_runner.h"
#include "pe_parser.h"
#include <windows.h>

/* --- Helpers to build minimal PE images in memory --- */

/* Build a minimal 64-bit PE image with one .text section.
 * Returns malloc'd buffer (caller must free). */
static uint8_t* build_min_pe64(size_t* out_size)
{
    size_t nt_off = 0x80; /* e_lfanew = 128 */
    size_t opt_size = sizeof(IMAGE_OPTIONAL_HEADER64);
    size_t nt_total = 4 + sizeof(IMAGE_FILE_HEADER) + opt_size;
    size_t sec_off = nt_off + nt_total;
    size_t total = sec_off + sizeof(IMAGE_SECTION_HEADER);

    uint8_t* buf = (uint8_t*)calloc(1, total);
    if (!buf) return NULL;

    /* DOS header */
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)buf;
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = (LONG)nt_off;

    /* PE signature */
    uint32_t* sig = (uint32_t*)(buf + nt_off);
    *sig = IMAGE_NT_SIGNATURE;

    /* File header */
    IMAGE_FILE_HEADER* fh = (IMAGE_FILE_HEADER*)(buf + nt_off + 4);
    fh->Machine = IMAGE_FILE_MACHINE_AMD64;
    fh->NumberOfSections = 1;
    fh->SizeOfOptionalHeader = (WORD)opt_size;
    fh->Characteristics = IMAGE_FILE_DLL;

    /* Optional header 64 */
    IMAGE_OPTIONAL_HEADER64* oh = (IMAGE_OPTIONAL_HEADER64*)(buf + nt_off + 4 + sizeof(IMAGE_FILE_HEADER));
    oh->Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    oh->AddressOfEntryPoint = 0x1000;
    oh->ImageBase = 0x180000000ULL;
    oh->SectionAlignment = 0x1000;
    oh->FileAlignment = 0x200;
    oh->SizeOfImage = 0x2000;
    oh->SizeOfHeaders = 0x200;
    oh->Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    oh->NumberOfRvaAndSizes = 16;

    /* Section header: .text */
    IMAGE_SECTION_HEADER* sec = (IMAGE_SECTION_HEADER*)(buf + sec_off);
    memcpy(sec->Name, ".text", 5);
    sec->Misc.VirtualSize = 0x1000;
    sec->VirtualAddress = 0x1000;
    sec->SizeOfRawData = 0x200;
    sec->PointerToRawData = 0x200;
    sec->Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

    *out_size = total;
    return buf;
}

/* Build a minimal 32-bit PE image (for is_64bit=false test) */
static uint8_t* build_min_pe32(size_t* out_size)
{
    size_t nt_off = 0x80;
    size_t opt_size = sizeof(IMAGE_OPTIONAL_HEADER32);
    size_t nt_total = 4 + sizeof(IMAGE_FILE_HEADER) + opt_size;
    size_t sec_off = nt_off + nt_total;
    size_t total = sec_off + sizeof(IMAGE_SECTION_HEADER);

    uint8_t* buf = (uint8_t*)calloc(1, total);
    if (!buf) return NULL;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)buf;
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = (LONG)nt_off;

    uint32_t* sig = (uint32_t*)(buf + nt_off);
    *sig = IMAGE_NT_SIGNATURE;

    IMAGE_FILE_HEADER* fh = (IMAGE_FILE_HEADER*)(buf + nt_off + 4);
    fh->Machine = IMAGE_FILE_MACHINE_I386;
    fh->NumberOfSections = 1;
    fh->SizeOfOptionalHeader = (WORD)opt_size;
    fh->Characteristics = IMAGE_FILE_DLL;

    IMAGE_OPTIONAL_HEADER32* oh = (IMAGE_OPTIONAL_HEADER32*)(buf + nt_off + 4 + sizeof(IMAGE_FILE_HEADER));
    oh->Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    oh->AddressOfEntryPoint = 0x1000;
    oh->ImageBase = 0x400000;
    oh->SectionAlignment = 0x1000;
    oh->FileAlignment = 0x200;
    oh->SizeOfImage = 0x2000;
    oh->SizeOfHeaders = 0x200;
    oh->Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    oh->NumberOfRvaAndSizes = 16;

    IMAGE_SECTION_HEADER* sec = (IMAGE_SECTION_HEADER*)(buf + sec_off);
    memcpy(sec->Name, ".text", 5);
    sec->Misc.VirtualSize = 0x1000;
    sec->VirtualAddress = 0x1000;
    sec->SizeOfRawData = 0x200;
    sec->PointerToRawData = 0x200;
    sec->Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

    *out_size = total;
    return buf;
}

/* Build a packed DLL: .text section has no raw data */
static uint8_t* build_packed_pe(size_t* out_size)
{
    size_t nt_off = 0x80;
    size_t opt_size = sizeof(IMAGE_OPTIONAL_HEADER64);
    size_t total = nt_off + 4 + sizeof(IMAGE_FILE_HEADER) + opt_size +
                   sizeof(IMAGE_SECTION_HEADER);

    uint8_t* buf = (uint8_t*)calloc(1, total);
    if (!buf) return NULL;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)buf;
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = (LONG)nt_off;

    uint32_t* sig = (uint32_t*)(buf + nt_off);
    *sig = IMAGE_NT_SIGNATURE;

    IMAGE_FILE_HEADER* fh = (IMAGE_FILE_HEADER*)(buf + nt_off + 4);
    fh->Machine = IMAGE_FILE_MACHINE_AMD64;
    fh->NumberOfSections = 1;
    fh->SizeOfOptionalHeader = (WORD)opt_size;

    IMAGE_OPTIONAL_HEADER64* oh = (IMAGE_OPTIONAL_HEADER64*)(buf + nt_off + 4 + sizeof(IMAGE_FILE_HEADER));
    oh->Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    oh->SectionAlignment = 0x1000;
    oh->FileAlignment = 0x200;
    oh->NumberOfRvaAndSizes = 16;

    IMAGE_SECTION_HEADER* sec = (IMAGE_SECTION_HEADER*)(buf + nt_off + 4 +
        sizeof(IMAGE_FILE_HEADER) + opt_size);
    memcpy(sec->Name, ".text", 5);
    sec->Misc.VirtualSize = 0x1000;  /* Has virtual size */
    sec->VirtualAddress = 0x1000;
    sec->SizeOfRawData = 0;          /* But no raw data = packed */
    sec->PointerToRawData = 0;
    sec->Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

    *out_size = total;
    return buf;
}

/* --- Tests --- */

static void test_parse_valid_pe64(void)
{
    size_t size;
    uint8_t* data = build_min_pe64(&size);
    ASSERT_NE(data, NULL);

    pe_image_t image;
    int ret = pe_parse_from_memory(data, size, &image);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(image.is_64bit, true);
    ASSERT_EQ(image.section_count, 1);
    ASSERT_EQ(image.is_packed, false);
    ASSERT_EQ(image.export_count, 0);
    ASSERT_EQ(image.import_count, 0);
    ASSERT_EQ(image.dos_header.e_magic, IMAGE_DOS_SIGNATURE);

    pe_free(&image);
    free(data);
}

static void test_parse_valid_pe32(void)
{
    size_t size;
    uint8_t* data = build_min_pe32(&size);
    ASSERT_NE(data, NULL);

    pe_image_t image;
    int ret = pe_parse_from_memory(data, size, &image);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(image.is_64bit, false);
    ASSERT_EQ(image.section_count, 1);
    ASSERT_EQ(image.is_packed, false);

    pe_free(&image);
    free(data);
}

static void test_parse_packed_dll(void)
{
    size_t size;
    uint8_t* data = build_packed_pe(&size);
    ASSERT_NE(data, NULL);

    pe_image_t image;
    int ret = pe_parse_from_memory(data, size, &image);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(image.is_packed, true);

    pe_free(&image);
    free(data);
}

static void test_parse_truncated_data(void)
{
    uint8_t tiny[4] = { 'M', 'Z', 0, 0 };
    pe_image_t image;
    int ret = pe_parse_from_memory(tiny, sizeof(tiny), &image);
    ASSERT_EQ(ret, -1);  /* Too small for DOS header */
}

static void test_parse_invalid_dos_magic(void)
{
    uint8_t data[128] = {0};
    pe_image_t image;
    int ret = pe_parse_from_memory(data, sizeof(data), &image);
    ASSERT_EQ(ret, -1);  /* No MZ magic */
}

static void test_parse_invalid_pe_signature(void)
{
    size_t size;
    uint8_t* data = build_min_pe64(&size);
    ASSERT_NE(data, NULL);

    /* Corrupt the PE signature */
    data[0x80] = 0;
    data[0x81] = 0;

    pe_image_t image;
    int ret = pe_parse_from_memory(data, size, &image);
    ASSERT_EQ(ret, -1);

    free(data);
}

static void test_parse_no_sections(void)
{
    /* Build PE with NumberOfSections = 0 */
    size_t nt_off = 0x80;
    size_t opt_size = sizeof(IMAGE_OPTIONAL_HEADER64);
    size_t total = nt_off + 4 + sizeof(IMAGE_FILE_HEADER) + opt_size;

    uint8_t* buf = (uint8_t*)calloc(1, total);
    ASSERT_NE(buf, NULL);

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)buf;
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = (LONG)nt_off;

    uint32_t* sig = (uint32_t*)(buf + nt_off);
    *sig = IMAGE_NT_SIGNATURE;

    IMAGE_FILE_HEADER* fh = (IMAGE_FILE_HEADER*)(buf + nt_off + 4);
    fh->NumberOfSections = 0;
    fh->SizeOfOptionalHeader = (WORD)opt_size;

    IMAGE_OPTIONAL_HEADER64* oh = (IMAGE_OPTIONAL_HEADER64*)(buf + nt_off + 4 + sizeof(IMAGE_FILE_HEADER));
    oh->Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    oh->NumberOfRvaAndSizes = 16;

    pe_image_t image;
    int ret = pe_parse_from_memory(buf, total, &image);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(image.section_count, 0);

    pe_free(&image);
    free(buf);
}

static void test_rva_to_offset(void)
{
    size_t size;
    uint8_t* data = build_min_pe64(&size);
    ASSERT_NE(data, NULL);

    pe_image_t image;
    int ret = pe_parse_from_memory(data, size, &image);
    ASSERT_EQ(ret, 0);

    /* Section: VA=0x1000, RawOffset=0x200, RawSize=0x200 */
    uint32_t offset;
    ret = pe_rva_to_offset(&image, 0x1000, &offset);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(offset, 0x200u);  /* VA 0x1000 → offset 0x200 */

    /* RVA 0x1000 + 0x10 → offset 0x200 + 0x10 = 0x210 */
    ret = pe_rva_to_offset(&image, 0x1010, &offset);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(offset, 0x210u);

    /* RVA outside any section → -1 */
    ret = pe_rva_to_offset(&image, 0x5000, &offset);
    ASSERT_EQ(ret, -1);

    pe_free(&image);
    free(data);
}

static void test_offset_to_rva(void)
{
    size_t size;
    uint8_t* data = build_min_pe64(&size);
    ASSERT_NE(data, NULL);

    pe_image_t image;
    pe_parse_from_memory(data, size, &image);

    /* offset 0x200 → VA 0x1000 */
    uintptr_t rva;
    int ret = pe_offset_to_rva(&image, 0x200, &rva);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(rva, 0x1000u);

    /* offset outside raw data → -1 */
    ret = pe_offset_to_rva(&image, 0x9999, &rva);
    ASSERT_EQ(ret, -1);

    pe_free(&image);
    free(data);
}

static void test_section_names(void)
{
    size_t size;
    uint8_t* data = build_min_pe64(&size);
    ASSERT_NE(data, NULL);

    pe_image_t image;
    pe_parse_from_memory(data, size, &image);

    ASSERT_EQ(image.section_count, 1);
    /* Section name should be ".text" */
    ASSERT(memcmp(image.sections[0].name, ".text", 5) == 0);
    ASSERT_EQ(image.sections[0].virtual_address, 0x1000u);
    ASSERT_EQ(image.sections[0].virtual_size, 0x1000u);
    ASSERT_EQ(image.sections[0].raw_offset, 0x200u);
    ASSERT_EQ(image.sections[0].raw_size, 0x200u);

    pe_free(&image);
    free(data);
}

void register_tests_pe_parser(void)
{
    REGISTER_TEST(parse_valid_pe64);
    REGISTER_TEST(parse_valid_pe32);
    REGISTER_TEST(parse_packed_dll);
    REGISTER_TEST(parse_truncated_data);
    REGISTER_TEST(parse_invalid_dos_magic);
    REGISTER_TEST(parse_invalid_pe_signature);
    REGISTER_TEST(parse_no_sections);
    REGISTER_TEST(rva_to_offset);
    REGISTER_TEST(offset_to_rva);
    REGISTER_TEST(section_names);
}
