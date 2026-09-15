#include "test_runner.h"
#include "inline_scanner_test.h"
#include <Zydis/Zydis.h>

/* Helper: decode one instruction from raw bytes and return true on success */
static bool decode_one(ZydisDecoder* decoder, const uint8_t* bytes, size_t len,
                       ZydisDecodedInstruction* instr,
                       ZydisDecodedOperand* operands)
{
    return ZYAN_SUCCESS(ZydisDecoderDecodeFull(
        decoder, bytes, len, instr, operands));
}

/* Prepare a 64-bit decoder */
static void init_decoder_64(ZydisDecoder* d)
{
    ZydisDecoderInit(d, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
}

/* --- Tests --- */

static void test_same_instruction_matches(void)
{
    ZydisDecoder decoder;
    init_decoder_64(&decoder);

    /* MOV RAX, RCX (x64: 48 89 C8) */
    uint8_t code[] = { 0x48, 0x89, 0xC8 };

    ZydisDecodedInstruction a, b;
    ZydisDecodedOperand a_ops[ZYDIS_MAX_OPERAND_COUNT];
    ZydisDecodedOperand b_ops[ZYDIS_MAX_OPERAND_COUNT];

    ASSERT_TRUE(decode_one(&decoder, code, sizeof(code), &a, a_ops));
    ASSERT_TRUE(decode_one(&decoder, code, sizeof(code), &b, b_ops));

    ASSERT_TRUE(test_instructions_match(&a, a_ops, &b, b_ops, 0x1000, 0x2000));
}

static void test_different_mnemonics_dont_match(void)
{
    ZydisDecoder decoder;
    init_decoder_64(&decoder);

    /* MOV RAX, RCX  vs  XOR RAX, RCX */
    uint8_t mov_code[] = { 0x48, 0x89, 0xC8 };
    uint8_t xor_code[] = { 0x48, 0x31, 0xC8 };  /* XOR RAX, RCX */

    ZydisDecodedInstruction mov, xor;
    ZydisDecodedOperand mov_ops[ZYDIS_MAX_OPERAND_COUNT];
    ZydisDecodedOperand xor_ops[ZYDIS_MAX_OPERAND_COUNT];

    ASSERT_TRUE(decode_one(&decoder, mov_code, sizeof(mov_code), &mov, mov_ops));
    ASSERT_TRUE(decode_one(&decoder, xor_code, sizeof(xor_code), &xor, xor_ops));

    ASSERT_FALSE(test_instructions_match(&mov, mov_ops, &xor, xor_ops, 0, 0));
}

static void test_different_immediates_dont_match(void)
{
    ZydisDecoder decoder;
    init_decoder_64(&decoder);

    /* MOV RAX, 1  vs  MOV RAX, 2 */
    uint8_t mov1[] = { 0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00 };
    uint8_t mov2[] = { 0x48, 0xC7, 0xC0, 0x02, 0x00, 0x00, 0x00 };

    ZydisDecodedInstruction a, b;
    ZydisDecodedOperand a_ops[ZYDIS_MAX_OPERAND_COUNT];
    ZydisDecodedOperand b_ops[ZYDIS_MAX_OPERAND_COUNT];

    ASSERT_TRUE(decode_one(&decoder, mov1, sizeof(mov1), &a, a_ops));
    ASSERT_TRUE(decode_one(&decoder, mov2, sizeof(mov2), &b, b_ops));

    ASSERT_FALSE(test_instructions_match(&a, a_ops, &b, b_ops, 0, 0));
}

static void test_different_registers_dont_match(void)
{
    ZydisDecoder decoder;
    init_decoder_64(&decoder);

    /* MOV RAX, RCX  vs  MOV RBX, RCX */
    uint8_t rax_rcx[] = { 0x48, 0x89, 0xC8 };
    uint8_t rbx_rcx[] = { 0x48, 0x89, 0xD9 };  /* MOV RBX, RCX */

    ZydisDecodedInstruction a, b;
    ZydisDecodedOperand a_ops[ZYDIS_MAX_OPERAND_COUNT];
    ZydisDecodedOperand b_ops[ZYDIS_MAX_OPERAND_COUNT];

    ASSERT_TRUE(decode_one(&decoder, rax_rcx, sizeof(rax_rcx), &a, a_ops));
    ASSERT_TRUE(decode_one(&decoder, rbx_rcx, sizeof(rbx_rcx), &b, b_ops));

    ASSERT_FALSE(test_instructions_match(&a, a_ops, &b, b_ops, 0, 0));
}

static void test_rip_relative_same_target_matches(void)
{
    ZydisDecoder decoder;
    init_decoder_64(&decoder);

    /* LEA RAX, [rip+0x10]  at address 0x1000
     * LEA RAX, [rip+0x20]  at address 0x2000
     * These resolve to the same final address: 0x1013 vs 0x2023?
     * Actually: rip+disp where rip = address + length.
     * LEA RAX, [rip+0x10]: rip = 0x1000 + 7 = 0x1007, target = 0x1017
     * LEA RAX, [rip+0x20]: rip = 0x2000 + 7 = 0x2007, target = 0x2027
     * These are different targets but same RVA...
     *
     * Wait, let me use the comparison logic:
     * rva_a = target_a - base_a = (base_a + length + disp) - base_a = length + disp
     * rva_b = target_b - base_b = (base_b + length + disp) - base_b = length + disp
     * So rva_a == rva_b always! That means the RVA comparison always passes
     * for identical instructions regardless of ASLR.
     *
     * The test should verify that two instructions with DIFFERENT RIP-relative
     * targets (different displacements) are detected as different. */

    uint8_t lea1[] = { 0x48, 0x8D, 0x05, 0x10, 0x00, 0x00, 0x00 };  /* LEA RAX, [rip+0x10] */
    uint8_t lea2[] = { 0x48, 0x8D, 0x05, 0x20, 0x00, 0x00, 0x00 };  /* LEA RAX, [rip+0x20] */

    ZydisDecodedInstruction a, b;
    ZydisDecodedOperand a_ops[ZYDIS_MAX_OPERAND_COUNT];
    ZydisDecodedOperand b_ops[ZYDIS_MAX_OPERAND_COUNT];

    ASSERT_TRUE(decode_one(&decoder, lea1, sizeof(lea1), &a, a_ops));
    ASSERT_TRUE(decode_one(&decoder, lea2, sizeof(lea2), &b, b_ops));

    /* Same base addresses — different displacements should NOT match */
    ASSERT_FALSE(test_instructions_match(&a, a_ops, &b, b_ops, 0x1000, 0x1000));
}

static void test_different_operand_count(void)
{
    ZydisDecoder decoder;
    init_decoder_64(&decoder);

    /* RET (no operands) vs MOV RAX, RCX (2 operands) */
    uint8_t ret[]  = { 0xC3 };
    uint8_t mov[]  = { 0x48, 0x89, 0xC8 };

    ZydisDecodedInstruction a, b;
    ZydisDecodedOperand a_ops[ZYDIS_MAX_OPERAND_COUNT];
    ZydisDecodedOperand b_ops[ZYDIS_MAX_OPERAND_COUNT];

    ASSERT_TRUE(decode_one(&decoder, ret, sizeof(ret), &a, a_ops));
    ASSERT_TRUE(decode_one(&decoder, mov, sizeof(mov), &b, b_ops));

    ASSERT_FALSE(test_instructions_match(&a, a_ops, &b, b_ops, 0, 0));
}

static void test_jmp_imm_vs_jmp_imm_diff_target(void)
{
    ZydisDecoder decoder;
    init_decoder_64(&decoder);

    /* JMP rel8: EB 10 (jmp +0x10) vs EB 20 (jmp +0x20) */
    uint8_t jmp1[] = { 0xEB, 0x10 };
    uint8_t jmp2[] = { 0xEB, 0x20 };

    ZydisDecodedInstruction a, b;
    ZydisDecodedOperand a_ops[ZYDIS_MAX_OPERAND_COUNT];
    ZydisDecodedOperand b_ops[ZYDIS_MAX_OPERAND_COUNT];

    ASSERT_TRUE(decode_one(&decoder, jmp1, sizeof(jmp1), &a, a_ops));
    ASSERT_TRUE(decode_one(&decoder, jmp2, sizeof(jmp2), &b, b_ops));

    /* Same base — different immediate → not match */
    ASSERT_FALSE(test_instructions_match(&a, a_ops, &b, b_ops, 0x1000, 0x1000));
}

static void test_jmp_same_target_aslr(void)
{
    ZydisDecoder decoder;
    init_decoder_64(&decoder);

    /* JMP +0x10 at base 0x1000  vs  JMP +0x20 at base 0x2000
     * These resolve to the same target: 0x1012 vs 0x2022?
     * target_a = 0x1000 + 2 + 0x10 = 0x1012
     * target_b = 0x2000 + 2 + 0x20 = 0x2022
     * These are NOT the same.
     *
     * For JMP, the operand is immediate, not RIP-relative.
     * The comparison uses imm.value.s directly, not resolved address.
     * So JMP +0x10 != JMP +0x20 regardless of base address. */

    uint8_t jmp[] = { 0xEB, 0x10 };

    ZydisDecodedInstruction a, b;
    ZydisDecodedOperand a_ops[ZYDIS_MAX_OPERAND_COUNT];
    ZydisDecodedOperand b_ops[ZYDIS_MAX_OPERAND_COUNT];

    ASSERT_TRUE(decode_one(&decoder, jmp, sizeof(jmp), &a, a_ops));
    ASSERT_TRUE(decode_one(&decoder, jmp, sizeof(jmp), &b, b_ops));

    /* Same instruction at different bases → should match (immediate same) */
    ASSERT_TRUE(test_instructions_match(&a, a_ops, &b, b_ops, 0x1000, 0x2000));
}

void register_tests_inline_matcher(void)
{
    REGISTER_TEST(same_instruction_matches);
    REGISTER_TEST(different_mnemonics_dont_match);
    REGISTER_TEST(different_immediates_dont_match);
    REGISTER_TEST(different_registers_dont_match);
    REGISTER_TEST(rip_relative_same_target_matches);
    REGISTER_TEST(different_operand_count);
    REGISTER_TEST(jmp_imm_vs_jmp_imm_diff_target);
    REGISTER_TEST(jmp_same_target_aslr);
}
