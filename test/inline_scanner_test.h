#ifndef INLINE_SCANNER_TEST_H
#define INLINE_SCANNER_TEST_H

#include <Zydis/Zydis.h>
#include <stdbool.h>
#include <stdint.h>

/* Exported from inline_scanner.c when compiled with -DHOOKSCAN_TESTING.
 * Tests the semantic instruction comparison logic. */
bool test_instructions_match(const ZydisDecodedInstruction* a,
                              const ZydisDecodedOperand* ops_a,
                              const ZydisDecodedInstruction* b,
                              const ZydisDecodedOperand* ops_b,
                              uintptr_t base_a, uintptr_t base_b);

#endif /* INLINE_SCANNER_TEST_H */
