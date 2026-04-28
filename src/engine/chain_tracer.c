#include "chain_tracer.h"
#include <Zydis/Zydis.h>
#include <stdlib.h>
#include <string.h>

/* Extract the target address from a JMP/CALL instruction */
static bool extract_jump_target(const ZydisDecodedInstruction* instr,
                                const ZydisDecodedOperand* operands,
                                uintptr_t current_ip,
                                uintptr_t* target)
{
    for (uint8_t i = 0; i < instr->operand_count_visible; i++) {
        const ZydisDecodedOperand* op = &operands[i];

        if (op->type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            *target = current_ip + instr->length + op->imm.value.s;
            return true;
        }

        if (op->type == ZYDIS_OPERAND_TYPE_MEMORY) {
            if (op->mem.base == ZYDIS_REGISTER_RIP) {
                uintptr_t eff_addr = current_ip + instr->length + op->mem.disp.value;
                *target = eff_addr;
                return true;
            }
            if (op->mem.base == ZYDIS_REGISTER_NONE &&
                op->mem.index == ZYDIS_REGISTER_NONE &&
                op->mem.disp.has_displacement) {
                *target = (uintptr_t)op->mem.disp.value;
                return true;
            }
        }
    }
    return false;
}

int chain_trace(HANDLE process, uintptr_t start_addr, bool is_64bit,
                chain_step_t* chain, int* chain_len)
{
    *chain_len = 0;

    ZydisDecoder decoder;
    if (is_64bit) {
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    } else {
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);
    }

    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

    uintptr_t addr = start_addr;

    for (int step = 0; step < MAX_CHAIN_DEPTH; step++) {
        uint8_t buf[32];
        SIZE_T  bytes_read = 0;
        if (!ReadProcessMemory(process, (LPCVOID)addr, buf, sizeof(buf), &bytes_read))
            break;
        if (bytes_read < 1) break;

        ZydisDecodedInstruction instr;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
        ZyanStatus status = ZydisDecoderDecodeFull(&decoder, buf, bytes_read,
            &instr, operands);
        if (!ZYAN_SUCCESS(status)) break;

        chain_step_t* cs = &chain[step];
        cs->address = addr;
        int copy_len = (instr.length < 16) ? (int)instr.length : 16;
        memcpy(cs->bytes, buf, copy_len);
        cs->byte_count = copy_len;

        ZydisFormatterFormatInstruction(&formatter, &instr, operands,
            instr.operand_count_visible, cs->disasm, sizeof(cs->disasm), addr, NULL);

        (*chain_len)++;

        bool is_unconditional_jmp = (instr.mnemonic == ZYDIS_MNEMONIC_JMP);
        bool is_ret = (instr.mnemonic == ZYDIS_MNEMONIC_RET);

        if (is_ret) break;

        if (!is_unconditional_jmp) break;

        uintptr_t target;
        if (!extract_jump_target(&instr, operands, addr, &target))
            break;

        bool is_indirect = false;
        for (uint8_t i = 0; i < instr.operand_count_visible; i++) {
            if (operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                is_indirect = true;
                break;
            }
        }

        if (is_indirect) {
            uintptr_t ptr = 0;
            SIZE_T ptr_size = is_64bit ? 8 : 4;
            if (!ReadProcessMemory(process, (LPCVOID)target, &ptr, ptr_size, NULL))
                break;
            if (ptr == 0) break;
            addr = ptr;
        } else {
            addr = target;
        }
    }

    return 0;
}