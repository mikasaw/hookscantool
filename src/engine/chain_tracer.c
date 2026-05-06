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

/* Check if instruction is MOV reg, imm64/imm32 (used in MOV+JMP reg pattern) */
static bool is_mov_reg_imm(const ZydisDecodedInstruction* instr,
                           const ZydisDecodedOperand* operands,
                           uintptr_t* imm_value)
{
    if (instr->mnemonic != ZYDIS_MNEMONIC_MOV)
        return false;
    if (instr->operand_count_visible < 2)
        return false;
    if (operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER)
        return false;
    if (operands[1].type != ZYDIS_OPERAND_TYPE_IMMEDIATE)
        return false;
    *imm_value = (uintptr_t)operands[1].imm.value.u;
    return true;
}

/* Check if instruction is JMP reg */
static bool is_jmp_reg(const ZydisDecodedInstruction* instr,
                       const ZydisDecodedOperand* operands,
                       ZydisRegister* reg)
{
    if (instr->mnemonic != ZYDIS_MNEMONIC_JMP)
        return false;
    if (instr->operand_count_visible < 1)
        return false;
    if (operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER)
        return false;
    *reg = operands[0].reg.value;
    return true;
}

/* Check if instruction is PUSH imm (used in PUSH+RET pattern) */
static bool is_push_imm(const ZydisDecodedInstruction* instr,
                        const ZydisDecodedOperand* operands,
                        uintptr_t* imm_value)
{
    if (instr->mnemonic != ZYDIS_MNEMONIC_PUSH)
        return false;
    if (instr->operand_count_visible < 1)
        return false;
    if (operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE)
        return false;
    *imm_value = (uintptr_t)operands[0].imm.value.u;
    return true;
}

/* Resolve an indirect memory target by reading the pointer from the process */
static bool resolve_indirect(HANDLE process, bool is_64bit,
                             uintptr_t eff_addr, uintptr_t* resolved)
{
    uintptr_t ptr = 0;
    SIZE_T ptr_size = is_64bit ? 8 : 4;
    if (!ReadProcessMemory(process, (LPCVOID)eff_addr, &ptr, ptr_size, NULL))
        return false;
    if (ptr == 0) return false;
    *resolved = ptr;
    return true;
}

/* Decode one instruction at addr, return true on success */
static bool decode_at(ZydisDecoder* decoder, HANDLE process,
                      uintptr_t addr, uint8_t* buf, size_t buf_size,
                      ZydisDecodedInstruction* instr,
                      ZydisDecodedOperand* operands)
{
    SIZE_T bytes_read = 0;
    if (!ReadProcessMemory(process, (LPCVOID)addr, buf, buf_size, &bytes_read))
        return false;
    if (bytes_read < 1) return false;
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, buf, bytes_read,
                                               instr, operands)))
        return false;
    if (bytes_read < instr->length)
        return false;
    return true;
}

/* Fill a chain_step_t from a decoded instruction */
static void fill_step(chain_step_t* cs, uintptr_t addr,
                      const uint8_t* raw_bytes, int raw_len,
                      ZydisFormatter* formatter,
                      const ZydisDecodedInstruction* instr,
                      const ZydisDecodedOperand* operands)
{
    cs->address = addr;
    int copy_len = (raw_len < 16) ? raw_len : 16;
    memcpy(cs->bytes, raw_bytes, copy_len);
    cs->byte_count = copy_len;
    ZydisFormatterFormatInstruction(formatter, instr, operands,
        instr->operand_count_visible, cs->disasm, sizeof(cs->disasm), addr, NULL);
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
        ZydisDecodedInstruction instr;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

        if (!decode_at(&decoder, process, addr, buf, sizeof(buf), &instr, operands))
            break;

        fill_step(&chain[step], addr, buf, instr.length, &formatter, &instr, operands);
        (*chain_len)++;

        /* --- Pattern 1: RET (end of chain) --- */
        if (instr.mnemonic == ZYDIS_MNEMONIC_RET)
            break;

        /* --- Pattern 2: Unconditional JMP (existing behavior) --- */
        if (instr.mnemonic == ZYDIS_MNEMONIC_JMP) {
            uintptr_t target;
            if (!extract_jump_target(&instr, operands, addr, &target))
                break;

            /* JMP reg — need prior MOV to resolve, handled in pattern 4 */
            bool is_indirect = false;
            for (uint8_t i = 0; i < instr.operand_count_visible; i++) {
                if (operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                    is_indirect = true;
                    break;
                }
                if (operands[i].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    /* JMP reg without preceding MOV — can't resolve target */
                    break;
                }
            }

            if (is_indirect) {
                uintptr_t resolved;
                if (!resolve_indirect(process, is_64bit, target, &resolved))
                    break;
                addr = resolved;
            } else {
                addr = target;
            }
            continue;
        }

        /* --- Pattern 3: PUSH imm + RET --- */
        if (instr.mnemonic == ZYDIS_MNEMONIC_PUSH) {
            uintptr_t push_val;
            if (!is_push_imm(&instr, operands, &push_val))
                break;

            /* Decode next instruction to check for RET */
            uint8_t buf2[16];
            ZydisDecodedInstruction instr2;
            ZydisDecodedOperand ops2[ZYDIS_MAX_OPERAND_COUNT];
            uintptr_t next_addr = addr + instr.length;

            if (decode_at(&decoder, process, next_addr, buf2, sizeof(buf2),
                          &instr2, ops2) &&
                instr2.mnemonic == ZYDIS_MNEMONIC_RET) {
                /* PUSH addr; RET is a jump to push_val */
                addr = push_val;
                continue;
            }
            /* Not PUSH+RET, stop tracing */
            break;
        }

        /* --- Pattern 4: MOV reg, imm + JMP reg --- */
        if (instr.mnemonic == ZYDIS_MNEMONIC_MOV) {
            uintptr_t imm_val;
            ZydisRegister dst_reg;
            if (!is_mov_reg_imm(&instr, operands, &imm_val))
                break;
            dst_reg = operands[0].reg.value;

            /* Decode next instruction to check for JMP reg */
            uint8_t buf2[16];
            ZydisDecodedInstruction instr2;
            ZydisDecodedOperand ops2[ZYDIS_MAX_OPERAND_COUNT];
            uintptr_t next_addr = addr + instr.length;

            if (decode_at(&decoder, process, next_addr, buf2, sizeof(buf2),
                          &instr2, ops2)) {
                ZydisRegister jmp_reg;
                if (is_jmp_reg(&instr2, ops2, &jmp_reg) && jmp_reg == dst_reg) {
                    /* MOV reg, addr; JMP reg is a jump to imm_val */
                    addr = imm_val;
                    continue;
                }
            }
            /* Not MOV+JMP pattern, stop tracing */
            break;
        }

        /* --- Pattern 5: CALL [mem] (hook dispatch via call gate) --- */
        if (instr.mnemonic == ZYDIS_MNEMONIC_CALL) {
            uintptr_t target;
            if (extract_jump_target(&instr, operands, addr, &target)) {
                bool is_indirect = false;
                for (uint8_t i = 0; i < instr.operand_count_visible; i++) {
                    if (operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                        is_indirect = true;
                        break;
                    }
                }
                if (is_indirect) {
                    uintptr_t resolved;
                    if (resolve_indirect(process, is_64bit, target, &resolved)) {
                        addr = resolved;
                        continue;
                    }
                } else {
                    addr = target;
                    continue;
                }
            }
            break;
        }

        /* Unknown pattern, stop tracing */
        break;
    }

    return 0;
}
