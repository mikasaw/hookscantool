#include "inline_scanner.h"
#include <Zydis/Zydis.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MAX_INSTR_COMPARE 5

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

/* Check if a jump target is in a different module than the source.
 * CFG/ILT trampolines sit in separate allocations just below the module's
 * base address, so we check both the simple range and the adjacent-allocation
 * heuristic. A target is intra-module if:
 * 1. It's within [base, base+size), OR
 * 2. It's in a separate allocation within 64KB below the module base
 *    (CFG/ILT dispatch pages are typically 1-16 pages below). */
static bool is_cross_module(HANDLE process, uintptr_t module_base,
                            uint32_t module_size, uintptr_t target)
{
    /* Simple range check first */
    if (target >= module_base && target < module_base + module_size)
        return false;

    /* Check if target is in an adjacent allocation below the module base.
     * CFG dispatch pages are typically 1-16 pages below the module base. */
    MEMORY_BASIC_INFORMATION mbi_tgt = {0};
    if (VirtualQueryEx(process, (LPCVOID)target, &mbi_tgt, sizeof(mbi_tgt)) == 0)
        return true;  /* Can't determine — assume cross-module */

    uintptr_t alloc_base = (uintptr_t)mbi_tgt.AllocationBase;

    /* If the target's allocation base is within 64KB below the module base,
     * it's likely a CFG/ILT page belonging to the same module. */
    if (alloc_base < module_base && alloc_base >= module_base - 0x10000)
        return false;

    return true;
}

/* Check if two decoded instructions match semantically, accounting for
 * ASLR relocations in RIP-relative operands. */
static bool instructions_match(const ZydisDecodedInstruction* a,
                               const ZydisDecodedOperand* ops_a,
                               const ZydisDecodedInstruction* b,
                               const ZydisDecodedOperand* ops_b,
                               uintptr_t base_a, uintptr_t base_b)
{
    if (a->mnemonic != b->mnemonic)
        return false;
    if (a->operand_count_visible != b->operand_count_visible)
        return false;

    for (uint8_t i = 0; i < a->operand_count_visible; i++) {
        const ZydisDecodedOperand* op_a = &ops_a[i];
        const ZydisDecodedOperand* op_b = &ops_b[i];

        if (op_a->type != op_b->type)
            return false;

        if (op_a->type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            if (op_a->imm.value.s != op_b->imm.value.s)
                return false;
        } else if (op_a->type == ZYDIS_OPERAND_TYPE_MEMORY) {
            if (op_a->mem.base == ZYDIS_REGISTER_RIP &&
                op_b->mem.base == ZYDIS_REGISTER_RIP) {
                uintptr_t target_a = base_a + a->length + op_a->mem.disp.value;
                uintptr_t target_b = base_b + b->length + op_b->mem.disp.value;
                uintptr_t rva_a = target_a - base_a;
                uintptr_t rva_b = target_b - base_b;
                if (rva_a != rva_b)
                    return false;
            } else {
                if (op_a->mem.disp.value != op_b->mem.disp.value)
                    return false;
                if (op_a->mem.base != op_b->mem.base)
                    return false;
                if (op_a->mem.index != op_b->mem.index)
                    return false;
                if (op_a->mem.scale != op_b->mem.scale)
                    return false;
            }
        } else if (op_a->type == ZYDIS_OPERAND_TYPE_REGISTER) {
            if (op_a->reg.value != op_b->reg.value)
                return false;
        }
    }
    return true;
}

#ifdef HOOKSCAN_TESTING
/* Exported for unit testing — declared in test/inline_scanner_test.h */
bool test_instructions_match(const ZydisDecodedInstruction* a,
                              const ZydisDecodedOperand* ops_a,
                              const ZydisDecodedInstruction* b,
                              const ZydisDecodedOperand* ops_b,
                              uintptr_t base_a, uintptr_t base_b)
{
    return instructions_match(a, ops_a, b, ops_b, base_a, base_b);
}
#endif

int inline_scan_module(HANDLE process, const module_info_t* mod,
                       hook_entry_t* hooks, int hook_cap)
{
    int found = 0;

    pe_image_t mem_image;
    if (pe_parse_from_process(process, mod->base_addr, &mem_image) != 0)
        return 0;

    uintptr_t export_rva, export_size;
    if (mem_image.is_64bit) {
        export_rva  = mem_image.nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        export_size = mem_image.nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    } else {
        export_rva  = ((IMAGE_NT_HEADERS32*)&mem_image.nt_headers)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        export_size = ((IMAGE_NT_HEADERS32*)&mem_image.nt_headers)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }

    if (export_rva == 0 || export_size == 0) {
        pe_free(&mem_image);
        return 0;
    }

    IMAGE_EXPORT_DIRECTORY exp_dir;
    if (!ReadProcessMemory(process, (LPCVOID)(mod->base_addr + export_rva),
                           &exp_dir, sizeof(exp_dir), NULL)) {
        pe_free(&mem_image);
        return 0;
    }

    uint8_t* disk_data = NULL;
    size_t   disk_size = 0;
    pe_image_t disk_image;
    if (pe_parse_from_disk(mod->path, &disk_data, &disk_size, &disk_image) != 0) {
        pe_free(&mem_image);
        return 0;
    }

    ZydisDecoder decoder;
    if (mem_image.is_64bit) {
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    } else {
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);
    }

    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

    uint32_t name_count = exp_dir.NumberOfNames;
    uintptr_t names_addr    = mod->base_addr + exp_dir.AddressOfNames;
    uintptr_t ordinals_addr = mod->base_addr + exp_dir.AddressOfNameOrdinals;
    uintptr_t functions_addr = mod->base_addr + exp_dir.AddressOfFunctions;

    for (uint32_t i = 0; i < name_count && found < hook_cap; i++) {
        uint32_t name_rva;
        if (!ReadProcessMemory(process, (LPCVOID)(names_addr + i * 4), &name_rva, 4, NULL))
            continue;

        char func_name[128] = {0};
        ReadProcessMemory(process, (LPCVOID)(mod->base_addr + name_rva),
                          func_name, sizeof(func_name) - 1, NULL);

        uint16_t ordinal;
        if (!ReadProcessMemory(process, (LPCVOID)(ordinals_addr + i * 2), &ordinal, 2, NULL))
            continue;

        /* Validate ordinal against NumberOfFunctions to prevent OOB */
        if (ordinal >= exp_dir.NumberOfFunctions)
            continue;

        uint32_t mem_func_rva;
        if (!ReadProcessMemory(process, (LPCVOID)(functions_addr + ordinal * 4), &mem_func_rva, 4, NULL))
            continue;

        if (mem_func_rva >= export_rva && mem_func_rva < export_rva + export_size)
            continue;

        uintptr_t mem_func_addr = mod->base_addr + mem_func_rva;

        uint32_t disk_func_rva = 0;
        bool found_in_disk = false;
        for (int j = 0; j < disk_image.export_count; j++) {
            if (strcmp(disk_image.exports[j].name, func_name) == 0) {
                if (!found_in_disk) {
                    /* first occurrence is the fallback for EAT-redirect checks */
                    disk_func_rva = (uint32_t)disk_image.exports[j].rva;
                    found_in_disk = true;
                }
                /* export aliases: pair the in-memory RVA with its own
                 * on-disk occurrence so prologues are compared correctly */
                if ((uint32_t)disk_image.exports[j].rva == mem_func_rva) {
                    disk_func_rva = (uint32_t)disk_image.exports[j].rva;
                    break;
                }
            }
        }
        if (!found_in_disk) continue;

        uint8_t mem_bytes[64];
        SIZE_T  mem_read = 0;
        if (!ReadProcessMemory(process, (LPCVOID)mem_func_addr,
                               mem_bytes, sizeof(mem_bytes), &mem_read))
            continue;
        if (mem_read < 16) continue;

        uint32_t disk_offset;
        if (pe_rva_to_offset(&disk_image, disk_func_rva, &disk_offset) != 0)
            continue;
        if (disk_offset + 64 > disk_size) continue;

        const uint8_t* disk_bytes = disk_data + disk_offset;

        /* Heuristic: skip data exports.
         * If the first 8 bytes are identical between memory and disk,
         * this is very likely not an inline hook (hooks modify first bytes).
         * However, if the function starts with a cross-module jmp/call
         * (e.g. WoW64 ntdll Nt* stubs), we still need to check it. */
        bool first_8_match = true;
        for (int k = 0; k < 8 && k < (int)mem_read && (disk_offset + k) < disk_size; k++) {
            if (mem_bytes[k] != disk_bytes[k]) {
                first_8_match = false;
                break;
            }
        }

        /* If the export RVA hasn't changed, the function wasn't redirected.
         * Byte differences are likely ASLR relocations, not hooks. But we
         * still check via Zydis — if the first instruction decodes as a
         * jump/call/push+ret redirect, it IS a hook even with the same RVA
         * (some hooks patch the prologue without touching the EAT). */
        bool same_rva = (mem_func_rva == disk_func_rva);

        /* When the EAT RVA changed, the function was redirected via EAT.
         * The code at the new address is a forwarding thunk (jmp to the
         * real implementation), not an inline hook. The EAT scanner
         * already reports these. Skip inline detection for EAT redirects. */
        if (!same_rva) continue;

        bool is_hooked = false;

        /* If bytes match exactly, the function hasn't been patched — skip it.
         * For WoW64 modules too: if bytes match, the function is original OS code
         * (including legitimate forwarding stubs and syscall transitions). */
        if (first_8_match && !mod->is_wow64)
            continue;

        if (first_8_match && mod->is_wow64) {
            /* Bytes match exactly — the function hasn't been patched.
             * Any jmp/call in the prologue is part of the original OS code
             * (e.g. DLL forwarding stubs, WoW64 syscall transitions), not a
             * hook. Skip it. */
            continue;
        }

        /* Full Zydis comparison: decode up to MAX_INSTR_COMPARE instructions
         * from both memory and disk, compare at the semantic level. */
        uintptr_t mem_ip  = mem_func_addr;
        uintptr_t disk_ip = mod->base_addr + disk_func_rva;
        size_t mem_off  = 0;
        size_t disk_off = 0;

        for (int instr_idx = 0; instr_idx < MAX_INSTR_COMPARE; instr_idx++) {
            ZydisDecodedInstruction mem_instr, disk_instr;
            ZydisDecodedOperand mem_ops[ZYDIS_MAX_OPERAND_COUNT];
            ZydisDecodedOperand disk_ops[ZYDIS_MAX_OPERAND_COUNT];

            ZyanStatus status_mem  = ZydisDecoderDecodeFull(&decoder,
                mem_bytes + mem_off, mem_read - mem_off, &mem_instr, mem_ops);
            ZyanStatus status_disk = ZydisDecoderDecodeFull(&decoder,
                disk_bytes + disk_off, disk_size - disk_offset - disk_off, &disk_instr, disk_ops);

            if (!ZYAN_SUCCESS(status_mem) || !ZYAN_SUCCESS(status_disk))
                break;

            if (!instructions_match(&mem_instr, mem_ops, &disk_instr, disk_ops, mem_ip, disk_ip)) {
                /* Only flag as inline hook if the first differing instruction
                 * is a redirect pattern (jmp/call/push+ret) that jumps to
                 * a different module. Intra-module jumps (CFG/ILT trampolines)
                 * are not real hooks. For instr_idx > 0, the prologue matched —
                 * any later difference is almost certainly ASLR, not a hook. */
                if (instr_idx == 0) {
                    bool is_redirect = (mem_instr.mnemonic == ZYDIS_MNEMONIC_JMP ||
                                        mem_instr.mnemonic == ZYDIS_MNEMONIC_CALL);
                    /* If both memory and disk have the same redirect mnemonic
                     * (e.g. both are JMP), the byte difference is just a
                     * relocation fixup — this is a legitimate forwarding
                     * stub, not a hook. Real hooks replace the original
                     * instruction with a different redirect. */
                    if (is_redirect && same_rva &&
                        mem_instr.mnemonic == disk_instr.mnemonic)
                        break;
                    uintptr_t jump_target = 0;
                    if (is_redirect) {
                        for (uint8_t oi = 0; oi < mem_instr.operand_count_visible; oi++) {
                            if (mem_ops[oi].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                                uintptr_t base = mem_ip + mem_instr.length;
                                int64_t offset = mem_ops[oi].imm.value.s;
                                uintptr_t jump_target_calc = (offset >= 0) ? base + (uintptr_t)offset : base - (uintptr_t)(-offset);
                                if ((offset >= 0 && jump_target_calc < base) ||
                                    (offset < 0 && jump_target_calc > base))
                                    break;  /* overflow — skip this target */
                                jump_target = jump_target_calc;
                                break;
                            }
                            if (mem_ops[oi].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                                if (mem_ops[oi].mem.base == ZYDIS_REGISTER_RIP) {
                                    uintptr_t eff_addr = mem_ip + mem_instr.length + mem_ops[oi].mem.disp.value;
                                    resolve_indirect(process, mem_image.is_64bit, eff_addr, &jump_target);
                                } else if (mem_ops[oi].mem.base == ZYDIS_REGISTER_NONE &&
                                           mem_ops[oi].mem.index == ZYDIS_REGISTER_NONE &&
                                           mem_ops[oi].mem.disp.has_displacement) {
                                    uintptr_t eff_addr = (uintptr_t)mem_ops[oi].mem.disp.value;
                                    resolve_indirect(process, mem_image.is_64bit, eff_addr, &jump_target);
                                }
                                break;
                            }
                        }
                    }
                    if (!is_redirect && mem_instr.mnemonic == ZYDIS_MNEMONIC_PUSH) {
                        ZydisDecodedInstruction next_instr;
                        ZydisDecodedOperand next_ops[ZYDIS_MAX_OPERAND_COUNT];
                        if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder,
                                mem_bytes + mem_instr.length,
                                mem_read - mem_instr.length,
                                &next_instr, next_ops)) &&
                            next_instr.mnemonic == ZYDIS_MNEMONIC_RET) {
                            /* If the disk image also has push+ret, this is a
                             * legitimate forwarding stub (relocation, not hook). */
                            if (disk_instr.mnemonic == ZYDIS_MNEMONIC_PUSH) {
                                ZydisDecodedInstruction disk_next;
                                if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder,
                                        disk_bytes + disk_instr.length,
                                        disk_size - disk_offset - disk_instr.length,
                                        &disk_next, NULL)) &&
                                    disk_next.mnemonic == ZYDIS_MNEMONIC_RET)
                                    break;
                            }
                            is_redirect = true;
                            /* PUSH+RET: target is the push immediate */
                            for (uint8_t oi = 0; oi < mem_instr.operand_count_visible; oi++) {
                                if (mem_ops[oi].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                                    jump_target = (uintptr_t)mem_ops[oi].imm.value.u;
                                    break;
                                }
                            }
                        }
                    }
                    if (!is_redirect)
                        break;
                    /* Intra-module redirect — not a real hook */
                    if (jump_target && !is_cross_module(process, mod->base_addr, mod->size, jump_target))
                        break;
                    is_hooked = true;
                }
                /* instr_idx > 0: prologue matched, later mismatch is ASLR */
                break;
            }

            mem_off  += mem_instr.length;
            disk_off += disk_instr.length;
            mem_ip   += mem_instr.length;
            disk_ip  += disk_instr.length;
        }

        /* Even when instructions match semantically, an indirect jmp/call
         * may point to a different target if the pointer was patched in
         * memory (e.g. WoW64 ntdll Nt* stubs hooked by AV software).
         * Compare the actual indirect targets. */
        if (!is_hooked && same_rva) {
            ZydisDecodedInstruction first_mem, first_disk;
            ZydisDecodedOperand fmem_ops[ZYDIS_MAX_OPERAND_COUNT];
            ZydisDecodedOperand fdisk_ops[ZYDIS_MAX_OPERAND_COUNT];
            ZyanStatus sm = ZydisDecoderDecodeFull(&decoder, mem_bytes, mem_read,
                                                    &first_mem, fmem_ops);
            ZyanStatus sd = ZydisDecoderDecodeFull(&decoder, disk_bytes,
                                                    disk_size - disk_offset,
                                                    &first_disk, fdisk_ops);
            if (ZYAN_SUCCESS(sm) && ZYAN_SUCCESS(sd) &&
                (first_mem.mnemonic == ZYDIS_MNEMONIC_JMP ||
                 first_mem.mnemonic == ZYDIS_MNEMONIC_CALL)) {
                uintptr_t mem_tgt = 0, disk_tgt = 0;
                for (uint8_t oi = 0; oi < first_mem.operand_count_visible; oi++) {
                    if (fmem_ops[oi].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                        uintptr_t eff = 0;
                        if (fmem_ops[oi].mem.base == ZYDIS_REGISTER_RIP)
                            eff = mem_func_addr + first_mem.length + fmem_ops[oi].mem.disp.value;
                        else if (fmem_ops[oi].mem.base == ZYDIS_REGISTER_NONE &&
                                 fmem_ops[oi].mem.index == ZYDIS_REGISTER_NONE &&
                                 fmem_ops[oi].mem.disp.has_displacement)
                            eff = (uintptr_t)fmem_ops[oi].mem.disp.value;
                        if (eff) resolve_indirect(process, mem_image.is_64bit, eff, &mem_tgt);
                        break;
                    }
                }
                for (uint8_t oi = 0; oi < first_disk.operand_count_visible; oi++) {
                    if (fdisk_ops[oi].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                        uintptr_t eff = 0;
                        if (fdisk_ops[oi].mem.base == ZYDIS_REGISTER_RIP)
                            eff = mod->base_addr + disk_func_rva + first_disk.length + fdisk_ops[oi].mem.disp.value;
                        else if (fdisk_ops[oi].mem.base == ZYDIS_REGISTER_NONE &&
                                 fdisk_ops[oi].mem.index == ZYDIS_REGISTER_NONE &&
                                 fdisk_ops[oi].mem.disp.has_displacement)
                            eff = (uintptr_t)fdisk_ops[oi].mem.disp.value;
                        /* For disk image, the pointer is in the disk bytes, not
                         * in process memory. Convert the effective address to an
                         * RVA, then to a file offset, and read from disk_data. */
                        if (eff) {
                            uint32_t ptr_rva = (uint32_t)(eff - mod->base_addr);
                            uint32_t ptr_file_off;
                            size_t ptr_size = mem_image.is_64bit ? 8 : 4;
                            if (pe_rva_to_offset(&disk_image, ptr_rva, &ptr_file_off) == 0 &&
                                ptr_file_off + ptr_size <= disk_size) {
                                memcpy(&disk_tgt, disk_data + ptr_file_off, ptr_size);
                            }
                        }
                        break;
                    }
                }
                if (mem_tgt && disk_tgt && mem_tgt != disk_tgt) {
                    if (is_cross_module(process, mod->base_addr, mod->size, mem_tgt))
                        is_hooked = true;
                }
                /* Also detect OS-level redirects (e.g. WoW64 ntdll Nt* stubs)
                 * where both memory and disk jump cross-module to the same
                 * target. These are legitimate redirects, not malware, but
                 * the function is still redirected via an inline jump. */
                if (!is_hooked && mem_tgt && disk_tgt && mem_tgt == disk_tgt) {
                    if (is_cross_module(process, mod->base_addr, mod->size, mem_tgt))
                        is_hooked = true;
                }
            }
        }

        if (is_hooked) {
            hook_entry_t* h = &hooks[found];
            memset(h, 0, sizeof(*h));

            strncpy(h->module_name, mod->name, sizeof(h->module_name) - 1);
            strncpy(h->function_name, func_name, sizeof(h->function_name) - 1);
            h->type = HOOK_INLINE;
            h->original_addr = mod->base_addr + disk_func_rva;
            h->current_addr  = mem_func_addr;
            h->restorable = !mem_image.is_packed && !disk_image.is_packed;

            int copy_len = (mem_read < 16) ? (int)mem_read : 16;
            memcpy(h->hooked_bytes, mem_bytes, copy_len);
            h->hooked_byte_count = copy_len;

            int orig_len = ((int)(disk_size - disk_offset) < 16) ? (int)(disk_size - disk_offset) : 16;
            memcpy(h->original_bytes, disk_bytes, orig_len);
            h->original_byte_count = orig_len;

            if (h->original_byte_count == 0)
                h->restorable = false;

            found++;
        }
    }

    pe_unmap_disk_image(disk_data, disk_size);
    pe_free(&disk_image);
    pe_free(&mem_image);
    return found;
}