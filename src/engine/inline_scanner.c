#include "inline_scanner.h"
#include <Zydis/Zydis.h>
#include <stdlib.h>
#include <string.h>

#define MAX_INSTR_COMPARE 5

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
                disk_func_rva = (uint32_t)disk_image.exports[j].rva;
                found_in_disk = true;
                break;
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
         * 1) If the first 8 bytes are identical between memory and disk,
         *    this is very likely not an inline hook (hooks modify first bytes).
         * 2) If the export address is the same in memory and on disk
         *    (original_addr == current_addr), the function hasn't been
         *    redirected — any byte difference is due to ASLR affecting
         *    RIP-relative operands in data, not a real hook. */
        bool first_8_match = true;
        for (int k = 0; k < 8 && k < (int)mem_read && (disk_offset + k) < disk_size; k++) {
            if (mem_bytes[k] != disk_bytes[k]) {
                first_8_match = false;
                break;
            }
        }
        if (first_8_match) continue;

        /* If the RVA hasn't changed, the export wasn't redirected.
         * Any byte-level difference is ASLR-related, not a hook. */
        if (mem_func_rva == disk_func_rva) continue;

        bool is_hooked = false;
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
                is_hooked = true;
                break;
            }

            mem_off  += mem_instr.length;
            disk_off += disk_instr.length;
            mem_ip   += mem_instr.length;
            disk_ip  += disk_instr.length;
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

            found++;
        }
    }

    pe_unmap_disk_image(disk_data, disk_size);
    pe_free(&disk_image);
    pe_free(&mem_image);
    return found;
}