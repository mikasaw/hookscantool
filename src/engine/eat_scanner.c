#include "eat_scanner.h"
#include <stdlib.h>
#include <string.h>

int eat_scan_module(HANDLE process, const module_info_t* mod,
                    hook_entry_t* hooks, int hook_cap)
{
    int found = 0;

    /* Parse the in-memory PE to get export directory */
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

    /* Read the export directory from process memory */
    uintptr_t export_addr = mod->base_addr + export_rva;
    IMAGE_EXPORT_DIRECTORY exp_dir;
    if (!ReadProcessMemory(process, (LPCVOID)export_addr, &exp_dir, sizeof(exp_dir), NULL)) {
        pe_free(&mem_image);
        return 0;
    }

    /* Parse the on-disk DLL for comparison */
    uint8_t* disk_data = NULL;
    size_t   disk_size = 0;
    pe_image_t disk_image;
    if (pe_parse_from_disk(mod->path, &disk_data, &disk_size, &disk_image) != 0) {
        pe_free(&mem_image);
        return 0;
    }

    /* Read export name RVAs from process memory */
    uint32_t name_count = exp_dir.NumberOfNames;
    uintptr_t names_addr = mod->base_addr + exp_dir.AddressOfNames;
    uintptr_t ordinals_addr = mod->base_addr + exp_dir.AddressOfNameOrdinals;
    uintptr_t functions_addr = mod->base_addr + exp_dir.AddressOfFunctions;

    for (uint32_t i = 0; i < name_count && found < hook_cap; i++) {
        /* Read function name */
        uint32_t name_rva;
        if (!ReadProcessMemory(process, (LPCVOID)(names_addr + i * 4), &name_rva, 4, NULL))
            continue;

        char func_name[128] = {0};
        ReadProcessMemory(process, (LPCVOID)(mod->base_addr + name_rva), func_name, sizeof(func_name) - 1, NULL);

        /* Read ordinal */
        uint16_t ordinal;
        if (!ReadProcessMemory(process, (LPCVOID)(ordinals_addr + i * 2), &ordinal, 2, NULL))
            continue;

        /* Validate ordinal against NumberOfFunctions to prevent OOB */
        if (ordinal >= exp_dir.NumberOfFunctions)
            continue;

        /* Read in-memory function RVA */
        uint32_t mem_func_rva;
        if (!ReadProcessMemory(process, (LPCVOID)(functions_addr + ordinal * 4), &mem_func_rva, 4, NULL))
            continue;

        /* Skip forwarded exports (RVA points within the export directory itself) */
        if (mem_func_rva >= export_rva && mem_func_rva < export_rva + export_size)
            continue;

        /* Find the same export in the on-disk image. A name can legitimately
         * be exported several times (aliases pointing at different RVAs —
         * common in the MSVC runtime DLLs); only if the in-memory RVA differs
         * from EVERY on-disk occurrence is the export table actually hooked. */
        uint32_t disk_func_rva = 0;
        bool found_in_disk = false;
        bool rva_is_alias = false;
        for (int j = 0; j < disk_image.export_count; j++) {
            if (strcmp(disk_image.exports[j].name, func_name) == 0) {
                if (!found_in_disk) {
                    disk_func_rva = (uint32_t)disk_image.exports[j].rva;
                    found_in_disk = true;
                }
                if ((uint32_t)disk_image.exports[j].rva == mem_func_rva) {
                    rva_is_alias = true;
                    break;
                }
            }
        }

        if (!found_in_disk) continue;
        if (rva_is_alias) continue;

        /* Compare: if RVAs differ, it's an EAT hook */
        if (mem_func_rva != disk_func_rva) {
            hook_entry_t* h = &hooks[found];
            memset(h, 0, sizeof(*h));

            strncpy(h->module_name, mod->name, sizeof(h->module_name) - 1);
            strncpy(h->function_name, func_name, sizeof(h->function_name) - 1);
            h->type = HOOK_EAT;
            h->original_addr = mod->base_addr + disk_func_rva;
            h->current_addr  = mod->base_addr + mem_func_rva;
            h->restorable = !mem_image.is_packed && !disk_image.is_packed;

            /* Read hooked bytes at the current address */
            SIZE_T hooked_read = 0;
            ReadProcessMemory(process, (LPCVOID)h->current_addr,
                              h->hooked_bytes, sizeof(h->hooked_bytes),
                              &hooked_read);
            h->hooked_byte_count = (int)(hooked_read > sizeof(h->hooked_bytes) ? sizeof(h->hooked_bytes) : hooked_read);

            /* Read original bytes from on-disk */
            uint32_t disk_offset;
            if (pe_rva_to_offset(&disk_image, disk_func_rva, &disk_offset) == 0 &&
                disk_offset + sizeof(h->original_bytes) <= disk_size) {
                memcpy(h->original_bytes, disk_data + disk_offset, sizeof(h->original_bytes));
                h->original_byte_count = sizeof(h->original_bytes);
            }

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