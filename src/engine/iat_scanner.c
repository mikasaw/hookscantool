#include "iat_scanner.h"
#include "process_enum.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Resolve the base address and size of a loaded DLL by name */
static bool find_module_range(const process_info_t* pinfo,
                              const char* dll_name,
                              uintptr_t* out_base, uint32_t* out_size)
{
    for (int i = 0; i < pinfo->module_count; i++) {
        if (_stricmp(pinfo->modules[i].name, dll_name) == 0) {
            *out_base = pinfo->modules[i].base_addr;
            *out_size = pinfo->modules[i].size;
            return true;
        }
    }
    return false;
}

int iat_scan_module(HANDLE process, uint32_t pid, const module_info_t* mod,
                    const process_info_t* pinfo,
                    hook_entry_t* hooks, int hook_cap)
{
    (void)pid;
    int found = 0;

    /* Parse the in-memory PE of this module */
    pe_image_t image;
    if (pe_parse_from_process(process, mod->base_addr, &image) != 0)
        return 0;

    if (image.import_count == 0) {
        pe_free(&image);
        return 0;
    }

    /* Walk each import descriptor */
    for (int i = 0; i < image.import_count && found < hook_cap; i++) {
        char* dll_name = image.imports[i].dll_name;
        if (dll_name[0] == '\0') continue;

        /* Find the address range of the imported DLL */
        uintptr_t dll_base = 0;
        uint32_t  dll_size = 0;
        bool dll_found = find_module_range(pinfo, dll_name, &dll_base, &dll_size);

        /* Find the on-disk path of the imported DLL */
        const char* dll_path = NULL;
        for (int m = 0; m < pinfo->module_count; m++) {
            if (_stricmp(pinfo->modules[m].name, dll_name) == 0) {
                dll_path = pinfo->modules[m].path;
                break;
            }
        }

        /* Read the import descriptor from process memory to get FirstThunk */
        uintptr_t import_dir_rva;
        if (image.is_64bit) {
            import_dir_rva = image.nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        } else {
            import_dir_rva = ((IMAGE_NT_HEADERS32*)&image.nt_headers)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        }

        uintptr_t desc_addr = mod->base_addr + import_dir_rva + i * sizeof(IMAGE_IMPORT_DESCRIPTOR);
        IMAGE_IMPORT_DESCRIPTOR desc;
        if (!ReadProcessMemory(process, (LPCVOID)desc_addr, &desc, sizeof(desc), NULL))
            continue;

        uintptr_t first_thunk = desc.FirstThunk;
        int thunk_count = image.imports[i].thunk_count;
        if (thunk_count <= 0) continue;

        /* Read OriginalFirstThunk to get function names */
        uintptr_t oft_rva = desc.OriginalFirstThunk;
        uintptr_t thunk_size = image.is_64bit ? 8 : 4;

        /* Parse the on-disk DLL once for this import descriptor */
        uint8_t* disk_data = NULL;
        size_t   disk_size = 0;
        pe_image_t disk_image = {0};
        bool have_disk = false;
        if (dll_path) {
            have_disk = (pe_parse_from_disk(dll_path, &disk_data, &disk_size, &disk_image) == 0);
        }

        for (int j = 0; j < thunk_count && found < hook_cap; j++) {
            /* Read the IAT entry (current function pointer) */
            uintptr_t iat_entry_addr = mod->base_addr + first_thunk + j * thunk_size;
            uintptr_t func_ptr = 0;
            if (!ReadProcessMemory(process, (LPCVOID)iat_entry_addr, &func_ptr, (SIZE_T)thunk_size, NULL))
                continue;

            if (func_ptr == 0) continue;

            /* Check: does the function pointer point outside the imported DLL? */
            if (dll_found && (func_ptr < dll_base || func_ptr >= dll_base + dll_size)) {
                hook_entry_t* h = &hooks[found];
                memset(h, 0, sizeof(*h));

                strncpy(h->module_name, dll_name, sizeof(h->module_name) - 1);
                h->type = HOOK_IAT;
                h->current_addr = func_ptr;
                h->restorable = false;

                /* Try to read the function name from OriginalFirstThunk */
                if (oft_rva != 0) {
                    uintptr_t oft_addr = mod->base_addr + oft_rva + j * thunk_size;
                    uintptr_t thunk_val = 0;
                    if (ReadProcessMemory(process, (LPCVOID)oft_addr, &thunk_val, (SIZE_T)thunk_size, NULL) && thunk_val != 0) {
                        uintptr_t ordinal_flag = image.is_64bit ? 0x8000000000000000ULL : 0x80000000UL;
                        if (!(thunk_val & ordinal_flag)) {
                            /* Import by name: low 32 bits are the hint/name RVA */
                            uint32_t name_rva_32 = (uint32_t)thunk_val;
                            uintptr_t name_addr = mod->base_addr + name_rva_32 + 2;
                            char fname[128] = {0};
                            ReadProcessMemory(process, (LPCVOID)name_addr, fname, sizeof(fname) - 1, NULL);
                            strncpy(h->function_name, fname, sizeof(h->function_name) - 1);
                        } else {
                            snprintf(h->function_name, sizeof(h->function_name), "Ordinal_%u",
                                     (unsigned)(thunk_val & 0xFFFF));
                        }
                    }
                }

                /* Resolve original address and bytes from cached on-disk DLL */
                if (have_disk && h->function_name[0] != '\0') {
                    for (int k = 0; k < disk_image.export_count; k++) {
                        if (strcmp(disk_image.exports[k].name, h->function_name) == 0) {
                            uintptr_t disk_rva = disk_image.exports[k].rva;
                            h->original_addr = dll_base + disk_rva;
                            h->restorable = !image.is_packed;

                            /* Read original bytes from on-disk */
                            uint32_t disk_offset;
                            if (pe_rva_to_offset(&disk_image, disk_rva, &disk_offset) == 0 &&
                                disk_offset + sizeof(h->original_bytes) <= disk_size) {
                                memcpy(h->original_bytes, disk_data + disk_offset, sizeof(h->original_bytes));
                                h->original_byte_count = sizeof(h->original_bytes);
                            }
                            if (h->original_byte_count == 0)
                                h->restorable = false;
                            break;
                        }
                    }
                }

                /* Read hooked bytes at the target address */
                SIZE_T hooked_read = 0;
                ReadProcessMemory(process, (LPCVOID)func_ptr,
                                  h->hooked_bytes, sizeof(h->hooked_bytes),
                                  &hooked_read);
                h->hooked_byte_count = (int)(hooked_read > sizeof(h->hooked_bytes) ? sizeof(h->hooked_bytes) : hooked_read);

                found++;
            }
        }

        if (have_disk) {
            pe_unmap_disk_image(disk_data, disk_size);
            pe_free(&disk_image);
        }
    }

    pe_free(&image);
    return found;
}
