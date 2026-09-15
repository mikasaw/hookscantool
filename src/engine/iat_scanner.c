#include "iat_scanner.h"
#include "process_enum.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MAX_IMPORT_DESCRIPTORS 256
#define MAX_IMPORT_THUNKS      16384

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

/* Find the on-disk path of a loaded DLL by name */
static const char* find_module_path(const process_info_t* pinfo,
                                    const char* dll_name)
{
    for (int i = 0; i < pinfo->module_count; i++) {
        if (_stricmp(pinfo->modules[i].name, dll_name) == 0)
            return pinfo->modules[i].path;
    }
    return NULL;
}

/* Find the loaded module that contains addr. Returns its index or -1. */
static int find_owner_module(const process_info_t* pinfo, uintptr_t addr)
{
    for (int i = 0; i < pinfo->module_count; i++) {
        if (addr >= pinfo->modules[i].base_addr &&
            addr < pinfo->modules[i].base_addr + pinfo->modules[i].size)
            return i;
    }
    return -1;
}

/* Cache of parsed on-disk images for api-set owner verification */
#define OWNER_CACHE_CAP 16
typedef struct {
    char       name[64];
    bool       tried;
    bool       valid;
    uint8_t*   data;
    size_t     size;
    pe_image_t image;
} owner_cache_t;

static void owner_cache_free(owner_cache_t* cache)
{
    for (int i = 0; i < OWNER_CACHE_CAP; i++) {
        if (cache[i].valid) {
            pe_unmap_disk_image(cache[i].data, cache[i].size);
            pe_free(&cache[i].image);
        }
        cache[i].data = NULL;
        cache[i].size = 0;
        cache[i].tried = false;
        cache[i].valid = false;
    }
}

static owner_cache_t* owner_cache_get(owner_cache_t* cache,
                                      const process_info_t* pinfo,
                                      const char* dll_name)
{
    for (int i = 0; i < OWNER_CACHE_CAP; i++)
        if (cache[i].tried && _stricmp(cache[i].name, dll_name) == 0)
            return &cache[i];
    for (int i = 0; i < OWNER_CACHE_CAP; i++) {
        if (!cache[i].tried) {
            snprintf(cache[i].name, sizeof(cache[i].name), "%s", dll_name);
            cache[i].tried = true;
            const char* path = find_module_path(pinfo, dll_name);
            cache[i].valid = path != NULL &&
                pe_parse_from_disk(path, &cache[i].data, &cache[i].size, &cache[i].image) == 0;
            return &cache[i];
        }
    }
    return NULL; /* cache exhausted — caller must not guess */
}

/* True if addr equals any export address of the named module (on-disk EAT).
 * Matching by address (not by import name) also covers forwarded api-set
 * resolutions, where the loader lands on the forward target's export. */
static bool owner_contains_export_addr(owner_cache_t* entry, uintptr_t owner_base,
                                       uintptr_t addr)
{
    if (!entry || !entry->valid)
        return false;
    for (int k = 0; k < entry->image.export_count; k++) {
        if (owner_base + entry->image.exports[k].rva == addr)
            return true;
    }
    return false;
}

int iat_scan_module(HANDLE process, uint32_t pid, const module_info_t* mod,
                    const process_info_t* pinfo,
                    hook_entry_t* hooks, int hook_cap, bool* hit_cap)
{
    (void)pid;
    int found = 0;
    if (hit_cap) *hit_cap = false;

    /* Parse the in-memory PE of this module (gives us the NT headers) */
    pe_image_t image;
    if (pe_parse_from_process(process, mod->base_addr, &image) != 0)
        return 0;

    /* Import directory from the in-memory NT headers */
    uintptr_t import_dir_rva;
    uint32_t  import_dir_size;
    if (image.is_64bit) {
        import_dir_rva  = image.nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        import_dir_size = image.nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    } else {
        import_dir_rva  = ((IMAGE_NT_HEADERS32*)&image.nt_headers)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        import_dir_size = ((IMAGE_NT_HEADERS32*)&image.nt_headers)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    }

    if (import_dir_rva == 0 || import_dir_size == 0) {
        pe_free(&image);
        return 0;
    }

    const size_t thunk_size = image.is_64bit ? 8 : 4;
    const uintptr_t ordinal_flag = image.is_64bit ? 0x8000000000000000ULL : 0x80000000UL;

    owner_cache_t owner_cache[OWNER_CACHE_CAP];
    memset(owner_cache, 0, sizeof(owner_cache));

    /* Walk import descriptors straight from process memory */
    for (int i = 0; i < MAX_IMPORT_DESCRIPTORS; i++) {
        uintptr_t desc_addr = mod->base_addr + import_dir_rva + i * sizeof(IMAGE_IMPORT_DESCRIPTOR);
        IMAGE_IMPORT_DESCRIPTOR desc;
        if (!ReadProcessMemory(process, (LPCVOID)desc_addr, &desc, sizeof(desc), NULL))
            break;
        if (desc.Name == 0 && desc.FirstThunk == 0)
            break; /* terminator */

        /* DLL name (ANSI) */
        char dll_name[64] = {0};
        ReadProcessMemory(process, (LPCVOID)(mod->base_addr + desc.Name),
                          dll_name, sizeof(dll_name) - 1, NULL);
        if (dll_name[0] == '\0')
            continue;

        /* Find the address range and on-disk path of the imported DLL */
        uintptr_t dll_base = 0;
        uint32_t  dll_size = 0;
        bool dll_found = find_module_range(pinfo, dll_name, &dll_base, &dll_size);
        const char* dll_path = find_module_path(pinfo, dll_name);

        /* FirstThunk array offset (fall back to OriginalFirstThunk) */
        uintptr_t first_thunk = desc.FirstThunk ? desc.FirstThunk : desc.OriginalFirstThunk;
        if (first_thunk == 0)
            continue;

        /* Count thunks by walking the array in memory until the terminator */
        int thunk_count = 0;
        {
            uintptr_t walk_addr = mod->base_addr + first_thunk;
            for (int j = 0; j < MAX_IMPORT_THUNKS; j++) {
                uintptr_t val = 0;
                if (!ReadProcessMemory(process, (LPCVOID)(walk_addr + j * thunk_size),
                                       &val, thunk_size, NULL))
                    break;
                if (val == 0)
                    break;
                thunk_count++;
            }
        }
        if (thunk_count == 0)
            continue;

        /* Parse the on-disk DLL once for this import descriptor */
        uint8_t* disk_data = NULL;
        size_t   disk_size = 0;
        pe_image_t disk_image = {0};
        bool have_disk = false;
        if (dll_path) {
            have_disk = (pe_parse_from_disk(dll_path, &disk_data, &disk_size, &disk_image) == 0);
        }

        for (int j = 0; j < thunk_count; j++) {
            /* Read the IAT entry (current function pointer) */
            uintptr_t iat_entry_addr = mod->base_addr + first_thunk + j * thunk_size;
            uintptr_t func_ptr = 0;
            if (!ReadProcessMemory(process, (LPCVOID)iat_entry_addr, &func_ptr, thunk_size, NULL))
                continue;

            if (func_ptr == 0) continue;

            /* Entries inside the imported DLL are by definition fine */
            if (dll_found &&
                func_ptr >= dll_base && func_ptr < dll_base + dll_size)
                continue;

            /* Function name from the OriginalFirstThunk array (parallel
             * to the IAT; fall back to the IAT itself for bound imports) */
            char fname[128] = {0};
            uintptr_t name_thunk = desc.OriginalFirstThunk ? desc.OriginalFirstThunk : desc.FirstThunk;
            if (name_thunk != 0) {
                uintptr_t oft_addr = mod->base_addr + name_thunk + j * thunk_size;
                uintptr_t thunk_val = 0;
                if (ReadProcessMemory(process, (LPCVOID)oft_addr, &thunk_val, thunk_size, NULL) && thunk_val != 0) {
                    if (!(thunk_val & ordinal_flag)) {
                        /* Import by name: low 32 bits are the hint/name RVA */
                        uint32_t name_rva_32 = (uint32_t)thunk_val;
                        uintptr_t name_addr = mod->base_addr + name_rva_32 + 2;
                        ReadProcessMemory(process, (LPCVOID)name_addr, fname, sizeof(fname) - 1, NULL);
                    } else {
                        snprintf(fname, sizeof(fname), "Ordinal_%u",
                                 (unsigned)(thunk_val & 0xFFFF));
                    }
                }
            }

            /* Follow on-disk export forwarders: "KERNEL32!InitializeSListHead"
             * forwards to "NTDLL.RtlInitializeSListHead", so the loader
             * legitimately points the IAT outside KERNEL32. If the named
             * export forwards to a DLL whose range contains the pointer,
             * this is the loader doing its job, not a hook. */
            if (dll_found && have_disk && fname[0] != '\0') {
                for (int k = 0; k < disk_image.export_count; k++) {
                    if (strcmp(disk_image.exports[k].name, fname) != 0)
                        continue;

                    uint32_t fwd_off = 0;
                    if (pe_rva_to_offset(&disk_image,
                                         (uint32_t)disk_image.exports[k].rva,
                                         &fwd_off) == 0 &&
                        (size_t)fwd_off + 64 <= disk_size) {
                        char fwd_str[65];
                        memcpy(fwd_str, disk_data + fwd_off, 64);
                        fwd_str[64] = '\0';
                        char fwd_dll[48];
                        if (pe_is_forwarder_string(fwd_str, fwd_dll, sizeof(fwd_dll))) {
                            uintptr_t fwd_base = 0;
                            uint32_t  fwd_size = 0;
                            /* forwarder names omit the ".dll" suffix */
                            if (!find_module_range(pinfo, fwd_dll, &fwd_base, &fwd_size)) {
                                char fwd_dll_ext[56];
                                snprintf(fwd_dll_ext, sizeof(fwd_dll_ext), "%s.dll", fwd_dll);
                                find_module_range(pinfo, fwd_dll_ext, &fwd_base, &fwd_size);
                            }
                            if (fwd_size != 0 &&
                                func_ptr >= fwd_base && func_ptr < fwd_base + fwd_size)
                                goto next_thunk; /* loader-resolved forwarder */
                        }
                    }
                    break; /* export found, not a benign forwarder */
                }
            }

            /* Unresolved import names (api-ms-* API Sets): the loader maps
             * them to a real module, so the pointer must land inside some
             * loaded module that actually exports the function. */
            bool flag = true;
            if (!dll_found) {
                int owner = find_owner_module(pinfo, func_ptr);
                if (owner < 0) {
                    /* pointer into unmapped memory — hijacked import */
                    flag = true;
                } else if (fname[0] == '\0' || strncmp(fname, "Ordinal_", 8) == 0) {
                    /* cannot verify by name — do not guess */
                    continue;
                } else {
                    owner_cache_t* e = owner_cache_get(owner_cache, pinfo,
                                                       pinfo->modules[owner].name);
                    if (e && owner_contains_export_addr(e, pinfo->modules[owner].base_addr,
                                                        func_ptr))
                        flag = false;  /* legitimate api-set resolution */
                    else if (!e || !e->valid)
                        continue;      /* cache/parse exhausted — cannot verify, don't guess */
                    else
                        flag = true;   /* pointer is not any export of the owner */
                }
            }

            if (!flag)
                goto next_thunk;

            if (found >= hook_cap) {
                /* the budget is full and another hook was found */
                if (hit_cap) *hit_cap = true;
                break;
            }

            {
                /* Flag as an IAT hook */
                hook_entry_t* h = &hooks[found];
                memset(h, 0, sizeof(*h));

                strncpy(h->module_name, dll_name, sizeof(h->module_name) - 1);
                strncpy(h->function_name, fname, sizeof(h->function_name) - 1);
                h->type = HOOK_IAT;
                h->current_addr = func_ptr;
                h->restorable = false;

                /* Resolve original address and bytes from cached on-disk DLL */
                if (have_disk && fname[0] != '\0') {
                    for (int k = 0; k < disk_image.export_count; k++) {
                        if (strcmp(disk_image.exports[k].name, fname) == 0) {
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
        next_thunk:;
        }

        if (have_disk) {
            pe_unmap_disk_image(disk_data, disk_size);
            pe_free(&disk_image);
        }
    }

    owner_cache_free(owner_cache);
    pe_free(&image);
    return found;
}
