#include "pe_parser.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Read a null-terminated string from a PE buffer at the given RVA */
static int read_string_at_rva(const uint8_t* data, size_t size,
                              const pe_image_t* image, uintptr_t rva,
                              char* out, int out_size)
{
    uint32_t file_offset;
    if (pe_rva_to_offset(image, rva, &file_offset) != 0)
        return -1;
    if (file_offset >= size)
        return -1;

    const char* src = (const char*)(data + file_offset);
    int i;
    for (i = 0; i < out_size - 1 && src[i] != '\0'; i++) {
        if (file_offset + i >= size)
            break;
        out[i] = src[i];
    }
    out[i] = '\0';
    return 0;
}

int pe_parse_from_memory(const uint8_t* data, size_t size, pe_image_t* image)
{
    memset(image, 0, sizeof(*image));

    if (size < sizeof(IMAGE_DOS_HEADER))
        return -1;

    memcpy(&image->dos_header, data, sizeof(IMAGE_DOS_HEADER));
    if (image->dos_header.e_magic != IMAGE_DOS_SIGNATURE)
        return -1;

    uintptr_t nt_offset = image->dos_header.e_lfanew;
    if (nt_offset + sizeof(IMAGE_NT_HEADERS) > size)
        return -1;

    memcpy(&image->nt_headers, data + nt_offset, sizeof(IMAGE_NT_HEADERS));
    if (image->nt_headers.Signature != IMAGE_NT_SIGNATURE)
        return -1;

    image->is_64bit = (image->nt_headers.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

    /* Parse sections */
    IMAGE_FILE_HEADER* file_hdr = &image->nt_headers.FileHeader;
    int sec_count = file_hdr->NumberOfSections;
    uintptr_t sec_offset = nt_offset + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER)
                         + file_hdr->SizeOfOptionalHeader;

    image->sections = (pe_section_t*)calloc(sec_count, sizeof(pe_section_t));
    if (!image->sections) return -1;
    image->section_count = sec_count;

    for (int i = 0; i < sec_count; i++) {
        uintptr_t off = sec_offset + i * sizeof(IMAGE_SECTION_HEADER);
        if (off + sizeof(IMAGE_SECTION_HEADER) > size) break;

        IMAGE_SECTION_HEADER sec;
        memcpy(&sec, data + off, sizeof(sec));

        memcpy(image->sections[i].name, sec.Name, 8);
        image->sections[i].virtual_address = sec.VirtualAddress;
        image->sections[i].virtual_size    = sec.Misc.VirtualSize;
        image->sections[i].raw_offset      = sec.PointerToRawData;
        image->sections[i].raw_size        = sec.SizeOfRawData;
        image->sections[i].characteristics = sec.Characteristics;

        /* Check for packed DLL: .text section with no raw data */
        if (sec.Name[0] == '.' && sec.Name[1] == 't' &&
            sec.SizeOfRawData == 0 && sec.Misc.VirtualSize > 0) {
            image->is_packed = true;
        }
    }

    /* Parse exports */
    uintptr_t export_rva, export_size;
    if (image->is_64bit) {
        export_rva  = image->nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        export_size = image->nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    } else {
        export_rva  = ((IMAGE_NT_HEADERS32*)&image->nt_headers)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        export_size = ((IMAGE_NT_HEADERS32*)&image->nt_headers)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }

    if (export_rva != 0 && export_size != 0) {
        uint32_t exp_off;
        if (pe_rva_to_offset(image, export_rva, &exp_off) == 0 &&
            exp_off + sizeof(IMAGE_EXPORT_DIRECTORY) <= size) {

            IMAGE_EXPORT_DIRECTORY exp_dir;
            memcpy(&exp_dir, data + exp_off, sizeof(exp_dir));

            int count = exp_dir.NumberOfNames;
            image->exports = (pe_export_t*)calloc(count, sizeof(pe_export_t));
            if (image->exports) {
                image->export_count = count;

                uint32_t names_off, functions_off, ordinals_off;
                if (pe_rva_to_offset(image, exp_dir.AddressOfNames, &names_off) == 0 &&
                    pe_rva_to_offset(image, exp_dir.AddressOfFunctions, &functions_off) == 0 &&
                    pe_rva_to_offset(image, exp_dir.AddressOfNameOrdinals, &ordinals_off) == 0) {

                    for (int i = 0; i < count; i++) {
                        /* Read name */
                        uint32_t name_rva;
                        if (names_off + i * 4 + 4 <= size) {
                            memcpy(&name_rva, data + names_off + i * 4, 4);
                            read_string_at_rva(data, size, image, name_rva,
                                              image->exports[i].name,
                                              sizeof(image->exports[i].name));
                        }

                        /* Read ordinal */
                        uint16_t ordinal;
                        if (ordinals_off + i * 2 + 2 <= size) {
                            memcpy(&ordinal, data + ordinals_off + i * 2, 2);
                        }

                        /* Read function RVA */
                        uint32_t func_rva;
                        if (functions_off + ordinal * 4 + 4 <= size) {
                            memcpy(&func_rva, data + functions_off + ordinal * 4, 4);
                            image->exports[i].rva = func_rva;
                            image->exports[i].ordinal = ordinal;
                        }
                    }
                }
            }
        }
    }

    /* Parse imports */
    uintptr_t import_rva, import_size;
    if (image->is_64bit) {
        import_rva  = image->nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        import_size = image->nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    } else {
        import_rva  = ((IMAGE_NT_HEADERS32*)&image->nt_headers)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        import_size = ((IMAGE_NT_HEADERS32*)&image->nt_headers)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    }

    if (import_rva != 0 && import_size != 0) {
        uint32_t imp_off;
        if (pe_rva_to_offset(image, import_rva, &imp_off) == 0) {
            /* Count import descriptors first */
            int imp_count = 0;
            uintptr_t cur = imp_off;
            while (cur + sizeof(IMAGE_IMPORT_DESCRIPTOR) <= size) {
                IMAGE_IMPORT_DESCRIPTOR desc;
                memcpy(&desc, data + cur, sizeof(desc));
                if (desc.OriginalFirstThunk == 0 && desc.FirstThunk == 0)
                    break;
                imp_count++;
                cur += sizeof(IMAGE_IMPORT_DESCRIPTOR);
            }

            image->imports = (pe_import_t*)calloc(imp_count, sizeof(pe_import_t));
            if (image->imports) {
                image->import_count = imp_count;

                for (int i = 0; i < imp_count; i++) {
                    IMAGE_IMPORT_DESCRIPTOR desc;
                    memcpy(&desc, data + imp_off + i * sizeof(IMAGE_IMPORT_DESCRIPTOR), sizeof(desc));

                    /* Read DLL name */
                    read_string_at_rva(data, size, image, desc.Name,
                                      image->imports[i].dll_name,
                                      sizeof(image->imports[i].dll_name));

                    /* Count thunks */
                    uint32_t oft_off;
                    int thunk_count = 0;
                    if (pe_rva_to_offset(image, desc.OriginalFirstThunk, &oft_off) == 0) {
                        uintptr_t thunk_size = image->is_64bit ? 8 : 4;
                        uintptr_t t = oft_off;
                        while (t + thunk_size <= size) {
                            uint64_t val = 0;
                            memcpy(&val, data + t, (size_t)thunk_size);
                            if (val == 0) break;
                            thunk_count++;
                            t += thunk_size;
                        }
                    }
                    image->imports[i].thunk_count = thunk_count;
                    /* thunk_addr will be filled at scan time with the in-memory IAT address */
                    image->imports[i].thunk_addr = NULL;
                }
            }
        }
    }

    return 0;
}

int pe_parse_from_process(HANDLE process, uintptr_t base_addr, pe_image_t* image)
{
    memset(image, 0, sizeof(*image));
    image->base_addr = base_addr;

    /* Read DOS header */
    IMAGE_DOS_HEADER dos;
    if (!ReadProcessMemory(process, (LPCVOID)base_addr, &dos, sizeof(dos), NULL))
        return -1;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE)
        return -1;

    memcpy(&image->dos_header, &dos, sizeof(dos));

    /* Read file header first to determine optional header size */
    uintptr_t nt_offset = base_addr + dos.e_lfanew;
    uint32_t signature;
    IMAGE_FILE_HEADER file_hdr;
    if (!ReadProcessMemory(process, (LPCVOID)nt_offset, &signature, sizeof(signature), NULL))
        return -1;
    if (signature != IMAGE_NT_SIGNATURE)
        return -1;
    if (!ReadProcessMemory(process, (LPCVOID)(nt_offset + sizeof(signature)),
                           &file_hdr, sizeof(file_hdr), NULL))
        return -1;

    /* Read the full NT headers structure. For 32-bit PE, the optional header
     * is shorter, but IMAGE_NT_HEADERS uses the 64-bit layout. We read the
     * actual size and zero-fill the rest. */
    size_t opt_hdr_size = file_hdr.SizeOfOptionalHeader;
    size_t nt_total = sizeof(signature) + sizeof(file_hdr) + opt_hdr_size;
    uint8_t* nt_buf = (uint8_t*)calloc(1, sizeof(IMAGE_NT_HEADERS));
    if (!nt_buf) return -1;
    if (!ReadProcessMemory(process, (LPCVOID)nt_offset, nt_buf,
                           nt_total > sizeof(IMAGE_NT_HEADERS) ? sizeof(IMAGE_NT_HEADERS) : nt_total, NULL)) {
        free(nt_buf);
        return -1;
    }
    memcpy(&image->nt_headers, nt_buf, sizeof(IMAGE_NT_HEADERS));
    free(nt_buf);

    image->is_64bit = (image->nt_headers.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

    /* Read sections */
    int sec_count = file_hdr.NumberOfSections;
    uintptr_t sec_offset = nt_offset + sizeof(uint32_t)
                        + sizeof(IMAGE_FILE_HEADER) + file_hdr.SizeOfOptionalHeader;

    image->sections = (pe_section_t*)calloc(sec_count, sizeof(pe_section_t));
    if (!image->sections) return -1;
    image->section_count = sec_count;

    for (int i = 0; i < sec_count; i++) {
        IMAGE_SECTION_HEADER sec;
        if (!ReadProcessMemory(process, (LPCVOID)(sec_offset + i * sizeof(sec)),
                               &sec, sizeof(sec), NULL))
            break;

        memcpy(image->sections[i].name, sec.Name, 8);
        image->sections[i].virtual_address = sec.VirtualAddress;
        image->sections[i].virtual_size    = sec.Misc.VirtualSize;
        image->sections[i].raw_offset      = sec.PointerToRawData;
        image->sections[i].raw_size        = sec.SizeOfRawData;
        image->sections[i].characteristics = sec.Characteristics;

        if (sec.Name[0] == '.' && sec.Name[1] == 't' &&
            sec.SizeOfRawData == 0 && sec.Misc.VirtualSize > 0) {
            image->is_packed = true;
        }
    }

    /* For process-parsed images, we read exports and imports lazily during scanning */
    return 0;
}

int pe_parse_from_disk(const char* path, uint8_t** mapped_data, size_t* mapped_size, pe_image_t* image)
{
    HANDLE file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return -1;

    HANDLE mapping = CreateFileMappingA(file, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!mapping) {
        CloseHandle(file);
        return -1;
    }

    *mapped_data = (uint8_t*)MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
    if (!*mapped_data) {
        CloseHandle(mapping);
        CloseHandle(file);
        return -1;
    }

    *mapped_size = GetFileSize(file, NULL);
    CloseHandle(mapping);
    CloseHandle(file);

    int result = pe_parse_from_memory(*mapped_data, *mapped_size, image);
    if (result != 0) {
        UnmapViewOfFile(*mapped_data);
        *mapped_data = NULL;
        *mapped_size = 0;
    }
    return result;
}

void pe_unmap_disk_image(uint8_t* mapped_data, size_t mapped_size)
{
    (void)mapped_size;
    if (mapped_data)
        UnmapViewOfFile(mapped_data);
}

int pe_rva_to_offset(const pe_image_t* image, uintptr_t rva, uint32_t* offset)
{
    for (int i = 0; i < image->section_count; i++) {
        uintptr_t va = image->sections[i].virtual_address;
        uint32_t  vs = image->sections[i].virtual_size;
        if (rva >= va && rva < va + vs) {
            uint32_t off = (uint32_t)(rva - va + image->sections[i].raw_offset);
            /* Verify the offset falls within the section's raw data */
            if (image->sections[i].raw_size > 0 && off >= image->sections[i].raw_offset + image->sections[i].raw_size)
                return -1;
            *offset = off;
            return 0;
        }
    }
    return -1;
}

int pe_offset_to_rva(const pe_image_t* image, uint32_t offset, uintptr_t* rva)
{
    for (int i = 0; i < image->section_count; i++) {
        uint32_t ro = image->sections[i].raw_offset;
        uint32_t rs = image->sections[i].raw_size;
        if (offset >= ro && offset < ro + rs) {
            *rva = image->sections[i].virtual_address + (offset - ro);
            return 0;
        }
    }
    return -1;
}

void pe_free(pe_image_t* image)
{
    if (image->sections) { free(image->sections); image->sections = NULL; }
    if (image->imports)  { free(image->imports);  image->imports = NULL; }
    if (image->exports)  { free(image->exports);  image->exports = NULL; }
    image->section_count = 0;
    image->import_count = 0;
    image->export_count = 0;
}
