#ifndef PE_PARSER_H
#define PE_PARSER_H

#include "types.h"
#include <windows.h>

/* Parsed PE import entry */
typedef struct {
    char       dll_name[64];
    uintptr_t* thunk_addr;     /* Address of the IAT thunk array in target process */
    uint32_t   thunk_count;    /* Number of thunks */
} pe_import_t;

/* Parsed PE export entry */
typedef struct {
    char       name[128];
    uintptr_t  rva;            /* Export RVA */
    uintptr_t  address;        /* Resolved address (base + rva) */
    uint16_t   ordinal;
} pe_export_t;

/* Parsed PE section info */
typedef struct {
    char       name[8];
    uintptr_t  virtual_address;
    uint32_t   virtual_size;
    uint32_t   raw_offset;
    uint32_t   raw_size;
    uint32_t   characteristics;
} pe_section_t;

/* Fully parsed PE image */
typedef struct {
    uintptr_t      base_addr;
    IMAGE_DOS_HEADER  dos_header;
    IMAGE_NT_HEADERS  nt_headers;
    pe_section_t*  sections;
    int            section_count;
    pe_import_t*   imports;
    int            import_count;
    pe_export_t*   exports;
    int            export_count;
    bool           is_64bit;
    bool           is_packed;  /* .text section has no raw data */
} pe_image_t;

/*
 * Parse a PE image from a memory buffer (on-disk DLL bytes).
 * Returns 0 on success, non-zero on error.
 * Caller must free image->sections, image->imports, image->exports.
 */
int pe_parse_from_memory(const uint8_t* data, size_t size, pe_image_t* image);

/*
 * Parse a PE image from a target process by reading its memory.
 * Uses ReadProcessMemory to read headers and directories.
 * Returns 0 on success, non-zero on error.
 */
int pe_parse_from_process(HANDLE process, uintptr_t base_addr, pe_image_t* image);

/*
 * Map an on-disk DLL and parse it. Returns the mapped base and parsed image.
 * Caller must unmap via pe_unmap_disk_image.
 */
int pe_parse_from_disk(const char* path, uint8_t** mapped_data, size_t* mapped_size, pe_image_t* image);

/*
 * Unmap a previously mapped on-disk DLL.
 */
void pe_unmap_disk_image(uint8_t* mapped_data, size_t mapped_size);

/*
 * Convert an RVA to a file offset using section table.
 * Returns 0 on success, non-zero if RVA is invalid.
 */
int pe_rva_to_offset(const pe_image_t* image, uintptr_t rva, uint32_t* offset);

/*
 * Convert a file offset to an RVA using section table.
 * Returns 0 on success, non-zero if offset is invalid.
 */
int pe_offset_to_rva(const pe_image_t* image, uint32_t offset, uintptr_t* rva);

/*
 * Free resources allocated by pe_parse_*.
 */
void pe_free(pe_image_t* image);

#endif /* PE_PARSER_H */
