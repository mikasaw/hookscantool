#ifndef EAT_SCANNER_H
#define EAT_SCANNER_H

#include "types.h"
#include "pe_parser.h"
#include <windows.h>

/*
 * Scan EAT hooks for a single module in a target process.
 * Compares in-memory export RVAs against on-disk export RVAs.
 * If they differ, the export has been patched.
 *
 * process:  Open handle to target process (PROCESS_VM_READ)
 * mod:      Module info for the DLL to scan
 * hooks:    Output array to append detected hooks
 * hook_cap: Capacity of the hooks array
 * hit_cap:  Optional; set when a hook was found but discarded because
 *           the hooks array was full
 * Returns:  Number of hooks detected, or -1 on error.
 */
int eat_scan_module(HANDLE process, const module_info_t* mod,
                    hook_entry_t* hooks, int hook_cap, bool* hit_cap);

/*
 * Result of matching an in-memory export RVA against the on-disk
 * export table by name (see eat_match_disk_rva).
 */
typedef enum {
    EAT_MATCH_NOT_FOUND,  /* name not exported on disk */
    EAT_MATCH_ALIAS,      /* mem RVA equals one of the disk occurrences (legal alias) */
    EAT_MATCH_DIFFERENT   /* name exists but mem RVA matches none of them (hook) */
} eat_match_result_t;

/*
 * Pure helper: look up func_name in the parsed on-disk export table and
 * classify how mem_rva relates to the matching entries. first_rva receives
 * the first occurrence's RVA (used as the hook's original address).
 */
eat_match_result_t eat_match_disk_rva(const pe_image_t* disk_image,
                                      const char* func_name,
                                      uint32_t mem_rva,
                                      uint32_t* first_rva);

#endif /* EAT_SCANNER_H */
