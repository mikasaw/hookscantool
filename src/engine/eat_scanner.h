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
 * Returns:  Number of hooks detected, or -1 on error.
 */
int eat_scan_module(HANDLE process, const module_info_t* mod,
                    hook_entry_t* hooks, int hook_cap, bool* hit_cap);

#endif /* EAT_SCANNER_H */
