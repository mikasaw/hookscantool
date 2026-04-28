#ifndef IAT_SCANNER_H
#define IAT_SCANNER_H

#include "types.h"
#include "pe_parser.h"
#include <windows.h>

/*
 * Scan IAT hooks for a single module in a target process.
 * For each import thunk, checks if the function pointer points outside
 * the expected DLL's address range.
 *
 * process:  Open handle to target process (PROCESS_VM_READ)
 * pid:      Target process ID
 * mod:      Module info for the DLL to scan
 * hooks:    Output array to append detected hooks
 * hook_cap: Capacity of the hooks array
 * Returns:  Number of hooks detected, or -1 on error.
 */
int iat_scan_module(HANDLE process, uint32_t pid, const module_info_t* mod,
                    const process_info_t* pinfo,
                    hook_entry_t* hooks, int hook_cap);

#endif /* IAT_SCANNER_H */
