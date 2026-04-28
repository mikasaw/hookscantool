#ifndef INLINE_SCANNER_H
#define INLINE_SCANNER_H

#include "types.h"
#include "pe_parser.h"
#include <windows.h>

/*
 * Scan inline hooks for a single module in a target process.
 * For each exported function, reads the first bytes and compares
 * against the on-disk DLL using Zydis instruction-level comparison.
 * RIP-relative operands are compared by resolved target address.
 *
 * process:  Open handle to target process (PROCESS_VM_READ)
 * mod:      Module info for the DLL to scan
 * hooks:    Output array to append detected hooks
 * hook_cap: Capacity of the hooks array
 * Returns:  Number of hooks detected, or -1 on error.
 */
int inline_scan_module(HANDLE process, const module_info_t* mod,
                       hook_entry_t* hooks, int hook_cap);

#endif /* INLINE_SCANNER_H */
