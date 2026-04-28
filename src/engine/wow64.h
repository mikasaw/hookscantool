#ifndef WOW64_H
#define WOW64_H

#include "types.h"
#include <windows.h>

/*
 * Check if a process is running under WoW64 (32-bit on 64-bit OS).
 */
bool wow64_is_process(HANDLE process);

/*
 * Enumerate modules of a WoW64 (32-bit) process from a 64-bit scanner.
 * Uses NtWow64 APIs to read 32-bit PEB.
 *
 * pid:   Target process ID
 * info:  Output process info with modules filled
 * Returns: 0 on success, non-zero on error.
 */
int wow64_enum_modules(uint32_t pid, process_info_t* info);

/*
 * Read memory from a WoW64 process using NtWow64ReadVirtualMemory64.
 * Falls back to standard ReadProcessMemory if not available.
 */
BOOL wow64_read_memory(HANDLE process, LPCVOID addr, LPVOID buf, SIZE_T size, SIZE_T* read);

#endif /* WOW64_H */