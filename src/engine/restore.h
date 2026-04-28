#ifndef RESTORE_H
#define RESTORE_H

#include "types.h"
#include <windows.h>

/*
 * Restore a hooked function by writing original bytes from the on-disk DLL.
 * Suspends target threads, writes bytes, resumes threads.
 *
 * process: Open handle to target process (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION)
 * pid:     Target process ID (for thread enumeration)
 * entry:   The hook entry to restore (must have restorable=true and original_bytes filled)
 * Returns: true on success, false on error.
 */
bool restore_hook(HANDLE process, uint32_t pid, hook_entry_t* entry);

#endif /* RESTORE_H */