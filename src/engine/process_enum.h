#ifndef PROCESS_H
#define PROCESS_H

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif
#include <windows.h>

/*
 * Read the target process's image file name (basename only, UTF-8) into buf.
 * Tries GetModuleFileNameExW, then QueryFullProcessImageNameW, then
 * GetProcessImageFileNameW. Leaves buf empty on total failure.
 */
void process_read_image_name(HANDLE process, char* buf, size_t buf_size);

/*
 * Enumerate all running processes.
 * Returns array of process_info_t (with pid and name filled, no modules yet).
 * Caller must free with process_free_list.
 * Returns NULL on error or empty list.
 */
process_info_t* process_enum_all(int* count);

/*
 * Enumerate loaded modules (DLLs) for a given process.
 * Fills the modules array in the process_info_t struct.
 * Returns 0 on success, non-zero on error.
 */
int process_enum_modules(uint32_t pid, process_info_t* info);

/*
 * Get a single process info with modules loaded.
 * Returns 0 on success, non-zero on error.
 */
int process_get_info(uint32_t pid, process_info_t* info);

/*
 * Free a process list allocated by process_enum_all.
 */
void process_free_list(process_info_t* list, int count);

/*
 * Free modules array inside a process_info_t.
 */
void process_free_modules(process_info_t* info);

#ifdef __cplusplus
}
#endif

#endif /* PROCESS_H */
