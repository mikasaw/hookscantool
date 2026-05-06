#ifndef MODULE_SCORER_H
#define MODULE_SCORER_H

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Compute suspicion score (0-100) for a module based on heuristics.
 * v1: path, name, WoW64. No PE parsing. */
uint8_t module_score(const module_info_t* mod, bool process_is_64bit);

/* Check if a path is under a trusted system directory (Windows, Program Files).
 * Uses dynamic paths from GetWindowsDirectoryA/GetEnvironmentVariableA. */
bool is_trusted_path(const char* path);

#ifdef __cplusplus
}
#endif

#endif /* MODULE_SCORER_H */
