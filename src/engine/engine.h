#ifndef ENGINE_H
#define ENGINE_H

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

hook_report_t* engine_scan_process(uint32_t pid);

int engine_scan_module(uint32_t pid, const module_info_t* mod,
                       hook_entry_t* hooks, int hook_cap);

bool engine_restore_hook(uint32_t pid, hook_entry_t* entry);

int engine_report_to_json(const hook_report_t* report, const char* path);

void engine_free_report(hook_report_t* report);

module_report_t* engine_recon_process(uint32_t pid);

hook_report_t* engine_scan_modules(uint32_t pid, const module_report_t* recon,
                                   const int* module_indices, int count);

void engine_free_module_report(module_report_t* report);

#ifdef __cplusplus
}
#endif

#endif /* ENGINE_H */