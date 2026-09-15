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

/* Write an array of reports (e.g. --deep multi-process scan) as a single
 * JSON document: {"schema_version":1,"process_count":N,"processes":[...]}. */
int engine_reports_to_json(const hook_report_t* const* reports, int count,
                           const char* path);

void engine_free_report(hook_report_t* report);

module_report_t* engine_recon_process(uint32_t pid);

hook_report_t* engine_scan_modules(uint32_t pid, const module_report_t* recon,
                                   const int* module_indices, int count);

void engine_free_module_report(module_report_t* report);

#ifdef __cplusplus
}
#endif

#endif /* ENGINE_H */