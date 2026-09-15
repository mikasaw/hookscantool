#ifndef ENGINE_H
#define ENGINE_H

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Error contract (applies to all functions returning a report):
 *
 * heap exhaustion → returns NULL.
 * every other failure → returns a non-NULL report with error_code != 0 and
 * a human-readable error_msg. Callers MUST check the pointer first, then
 * error_code — success is signalled only by non-NULL && error_code == 0.
 *
 * All returned reports are owned by the caller and must be released with
 * engine_free_report / engine_free_module_report.
 */

/* Full scan: enumerate all modules of the process and run the IAT, EAT and
 * inline scanners over each of them, tracing hook chains for inline hits. */
hook_report_t* engine_scan_process(uint32_t pid);

/* Scan a single module. hooks is a CALLER-allocated array of hook_cap
 * entries; entries are zeroed by the caller. Returns the number of hooks
 * written (0 = no hooks, -1 = the process could not be opened/enumerated).
 * Note: this function is currently unused by CLI/GUI — prefer
 * engine_scan_modules. */
int engine_scan_module(uint32_t pid, const module_info_t* mod,
                       hook_entry_t* hooks, int hook_cap);

/* Restore a detected hook: suspend target threads, verify the hook bytes
 * are still what was scanned (TOCTOU), write back the original bytes,
 * verify the write (rolling back to the hooked state on failure), then
 * resume the threads. Returns false when the hook was not restored; the
 * target is left in its pre-call (still hooked) state. */
bool engine_restore_hook(uint32_t pid, hook_entry_t* entry);

/* Write one scan report as a JSON object to path (UTF-8).
 * Returns 0 on success, -1 on argument/file/write failure. */
int engine_report_to_json(const hook_report_t* report, const char* path);

/* Write multiple reports (e.g. --deep scan) as
 * {"schema_version":1,"process_count":N,"processes":[...]}.
 * Returns 0 on success, -1 on argument/file/write failure. */
int engine_reports_to_json(const hook_report_t* const* reports, int count,
                           const char* path);

/* Free a report returned by engine_scan_process/engine_scan_modules,
 * including every hook's chain array. */
void engine_free_report(hook_report_t* report);

/* Recon pass: enumerate the process's modules and score each for suspicion
 * (no scanning). Result feeds engine_scan_modules. */
module_report_t* engine_recon_process(uint32_t pid);

/* Scan the selected modules (indices into recon->modules; 0 <= idx <
 * recon->module_count). recon must stay valid and unmodified for the whole
 * call. Returns a report owned by the caller (engine_free_report). */
hook_report_t* engine_scan_modules(uint32_t pid, const module_report_t* recon,
                                   const int* module_indices, int count);

/* Free a recon report returned by engine_recon_process. */
void engine_free_module_report(module_report_t* report);

#ifdef __cplusplus
}
#endif

#endif /* ENGINE_H */
