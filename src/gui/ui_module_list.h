#ifndef UI_MODULE_LIST_H
#define UI_MODULE_LIST_H

#include "engine.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Render the module triage panel. Returns selected PID (0 if none).
 * selected_pid: PID from process tree (triggers recon on change).
 * scanning: shared scanning flag (disabled during scan). */
uint32_t ui_module_list_render(uint32_t selected_pid, bool scanning);

/* Get the last hook report from a selective scan. */
hook_report_t* ui_module_get_last_report(void);

/* Free resources on shutdown. */
void ui_module_list_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* UI_MODULE_LIST_H */
