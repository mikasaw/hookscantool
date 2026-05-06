#ifndef UI_PROCESS_TREE_H
#define UI_PROCESS_TREE_H

#include "types.h"

/*
 * Render the process tree panel (left side).
 * Returns the selected PID (0 if none selected).
 */
uint32_t ui_process_tree_render(void);

/*
 * Refresh the process list.
 */
void ui_process_tree_refresh(void);

/*
 * Cleanup process tree resources.
 */
void ui_process_tree_cleanup(void);

/* Check if a scan is currently running */
bool ui_is_scanning(void);

/* Get the last hook report from full process scan */
hook_report_t* ui_get_last_report(void);

#endif /* UI_PROCESS_TREE_H */