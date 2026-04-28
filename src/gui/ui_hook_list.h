#ifndef UI_HOOK_LIST_H
#define UI_HOOK_LIST_H

#include "types.h"
#include "engine.h"

/*
 * Render the hook list panel (right side).
 * Takes the current report and displays all detected hooks.
 * Returns the index of the selected hook (-1 if none).
 */
int ui_hook_list_render(const hook_report_t* report);

#endif /* UI_HOOK_LIST_H */