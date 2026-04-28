#ifndef UI_RESTORE_H
#define UI_RESTORE_H

#include "types.h"
#include "engine.h"

/*
 * Render the restore button and confirmation dialog.
 */
void ui_restore_render(uint32_t pid, hook_report_t* report, int selected_hook);

#endif /* UI_RESTORE_H */