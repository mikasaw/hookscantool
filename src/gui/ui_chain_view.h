#ifndef UI_CHAIN_VIEW_H
#define UI_CHAIN_VIEW_H

#include "types.h"

/*
 * Render the chain view panel (bottom).
 * Shows the disassembly chain for a selected hook.
 */
void ui_chain_view_render(const hook_entry_t* hook);

#endif /* UI_CHAIN_VIEW_H */