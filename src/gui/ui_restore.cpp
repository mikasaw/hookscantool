#include "ui_restore.h"
#include <imgui.h>
#include <cstdio>

static bool g_confirm_open = false;
static int  g_confirm_idx  = -1;
static bool g_restore_result = false;
static bool g_show_result = false;

void ui_restore_render(uint32_t pid, hook_report_t* report, int selected_hook)
{
    if (!report || selected_hook < 0 || selected_hook >= report->hook_count)
        return;

    const hook_entry_t* h = &report->hooks[selected_hook];

    ImGui::Begin("Restore");

    if (!h->restorable) {
        ImGui::TextColored(ImVec4(0.7f, 0.7f, 0.7f, 1.0f),
                          "This hook cannot be restored (packed DLL or no on-disk reference).");
        ImGui::End();
        return;
    }

    ImGui::Text("Restore: %s!%s", h->module_name, h->function_name);
    ImGui::Text("This will overwrite the hooked bytes with original bytes from the on-disk DLL.");
    ImGui::Separator();

    if (ImGui::Button("Restore Hook")) {
        g_confirm_open = true;
        g_confirm_idx  = selected_hook;
    }

    /* Confirmation dialog */
    if (g_confirm_open) {
        ImGui::OpenPopup("Confirm Restore");
        if (ImGui::BeginPopupModal("Confirm Restore", &g_confirm_open)) {
            ImGui::Text("Are you sure you want to restore this hook?");
            ImGui::Text("Function: %s!%s", h->module_name, h->function_name);
            ImGui::Text("This will modify the target process memory.");
            ImGui::Separator();

            if (ImGui::Button("Yes, Restore")) {
                hook_entry_t local_entry = *h;
                g_restore_result = engine_restore_hook(pid, &local_entry);
                if (g_restore_result) {
                    /* Mark the shared entry as no longer restorable so UI updates */
                    const_cast<hook_entry_t*>(h)->restorable = false;
                }
                g_show_result = true;
                g_confirm_open = false;
            }
            ImGui::SameLine();
            if (ImGui::Button("Cancel")) {
                g_confirm_open = false;
            }
            ImGui::EndPopup();
        }
    }

    /* Result popup (shown after confirmation closes) */
    if (g_show_result) {
        ImGui::OpenPopup("Restore Result");
        if (ImGui::BeginPopupModal("Restore Result", &g_show_result)) {
            if (g_restore_result) {
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.4f, 1.0f, 0.4f, 1.0f));
                ImGui::Text("Hook restored successfully.");
                ImGui::PopStyleColor();
            } else {
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.3f, 0.3f, 1.0f));
                ImGui::Text("Failed to restore hook.");
                ImGui::PopStyleColor();
            }
            ImGui::Separator();
            if (ImGui::Button("OK")) {
                g_show_result = false;
            }
            ImGui::EndPopup();
        }
    }

    ImGui::End();
}
