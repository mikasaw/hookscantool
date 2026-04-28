#include "ui_chain_view.h"
#include <imgui.h>
#include <cstdio>

void ui_chain_view_render(const hook_entry_t* hook)
{
    ImGui::Begin("Hook Chain");

    if (!hook) {
        ImGui::Text("Select a hook to view its chain.");
        ImGui::End();
        return;
    }

    ImGui::Text("Function: %s!%s", hook->module_name, hook->function_name);
    ImGui::Separator();

    /* Show original vs current address */
    ImGui::Text("Original addr: 0x%016llX", (unsigned long long)hook->original_addr);
    ImGui::Text("Current  addr: 0x%016llX", (unsigned long long)hook->current_addr);
    ImGui::Separator();

    /* Show original bytes */
    ImGui::Text("Original bytes:");
    char hex[128] = {0};
    int off = 0;
    for (int i = 0; i < hook->original_byte_count && off < 100; i++) {
        off += snprintf(hex + off, sizeof(hex) - off, "%02X ", hook->original_bytes[i]);
    }
    ImGui::Text("  %s", hex);

    /* Show hooked bytes */
    ImGui::Text("Hooked bytes:");
    hex[0] = '\0'; off = 0;
    for (int i = 0; i < hook->hooked_byte_count && off < 100; i++) {
        off += snprintf(hex + off, sizeof(hex) - off, "%02X ", hook->hooked_bytes[i]);
    }
    ImGui::Text("  %s", hex);

    ImGui::Separator();

    /* Show chain */
    if (hook->chain_depth == 0 || !hook->chain) {
        ImGui::Text("No chain traced (not an inline hook or chain is trivial).");
    } else {
        ImGui::Text("Hook chain (%d steps):", hook->chain_depth);
        ImGui::Separator();

        if (ImGui::BeginTable("chain_table", 3,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY)) {

            ImGui::TableSetupColumn("Step", ImGuiTableColumnFlags_WidthFixed, 40.0f);
            ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 160.0f);
            ImGui::TableSetupColumn("Disassembly", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();

            for (int i = 0; i < hook->chain_depth; i++) {
                const chain_step_t* cs = &hook->chain[i];
                ImGui::TableNextRow();
                if (ImGui::TableSetColumnIndex(0)) ImGui::Text("%d", i);
                if (ImGui::TableSetColumnIndex(1)) ImGui::Text("0x%016llX", (unsigned long long)cs->address);
                if (ImGui::TableSetColumnIndex(2)) {
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.4f, 1.0f, 0.4f, 1.0f));
                    ImGui::Text("%s", cs->disasm);
                    ImGui::PopStyleColor();
                }
            }

            ImGui::EndTable();
        }
    }

    ImGui::End();
}