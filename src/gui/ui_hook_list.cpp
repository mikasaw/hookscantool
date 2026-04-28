#include "ui_hook_list.h"
#include <imgui.h>
#include <cstdio>
#include <cstring>

static int g_selected_hook = -1;

static const char* hook_type_str(hook_type_t type)
{
    switch (type) {
        case HOOK_IAT:    return "IAT";
        case HOOK_INLINE: return "INLINE";
        case HOOK_EAT:    return "EAT";
        default:          return "?";
    }
}

int ui_hook_list_render(const hook_report_t* report)
{
    ImGui::Begin("Hooks");

    if (!report) {
        ImGui::Text("Select a process and click 'Scan Selected' to begin.");
        ImGui::End();
        return -1;
    }

    /* Show error if scan failed */
    if (report->error_code != 0) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.3f, 0.3f, 1.0f));
        ImGui::Text("Error: %s", report->error_msg);
        ImGui::PopStyleColor();
        ImGui::Separator();
        ImGui::Text("PID: %u | Time: %llu ms",
                    report->pid, (unsigned long long)report->scan_time_ms);
        ImGui::End();
        return -1;
    }

    if (report->hook_count == 0) {
        ImGui::Text("Process: %s (PID %u)", report->process_name, report->pid);
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.4f, 1.0f, 0.4f, 1.0f));
        ImGui::Text("No hooks detected. %d modules scanned in %llu ms.",
                    report->modules_scanned, (unsigned long long)report->scan_time_ms);
        ImGui::PopStyleColor();
        ImGui::End();
        return -1;
    }

    ImGui::Text("Process: %s (PID %u) | Hooks: %d | Modules: %d | Time: %llu ms",
                report->process_name, report->pid, report->hook_count,
                report->modules_scanned, (unsigned long long)report->scan_time_ms);
    ImGui::Separator();

    if (ImGui::BeginTable("hooks_table", 6,
        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
        ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable)) {

        ImGui::TableSetupColumn("#", ImGuiTableColumnFlags_WidthFixed, 30.0f);
        ImGui::TableSetupColumn("Module", ImGuiTableColumnFlags_WidthFixed, 150.0f);
        ImGui::TableSetupColumn("Function", ImGuiTableColumnFlags_WidthFixed, 200.0f);
        ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 60.0f);
        ImGui::TableSetupColumn("Chain", ImGuiTableColumnFlags_WidthFixed, 50.0f);
        ImGui::TableSetupColumn("Restorable", ImGuiTableColumnFlags_WidthFixed, 70.0f);
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();

        for (int i = 0; i < report->hook_count; i++) {
            const hook_entry_t* h = &report->hooks[i];

            ImGui::TableNextRow();

            if (ImGui::TableSetColumnIndex(0)) {
                char label[16];
                snprintf(label, sizeof(label), "%d", i);
                if (ImGui::Selectable(label, g_selected_hook == i,
                    ImGuiSelectableFlags_SpanAllColumns)) {
                    g_selected_hook = i;
                }
            }
            if (ImGui::TableSetColumnIndex(1)) ImGui::Text("%s", h->module_name);
            if (ImGui::TableSetColumnIndex(2)) ImGui::Text("%s", h->function_name);
            if (ImGui::TableSetColumnIndex(3)) {
                if (h->type == HOOK_INLINE)
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.5f, 0.0f, 1.0f));
                else if (h->type == HOOK_IAT)
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.3f, 0.7f, 1.0f, 1.0f));
                else
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.7f, 0.7f, 0.3f, 1.0f));
                ImGui::Text("%s", hook_type_str(h->type));
                ImGui::PopStyleColor();
            }
            if (ImGui::TableSetColumnIndex(4)) ImGui::Text("%d", h->chain_depth);
            if (ImGui::TableSetColumnIndex(5)) {
                ImGui::Text("%s", h->restorable ? "YES" : "NO");
            }
        }

        ImGui::EndTable();
    }

    ImGui::End();
    return g_selected_hook;
}