#include "ui_hook_list.h"
#include "engine.h"
#include <imgui.h>
#include <windows.h>
#include <commdlg.h>
#include <cstdio>
#include <cstring>

static int g_selected_hook = -1;

/* Save-as dialog; returns chosen path in buf (empty on cancel) */
static bool save_file_dialog(const char* filter, const char* def_ext,
                             char* buf, int cap)
{
    OPENFILENAMEA ofn;
    memset(&ofn, 0, sizeof(ofn));
    buf[0] = '\0';
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = GetActiveWindow();
    ofn.lpstrFilter = filter;
    ofn.lpstrFile   = buf;
    ofn.nMaxFile    = cap;
    ofn.lpstrDefExt = def_ext;
    ofn.Flags       = OFN_OVERWRITEPROMPT;
    return GetSaveFileNameA(&ofn) != 0;
}

/* sticky so the user can actually read it */
static char g_export_status[512] = "";

static void export_report(const hook_report_t* report, bool as_json)
{
    char path[MAX_PATH];
    const char* filter = as_json
        ? "JSON report\0*.json\0All files\0*.*\0"
        : "CSV report\0*.csv\0All files\0*.*\0";
    const char* ext = as_json ? "json" : "csv";
    if (!save_file_dialog(filter, ext, path, MAX_PATH)) {
        snprintf(g_export_status, sizeof(g_export_status), "Export cancelled.");
        return;
    }
    bool ok = as_json ? engine_report_to_json(report, path) == 0
                      : engine_report_to_csv(report, path) == 0;
    snprintf(g_export_status, sizeof(g_export_status),
             ok ? "Report written to %s" : "Failed to write %s", path);
}

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
    if (report->truncated) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.6f, 0.2f, 1.0f));
        ImGui::TextWrapped("WARNING: hook buffer filled up - results may be incomplete.");
        ImGui::PopStyleColor();
    }
    if (ImGui::Button("Export JSON")) {
        export_report(report, true);
    }
    ImGui::SameLine();
    if (ImGui::Button("Export CSV")) {
        export_report(report, false);
    }
    if (g_export_status[0])
        ImGui::TextWrapped("%s", g_export_status);
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