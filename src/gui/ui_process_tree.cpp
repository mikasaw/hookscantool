#include "ui_process_tree.h"
#include "process.h"
#include "engine.h"
#include <imgui.h>
#include <cstdio>
#include <cstring>
#include <thread>
#include <atomic>
#include <mutex>
#include <exception>

#include <algorithm>
#include <vector>

static process_info_t* g_procs = NULL;
static int             g_proc_count = 0;
static uint32_t        g_selected_pid = 0;
static hook_report_t*  g_last_report = NULL;
static hook_report_t*  g_pending_free = NULL;
static std::atomic<bool> g_scanning(false);
static std::mutex g_report_mutex;
static std::mutex g_procs_mutex;

enum sort_col_t { SORT_PID, SORT_NAME };
static sort_col_t g_sort_col = SORT_PID;
static bool       g_sort_asc = true;
static sort_col_t g_tiebreak_col = SORT_NAME;
static bool       g_tiebreak_asc = true;

void ui_process_tree_refresh(void)
{
    std::lock_guard<std::mutex> lock(g_procs_mutex);
    if (g_procs) {
        process_free_list(g_procs, g_proc_count);
        g_procs = NULL;
        g_proc_count = 0;
    }
    g_procs = process_enum_all(&g_proc_count);

    /* Validate selected PID still exists after refresh */
    if (g_selected_pid != 0 && g_procs) {
        bool found = false;
        for (int i = 0; i < g_proc_count; i++) {
            if (g_procs[i].pid == g_selected_pid) { found = true; break; }
        }
        if (!found) g_selected_pid = 0;
    }
}

void ui_process_tree_cleanup(void)
{
    /* Wait for any in-flight scan to finish (max 5 seconds) */
    for (int i = 0; i < 500 && g_scanning.load(); i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    {
        std::lock_guard<std::mutex> lock(g_procs_mutex);
        if (g_procs) {
            process_free_list(g_procs, g_proc_count);
            g_procs = NULL;
        }
    }
    {
        std::lock_guard<std::mutex> lock(g_report_mutex);
        if (g_last_report) {
            engine_free_report(g_last_report);
            g_last_report = NULL;
        }
        if (g_pending_free) {
            engine_free_report(g_pending_free);
            g_pending_free = NULL;
        }
    }
}

uint32_t ui_process_tree_render(void)
{
    ImGui::Begin("Processes");

    if (ImGui::Button("Refresh") || g_procs == NULL) {
        ui_process_tree_refresh();
    }

    ImGui::SameLine();

    /* Scan button - more prominent when a process is selected */
    bool can_scan = g_selected_pid != 0 && !g_scanning.load();
    if (g_selected_pid != 0) {
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.2f, 0.6f, 0.2f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.3f, 0.8f, 0.3f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.1f, 0.5f, 0.1f, 1.0f));
    }

    if (!can_scan) {
        ImGui::BeginDisabled();
    }

    if (ImGui::Button("Scan Selected") && can_scan) {
        g_scanning.store(true);
        uint32_t scan_pid = g_selected_pid;
        std::thread([scan_pid]() {
            try {
                hook_report_t* report = engine_scan_process(scan_pid);
                {
                    std::lock_guard<std::mutex> lock(g_report_mutex);
                    if (g_pending_free) {
                        engine_free_report(g_pending_free);
                    }
                    g_pending_free = g_last_report;
                    g_last_report = report;
                }
            } catch (const std::exception& e) {
                hook_report_t* err_report = (hook_report_t*)calloc(1, sizeof(hook_report_t));
                if (err_report) {
                    err_report->pid = scan_pid;
                    err_report->error_code = ENGINE_SCAN_FAILED;
                    snprintf(err_report->error_msg, sizeof(err_report->error_msg),
                             "Scan exception: %s", e.what());
                    std::lock_guard<std::mutex> lock(g_report_mutex);
                    if (g_pending_free) engine_free_report(g_pending_free);
                    g_pending_free = g_last_report;
                    g_last_report = err_report;
                }
            } catch (...) {
                /* Prevent exception from escaping detached thread (std::terminate) */
            }
            g_scanning.store(false);
        }).detach();
    }

    if (!can_scan) {
        ImGui::EndDisabled();
    }

    if (g_selected_pid != 0) {
        ImGui::PopStyleColor(3);
    }

    /* Show scanning indicator */
    if (g_scanning.load()) {
        ImGui::SameLine();
        ImGui::Text("Scanning...");
    }

    /* Show scan result summary (safe: read pointer under mutex, hold for frame) */
    hook_report_t* report = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_report_mutex);
        report = g_last_report;
    }

    if (report && !g_scanning.load()) {
        ImGui::SameLine();
        if (report->error_code != 0) {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.3f, 0.3f, 1.0f));
            ImGui::Text("Error!");
            ImGui::PopStyleColor();
        } else if (report->hook_count > 0) {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.5f, 0.0f, 1.0f));
            ImGui::Text("Hooks: %d", report->hook_count);
            ImGui::PopStyleColor();
        } else {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.4f, 1.0f, 0.4f, 1.0f));
            ImGui::Text("Clean");
            ImGui::PopStyleColor();
        }
    }

    ImGui::Separator();

    /* Show which PID is selected */
    if (g_selected_pid != 0) {
        ImGui::Text("Selected: PID %u", g_selected_pid);
        ImGui::Separator();
    }

    if (g_procs) {
        /* Build sorted index array */
        std::vector<int> idx(g_proc_count);
        for (int i = 0; i < g_proc_count; i++) idx[i] = i;

        ImGuiTableFlags flags = ImGuiTableFlags_Sortable | ImGuiTableFlags_SortMulti |
                                 ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersOuterH |
                                 ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit;
        if (ImGui::BeginTable("proc_table", 2, flags, ImVec2(0, 0))) {
            ImGui::TableSetupColumn("PID",   ImGuiTableColumnFlags_DefaultSort | ImGuiTableColumnFlags_WidthFixed, 60.0f);
            ImGui::TableSetupColumn("Name",  ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableHeadersRow();

            /* Respond to user clicking sort arrows */
            if (ImGuiTableSortSpecs* specs = ImGui::TableGetSortSpecs()) {
                if (specs->SpecsDirty) {
                    /* Use the primary sort column; if multi-column, use
                     * secondary as tiebreaker */
                    g_sort_col = (specs->Specs->ColumnIndex == 0) ? SORT_PID : SORT_NAME;
                    g_sort_asc = (specs->Specs->SortDirection == ImGuiSortDirection_Ascending);
                    if (specs->SpecsCount > 1) {
                        g_tiebreak_col = (specs->Specs[1].ColumnIndex == 0) ? SORT_PID : SORT_NAME;
                        g_tiebreak_asc = (specs->Specs[1].SortDirection == ImGuiSortDirection_Ascending);
                    } else {
                        g_tiebreak_col = (g_sort_col == SORT_PID) ? SORT_NAME : SORT_PID;
                        g_tiebreak_asc = true;
                    }
                    specs->SpecsDirty = false;
                }
            }

            /* Sort with captured parameters (not mutable globals during sort) */
            sort_col_t sort_col = g_sort_col;
            bool sort_asc = g_sort_asc;
            sort_col_t tiebreak_col = g_tiebreak_col;
            bool tiebreak_asc = g_tiebreak_asc;
            std::sort(idx.begin(), idx.end(), [sort_col, sort_asc, tiebreak_col, tiebreak_asc](int a, int b) {
                int r = 0;
                switch (sort_col) {
                    case SORT_PID:  r = (g_procs[a].pid < g_procs[b].pid) ? -1 : (g_procs[a].pid > g_procs[b].pid) ? 1 : 0; break;
                    case SORT_NAME: r = strcmp(g_procs[a].name, g_procs[b].name); break;
                }
                if (r != 0) return sort_asc ? r < 0 : r > 0;
                /* Tiebreak on secondary column */
                switch (tiebreak_col) {
                    case SORT_PID:  r = (g_procs[a].pid < g_procs[b].pid) ? -1 : (g_procs[a].pid > g_procs[b].pid) ? 1 : 0; break;
                    case SORT_NAME: r = strcmp(g_procs[a].name, g_procs[b].name); break;
                }
                return tiebreak_asc ? r < 0 : r > 0;
            });

            for (int si = 0; si < g_proc_count; si++) {
                int i = idx[si];
                bool is_selected = (g_procs[i].pid == g_selected_pid);
                bool has_hooks = false;

                if (report && report->pid == g_procs[i].pid && report->hook_count > 0) {
                    has_hooks = true;
                }

                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                if (has_hooks) ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.3f, 0.3f, 1.0f));
                char pid_label[32];
                snprintf(pid_label, sizeof(pid_label), "%u", g_procs[i].pid);
                if (ImGui::Selectable(pid_label, is_selected, ImGuiSelectableFlags_SpanAllColumns)) {
                    g_selected_pid = g_procs[i].pid;
                }
                if (has_hooks) ImGui::PopStyleColor();

                ImGui::TableSetColumnIndex(1);
                ImGui::Text("%s%s", g_procs[i].name, has_hooks ? " **HOOKED**" : "");
            }
            ImGui::EndTable();
        }
    }

    ImGui::End();
    return g_selected_pid;
}

hook_report_t* ui_get_last_report(void) {
    std::lock_guard<std::mutex> lock(g_report_mutex);
    return g_last_report;
}

void ui_set_last_report(hook_report_t* r) {
    std::lock_guard<std::mutex> lock(g_report_mutex);
    g_last_report = r;
}
