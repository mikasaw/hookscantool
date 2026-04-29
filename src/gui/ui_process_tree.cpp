#include "ui_process_tree.h"
#include "process.h"
#include "engine.h"
#include <imgui.h>
#include <cstdio>
#include <cstring>
#include <thread>
#include <atomic>
#include <mutex>

static process_info_t* g_procs = NULL;
static int             g_proc_count = 0;
static uint32_t        g_selected_pid = 0;
static hook_report_t*  g_last_report = NULL;
static hook_report_t*  g_pending_free = NULL;
static std::atomic<bool> g_scanning(false);
static std::mutex g_report_mutex;

void ui_process_tree_refresh(void)
{
    if (g_procs) {
        process_free_list(g_procs, g_proc_count);
        g_procs = NULL;
        g_proc_count = 0;
    }
    g_procs = process_enum_all(&g_proc_count);
}

void ui_process_tree_cleanup(void)
{
    /* Wait for any in-flight scan to finish */
    while (g_scanning.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (g_procs) {
        process_free_list(g_procs, g_proc_count);
        g_procs = NULL;
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
            hook_report_t* report = engine_scan_process(scan_pid);
            {
                std::lock_guard<std::mutex> lock(g_report_mutex);
                /* Don't free the old report here — the render thread may still
                 * be using it. Stash it for deferred free on next frame. */
                if (g_pending_free) {
                    engine_free_report(g_pending_free);
                }
                g_pending_free = g_last_report;
                g_last_report = report;
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
        for (int i = 0; i < g_proc_count; i++) {
            bool is_selected = (g_procs[i].pid == g_selected_pid);
            bool has_hooks = false;

            if (report && report->pid == g_procs[i].pid && report->hook_count > 0) {
                has_hooks = true;
            }

            char label[128];
            snprintf(label, sizeof(label), "%s [%u]%s", g_procs[i].name, g_procs[i].pid,
                      has_hooks ? " **HOOKED**" : "");

            if (has_hooks) {
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.3f, 0.3f, 1.0f));
            }

            if (ImGui::Selectable(label, is_selected)) {
                g_selected_pid = g_procs[i].pid;
            }

            if (has_hooks) {
                ImGui::PopStyleColor();
            }
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
