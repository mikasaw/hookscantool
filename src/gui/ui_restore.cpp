#include "ui_restore.h"
#include <imgui.h>
#include <atomic>
#include <thread>
#include <chrono>
#include <cstdio>

/* Restore runs on a background thread (it suspends threads of the target
 * and can take a moment) — the UI polls the atomics and applies the
 * result to the live report on the render thread only. */
static std::atomic<bool> g_restore_running(false);
static std::atomic<bool> g_restore_success(false);
static std::atomic<bool> g_restore_done(false);

static hook_entry_t      g_restore_entry;        /* worker's private copy */
static uint32_t          g_restore_pid = 0;
static const hook_report_t* g_restore_src = NULL; /* report the entry came from */
static int               g_restore_idx = -1;

static bool g_confirm_open = false;
static bool g_show_result = false;
static bool g_restore_result = false;

void ui_restore_render(uint32_t pid, hook_report_t* report, int selected_hook)
{
    if (!report || selected_hook < 0 || selected_hook >= report->hook_count)
        return;

    const hook_entry_t* h = &report->hooks[selected_hook];

    ImGui::Begin("Restore");

    /* Apply a finished background restore to the live report */
    if (g_restore_done.exchange(false)) {
        if (report == g_restore_src &&
            g_restore_idx >= 0 && g_restore_idx < report->hook_count) {
            if (g_restore_success.load())
                report->hooks[g_restore_idx].restorable = false;
        }
        g_restore_result = g_restore_success.load();
        g_show_result = true;
    }

    if (!h->restorable) {
        ImGui::TextColored(ImVec4(0.7f, 0.7f, 0.7f, 1.0f),
                          "This hook cannot be restored (packed DLL or no on-disk reference).");
        ImGui::End();
        return;
    }

    ImGui::Text("Restore: %s!%s", h->module_name, h->function_name);
    ImGui::Text("This will overwrite the hooked bytes with original bytes from the on-disk DLL.");
    ImGui::Separator();

    if (g_restore_running.load()) {
        ImGui::Text("Restoring... (suspending threads and writing)");
        if (ImGui::Button("Restore Hook")) { /* disabled while running */ }
        ImGui::End();
        return;
    }

    if (ImGui::Button("Restore Hook")) {
        g_confirm_open = true;
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
                /* Snapshot on the UI thread; worker writes only its copy */
                g_restore_entry = *h;
                g_restore_pid = pid;
                g_restore_src = report;
                g_restore_idx = selected_hook;
                g_restore_done.store(false);
                g_restore_running.store(true);
                std::thread([]() {
                    bool ok = engine_restore_hook(g_restore_pid, &g_restore_entry);
                    g_restore_success.store(ok);
                    g_restore_done.store(true);
                    g_restore_running.store(false);
                }).detach();
                g_confirm_open = false;
            }
            ImGui::SameLine();
            if (ImGui::Button("Cancel")) {
                g_confirm_open = false;
            }
            ImGui::EndPopup();
        }
    }

    /* Result popup (shown once the background restore finishes) */
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
