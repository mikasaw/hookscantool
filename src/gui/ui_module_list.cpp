#include "ui_module_list.h"
#include "engine.h"
#include "module_scorer.h"
#include <imgui.h>
#include <cstdio>
#include <cstring>
#include <thread>
#include <atomic>
#include <mutex>
#include <exception>
#include <vector>
#include <chrono>
#include <algorithm>

/* --- State --- */
static module_report_t* g_recon = NULL;
static module_report_t* g_pending_recon_free = NULL;
static std::vector<bool> g_checked;          /* per-module checkbox state */
static int               g_filter = 0;       /* 0=All, 1=Suspicious Only, 2=Non-Microsoft */
static uint32_t          g_recon_pid = 0;    /* PID that current recon is for */
static float             g_recon_debounce = 0.0f;

/* Selective scan state */
static hook_report_t*    g_sel_report = NULL;
static hook_report_t*    g_sel_pending_free = NULL;
static std::atomic<bool> g_sel_scanning(false);
static std::mutex        g_sel_mutex;

/* Recon thread safety */
static std::mutex        g_recon_mutex;
static std::atomic<bool> g_recon_active(false);

/* Module table sort state */
enum mod_sort_col_t { MOD_SORT_NAME, MOD_SORT_BASE, MOD_SORT_SIZE, MOD_SORT_SCORE };
static mod_sort_col_t g_mod_sort_col = MOD_SORT_SCORE;
static bool           g_mod_sort_asc = false;

/* --- Helpers --- */

static ImVec4 score_color(uint8_t score)
{
    if (score <= 30) return ImVec4(0.4f, 0.8f, 0.4f, 1.0f);  /* green */
    if (score <= 60) return ImVec4(0.9f, 0.8f, 0.2f, 1.0f);  /* yellow */
    if (score <= 80) return ImVec4(0.9f, 0.5f, 0.1f, 1.0f);  /* orange */
    return ImVec4(0.78f, 0.24f, 0.24f, 1.0f);                  /* muted red */
}

static bool passes_filter(const scored_module_t* mod, int filter)
{
    if (filter == 0) return true;  /* All */
    if (filter == 1) return mod->suspicion_score >= 50;  /* Suspicious Only */
    /* Non-Microsoft: use dynamic trusted path check */
    if (filter == 2) {
        return !is_trusted_path(mod->info.path);
    }
    return true;
}

static void auto_check_visible(void)
{
    if (!g_recon) return;
    g_checked.resize(g_recon->module_count, false);
    for (int i = 0; i < g_recon->module_count; i++) {
        if (passes_filter(&g_recon->modules[i], g_filter)) {
            g_checked[i] = true;
        }
    }
}

static void clear_state(void)
{
    if (g_recon) {
        engine_free_module_report(g_recon);
        g_recon = NULL;
    }
    g_checked.clear();
    g_recon_pid = 0;
}

/* --- Public API --- */

void ui_module_list_cleanup(void)
{
    /* Wait for recon thread to finish */
    for (int i = 0; i < 500 && g_recon_active.load(); i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    /* Wait for scan thread to finish */
    for (int i = 0; i < 500 && g_sel_scanning.load(); i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    {
        std::lock_guard<std::mutex> lock(g_recon_mutex);
        clear_state();
        if (g_pending_recon_free) {
            engine_free_module_report(g_pending_recon_free);
            g_pending_recon_free = NULL;
        }
    }
    {
        std::lock_guard<std::mutex> lock(g_sel_mutex);
        if (g_sel_report) {
            engine_free_report(g_sel_report);
            g_sel_report = NULL;
        }
        if (g_sel_pending_free) {
            engine_free_report(g_sel_pending_free);
            g_sel_pending_free = NULL;
        }
    }
}

hook_report_t* ui_module_get_last_report(void)
{
    std::lock_guard<std::mutex> lock(g_sel_mutex);
    return g_sel_report;
}

uint32_t ui_module_list_render(uint32_t selected_pid, bool scanning)
{
    /* --- Recon trigger (debounced 200ms on PID change) --- */
    {
        std::lock_guard<std::mutex> lock(g_recon_mutex);
        if (selected_pid != g_recon_pid && selected_pid != 0) {
            g_recon_debounce = 0.2f;  /* 200ms debounce */
            g_recon_pid = selected_pid;
        }
    }

    if (selected_pid == 0) {
        /* No process selected */
        std::lock_guard<std::mutex> lock(g_recon_mutex);
        clear_state();
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "Select a process to view modules.");
        return selected_pid;
    }

    /* Debounce countdown (read/write under mutex) */
    bool should_start_recon = false;
    {
        std::lock_guard<std::mutex> lock(g_recon_mutex);
        if (g_recon_debounce > 0.0f) {
            g_recon_debounce -= ImGui::GetIO().DeltaTime;
            if (g_recon_debounce <= 0.0f) {
                g_recon_debounce = 0.0f;
                should_start_recon = true;
            }
        }
    }

    if (should_start_recon) {
        /* Only start recon if no scan is in flight (scan holds a recon ref) */
        if (!g_sel_scanning.load() && !g_recon_active.load()) {
            g_recon_active.store(true);
            uint32_t recon_pid = selected_pid;
            int cur_filter = g_filter;
            std::thread([recon_pid, cur_filter]() {
                try {
                    module_report_t* r = engine_recon_process(recon_pid);
                    std::vector<bool> new_checked;
                    if (r && r->module_count > 0) {
                        new_checked.resize(r->module_count, false);
                        for (int i = 0; i < r->module_count; i++) {
                            if (passes_filter(&r->modules[i], cur_filter)) {
                                new_checked[i] = true;
                            }
                        }
                    }
                    {
                        std::lock_guard<std::mutex> lock(g_recon_mutex);
                        g_pending_recon_free = g_recon;
                        g_recon = r;
                        g_checked = std::move(new_checked);
                    }
                } catch (...) {
                    /* Prevent exception from escaping detached thread */
                }
                g_recon_active.store(false);
            }).detach();
        }
        ImGui::Text("Loading modules...");
        return selected_pid;
    }

    /* Still debouncing */
    {
        std::lock_guard<std::mutex> lock(g_recon_mutex);
        if (g_recon_debounce > 0.0f) {
            ImGui::Text("Loading modules...");
            return selected_pid;
        }
    }

    /* Free deferred recon from previous run (safe: only on render thread) */
    {
        std::lock_guard<std::mutex> lock(g_recon_mutex);
        if (g_pending_recon_free) {
            engine_free_module_report(g_pending_recon_free);
            g_pending_recon_free = NULL;
        }
    }

    /* Snapshot recon pointer and checked state under mutex for this frame */
    module_report_t* recon = nullptr;
    std::vector<bool> checked_snap;
    {
        std::lock_guard<std::mutex> lock(g_recon_mutex);
        recon = g_recon;
        checked_snap = g_checked;
    }

    /* --- Error state --- */
    if (recon && recon->error_code != 0) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.3f, 0.3f, 1.0f));
        ImGui::Text("Error: %s", recon->error_msg);
        ImGui::PopStyleColor();
        return selected_pid;
    }

    /* --- Empty state --- */
    if (!recon || recon->module_count == 0) {
        ImGui::TextColored(ImVec4(0.6f, 0.6f, 0.6f, 1.0f), "No modules accessible.");
        return selected_pid;
    }

    /* --- Header: module count + recon time --- */
    ImGui::Text("Modules: %d | Recon: %llu ms",
                recon->module_count, (unsigned long long)recon->recon_time_ms);
    ImGui::Separator();

    /* --- Filter buttons --- */
    const char* filter_names[] = { "All", "Suspicious Only", "Non-Microsoft" };
    for (int i = 0; i < 3; i++) {
        if (i > 0) ImGui::SameLine();
        if (g_filter == i) {
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.3f, 0.5f, 0.7f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.4f, 0.6f, 0.8f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.2f, 0.4f, 0.6f, 1.0f));
        }
        if (ImGui::Button(filter_names[i])) {
            g_filter = i;
            auto_check_visible();
        }
        if (g_filter == i) {
            ImGui::PopStyleColor(3);
        }
    }

    ImGui::SameLine();
    if (ImGui::Button("Select All")) {
        checked_snap.assign(recon->module_count, true);
        std::lock_guard<std::mutex> lock(g_recon_mutex);
        g_checked = checked_snap;
    }
    ImGui::SameLine();
    if (ImGui::Button("Deselect All")) {
        checked_snap.assign(recon->module_count, false);
        std::lock_guard<std::mutex> lock(g_recon_mutex);
        g_checked = checked_snap;
    }

    /* --- Scan Selected button --- */
    int checked_count = 0;
    for (int i = 0; i < (int)checked_snap.size() && i < recon->module_count; i++) {
        if (checked_snap[i]) checked_count++;
    }

    bool can_scan = checked_count > 0 && !scanning && !g_sel_scanning.load() && !g_recon_active.load();
    if (!can_scan) ImGui::BeginDisabled();

    if (ImGui::Button("Scan Selected") && can_scan) {
        g_sel_scanning.store(true);

        /* Build index array of checked modules */
        std::vector<int> indices;
        for (int i = 0; i < (int)checked_snap.size() && i < recon->module_count; i++) {
            if (checked_snap[i]) indices.push_back(i);
        }

        uint32_t scan_pid = selected_pid;
        int count = (int)indices.size();
        int* idx_copy = (int*)malloc(count * sizeof(int));
        if (!idx_copy) {
            g_sel_scanning.store(false);
        } else {
            memcpy(idx_copy, indices.data(), count * sizeof(int));

            /* Snapshot recon pointer (safe: new recon is blocked while scan is in flight) */
            const module_report_t* recon_snap = recon;

            std::thread([scan_pid, recon_snap, idx_copy, count]() {
                try {
                    hook_report_t* report = engine_scan_modules(scan_pid, recon_snap, idx_copy, count);
                    {
                        std::lock_guard<std::mutex> lock(g_sel_mutex);
                        g_sel_pending_free = g_sel_report;
                        g_sel_report = report;
                    }
                } catch (const std::exception& e) {
                    hook_report_t* err_report = (hook_report_t*)calloc(1, sizeof(hook_report_t));
                    if (err_report) {
                        err_report->pid = scan_pid;
                        err_report->error_code = ENGINE_SCAN_FAILED;
                        snprintf(err_report->error_msg, sizeof(err_report->error_msg),
                                 "Scan exception: %s", e.what());
                        std::lock_guard<std::mutex> lock(g_sel_mutex);
                        if (g_sel_pending_free) engine_free_report(g_sel_pending_free);
                        g_sel_pending_free = g_sel_report;
                        g_sel_report = err_report;
                    }
                } catch (...) {
                    /* Prevent exception from escaping detached thread */
                }
                free(idx_copy);
                g_sel_scanning.store(false);
            }).detach();
        }
    }

    if (!can_scan) ImGui::EndDisabled();

    if (g_sel_scanning.load()) {
        ImGui::SameLine();
        ImGui::Text("Scanning...");
    }

    /* Free deferred selective scan report (safe: only on render thread) */
    {
        std::lock_guard<std::mutex> lock(g_sel_mutex);
        if (g_sel_pending_free) {
            engine_free_report(g_sel_pending_free);
            g_sel_pending_free = NULL;
        }
    }

    ImGui::Separator();

    /* --- Module table --- */
    ImGuiTableFlags flags = ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                            ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable |
                            ImGuiTableFlags_Sortable;

    if (ImGui::BeginTable("modules_table", 5, flags, ImVec2(0, 0))) {
        ImGui::TableSetupColumn("##check", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoSort, 24.0f);
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_DefaultSort, 160.0f);
        ImGui::TableSetupColumn("Base", ImGuiTableColumnFlags_WidthFixed, 90.0f);
        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 70.0f);
        ImGui::TableSetupColumn("Score", ImGuiTableColumnFlags_WidthFixed, 50.0f);
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();

        /* Respond to sort specs */
        if (ImGuiTableSortSpecs* specs = ImGui::TableGetSortSpecs()) {
            if (specs->SpecsDirty) {
                switch (specs->Specs->ColumnIndex) {
                    case 1: g_mod_sort_col = MOD_SORT_NAME; break;
                    case 2: g_mod_sort_col = MOD_SORT_BASE; break;
                    case 3: g_mod_sort_col = MOD_SORT_SIZE; break;
                    case 4: g_mod_sort_col = MOD_SORT_SCORE; break;
                    default: break;
                }
                g_mod_sort_asc = (specs->Specs->SortDirection == ImGuiSortDirection_Ascending);
                specs->SpecsDirty = false;
            }
        }

        /* Build sorted index array of visible modules */
        std::vector<int> vis_idx;
        for (int i = 0; i < recon->module_count; i++) {
            if (passes_filter(&recon->modules[i], g_filter))
                vis_idx.push_back(i);
        }

        mod_sort_col_t sort_col = g_mod_sort_col;
        bool sort_asc = g_mod_sort_asc;
        std::sort(vis_idx.begin(), vis_idx.end(), [sort_col, sort_asc, recon](int a, int b) {
            const scored_module_t* ma = &recon->modules[a];
            const scored_module_t* mb = &recon->modules[b];
            int r = 0;
            switch (sort_col) {
                case MOD_SORT_NAME:
                    r = _stricmp(ma->info.name, mb->info.name);
                    break;
                case MOD_SORT_BASE:
                    r = (ma->info.base_addr < mb->info.base_addr) ? -1 :
                        (ma->info.base_addr > mb->info.base_addr) ? 1 : 0;
                    break;
                case MOD_SORT_SIZE:
                    r = (ma->info.size < mb->info.size) ? -1 :
                        (ma->info.size > mb->info.size) ? 1 : 0;
                    break;
                case MOD_SORT_SCORE:
                    r = (ma->suspicion_score < mb->suspicion_score) ? -1 :
                        (ma->suspicion_score > mb->suspicion_score) ? 1 : 0;
                    break;
            }
            return sort_asc ? r < 0 : r > 0;
        });

        for (int vi = 0; vi < (int)vis_idx.size(); vi++) {
            int i = vis_idx[vi];
            const scored_module_t* mod = &recon->modules[i];

            ImGui::TableNextRow();

            /* Checkbox */
            if (ImGui::TableSetColumnIndex(0)) {
                bool checked = (i < (int)checked_snap.size()) ? checked_snap[i] : false;
                char cb_label[32];
                snprintf(cb_label, sizeof(cb_label), "##cb%d", i);
                if (ImGui::Checkbox(cb_label, &checked)) {
                    if (i < (int)checked_snap.size()) {
                        checked_snap[i] = checked;
                        std::lock_guard<std::mutex> lock(g_recon_mutex);
                        g_checked[i] = checked;
                    }
                }
            }

            /* Name (tooltip on this column — wider hover target) */
            if (ImGui::TableSetColumnIndex(1)) {
                ImGui::Text("%s", mod->info.name);
                if (ImGui::IsItemHovered()) {
                    ImGui::BeginTooltip();
                    ImGui::Text("Path: %s", mod->info.path);
                    ImGui::Text("Base: 0x%llX", (unsigned long long)mod->info.base_addr);
                    ImGui::Text("Size: %u bytes", mod->info.size);
                    ImGui::Text("WoW64: %s", mod->info.is_wow64 ? "Yes" : "No");
                    ImGui::Text("Score: %d", mod->suspicion_score);
                    ImGui::EndTooltip();
                }
            }

            /* Base address */
            if (ImGui::TableSetColumnIndex(2)) {
                ImGui::Text("0x%llX", (unsigned long long)mod->info.base_addr);
            }

            /* Size */
            if (ImGui::TableSetColumnIndex(3)) {
                ImGui::Text("%u KB", mod->info.size / 1024);
            }

            /* Suspicion score (colored badge with number) */
            if (ImGui::TableSetColumnIndex(4)) {
                ImVec4 col = score_color(mod->suspicion_score);
                ImGui::PushStyleColor(ImGuiCol_Text, col);
                ImGui::Text("%d", mod->suspicion_score);
                ImGui::PopStyleColor();
            }
        }

        ImGui::EndTable();
    }

    return selected_pid;
}

