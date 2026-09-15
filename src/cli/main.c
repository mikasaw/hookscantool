#include "engine.h"
#include "process_enum.h"
#include "module_scorer.h"
#include "args.h"
#include "version.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static const char* hook_type_str(hook_type_t type)
{
    switch (type) {
        case HOOK_IAT:    return "IAT";
        case HOOK_INLINE: return "INLINE";
        case HOOK_EAT:    return "EAT";
        default:          return "UNKNOWN";
    }
}

static void print_usage(const char* prog)
{
    printf("HookScanTool v%s - Windows Process Hook Scanner\n\n", HOOKSCAN_VERSION_STR);
    printf("Usage: %s <pid> [options]\n", prog);
    printf("       %s --deep [options]\n", prog);
    printf("Options:\n");
    printf("  --json <path>       Write JSON report to file\n");
    printf("  --csv <path>        Write report as CSV (one row per hook)\n");
    printf("  --sarif <path>      Write report as SARIF 2.1.0 (code scanning)\n");
    printf("  --restore <n>       Restore hook #n (0-indexed)\n");
    printf("  --list              List all processes and exit\n");
    printf("  --modules           List modules with suspicion scores (uses recon)\n");
    printf("  --scan-module <n>   Scan a specific module by index\n");
    printf("  --filter <s|a|m>    Filter modules: s=suspicious, a=all, m=non-microsoft (with --modules)\n");
    printf("  --watch             Watch <pid>: rescan at --interval, alert on new hooks\n");
    printf("  --interval <sec>    Watch interval in seconds (default 30, min 1)\n");
    printf("  --deep              Scan every accessible process (no <pid> needed)\n");
    printf("  --version           Show version information\n");
    printf("  --help              Show this help\n");
    printf("\nWatch exit codes: 0 = clean stop, 1 = new hooks seen, 2 = target lost\n");
}

static void print_version(void)
{
    printf("HookScanTool v%s\n", HOOKSCAN_VERSION_STR);
    printf("Windows Process Hook Scanner\n");
    printf("Engine: IAT / EAT / Inline hook detection\n");
    printf("Built: " __DATE__ " " __TIME__ "\n");
}

static void list_processes(void)
{
    int count = 0;
    process_info_t* procs = process_enum_all(&count);
    if (!procs) {
        printf("Failed to enumerate processes.\n");
        return;
    }

    printf("%-8s %-40s\n", "PID", "Name");
    printf("-------- ----------------------------------------\n");
    for (int i = 0; i < count; i++) {
        printf("%-8u %-40s\n", procs[i].pid, procs[i].name);
    }

    process_free_list(procs, count);
}

static void print_hook_report(const hook_report_t* report)
{
    printf("\nProcess: %s (PID %u)\n", report->process_name, report->pid);
    printf("Modules scanned: %d\n", report->modules_scanned);
    printf("Scan time: %llu ms\n", (unsigned long long)report->scan_time_ms);
    printf("Hooks found: %d\n", report->hook_count);
    if (report->truncated) {
        printf("WARNING: hook buffer filled up — results may be incomplete.\n");
    }
    printf("\n");

    if (report->hook_count == 0) {
        printf("No hooks detected.\n");
    } else {
        printf("%-4s %-20s %-30s %-8s %-18s %-18s %-10s\n",
               "#", "Module", "Function", "Type", "Original", "Current", "Restorable");
        printf("---- -------------------- ------------------------------ -------- ------------------ ------------------ ----------\n");

        for (int i = 0; i < report->hook_count; i++) {
            const hook_entry_t* h = &report->hooks[i];
            printf("%-4d %-20s %-30s %-8s 0x%016llx 0x%016llx %-10s\n",
                   i,
                   h->module_name,
                   h->function_name,
                   hook_type_str(h->type),
                   (unsigned long long)h->original_addr,
                   (unsigned long long)h->current_addr,
                   h->restorable ? "YES" : "NO");

            /* Print chain if available */
            for (int c = 0; c < h->chain_depth; c++) {
                const chain_step_t* cs = &h->chain[c];
                printf("  [%d] 0x%016llx: %s\n", c, (unsigned long long)cs->address, cs->disasm);
            }
        }
    }
}

static void list_modules(uint32_t pid, int filter)
{
    printf("Recon PID %u...\n", pid);
    module_report_t* recon = engine_recon_process(pid);
    if (!recon) {
        printf("Failed to recon process.\n");
        return;
    }

    if (recon->error_code != 0) {
        printf("Error: %s\n", recon->error_msg);
        engine_free_module_report(recon);
        return;
    }

    printf("\nProcess: %s (PID %u) | %s | Recon: %llu ms\n",
           recon->process_name, recon->pid,
           recon->is_64bit ? "64-bit" : "32-bit (WoW64)",
           (unsigned long long)recon->recon_time_ms);
    printf("\n");

    printf("%-4s %-24s %-12s %-8s %-5s  %s\n",
           "#", "Module", "Base", "Size", "Score", "Path");
    printf("---- ------------------------ ------------ -------- -----  --------------------------------\n");

    int shown = 0;
    for (int i = 0; i < recon->module_count; i++) {
        const scored_module_t* sm = &recon->modules[i];
        bool pass = true;
        if (filter == 1) pass = (sm->suspicion_score >= 50);
        else if (filter == 2) pass = !is_trusted_path(sm->info.path);
        if (!pass) continue;

        printf("%-4d %-24s 0x%08llX %-5u KB %-3d  %s\n",
               i,
               sm->info.name,
               (unsigned long long)sm->info.base_addr,
               sm->info.size / 1024,
               sm->suspicion_score,
               sm->info.path);
        shown++;
    }

    if (shown == 0) {
        printf("(no modules match the current filter)\n");
    } else {
        printf("\nTotal: %d modules shown (of %d total)\n", shown, recon->module_count);
    }

    engine_free_module_report(recon);
}

/* --- --watch: poll a process and report newly appearing hooks --- */

static volatile bool g_watch_stop = false;

static BOOL WINAPI watch_ctrl_handler(DWORD type)
{
    (void)type;
    g_watch_stop = true;
    return TRUE;
}

/* Identity of a hook for diffing between rounds */
typedef struct {
    char             module[64];
    char             function[128];
    hook_type_t      type;
    unsigned long long addr;
} hook_key_t;

static int build_hook_keys(const hook_report_t* r, hook_key_t** out)
{
    *out = NULL;
    if (!r || r->hook_count <= 0) return 0;
    hook_key_t* keys = (hook_key_t*)calloc((size_t)r->hook_count, sizeof(hook_key_t));
    if (!keys) return -1;
    for (int i = 0; i < r->hook_count; i++) {
        const hook_entry_t* h = &r->hooks[i];
        snprintf(keys[i].module, sizeof(keys[i].module), "%s", h->module_name);
        snprintf(keys[i].function, sizeof(keys[i].function), "%s", h->function_name);
        keys[i].type = h->type;
        keys[i].addr = (unsigned long long)h->current_addr;
    }
    *out = keys;
    return r->hook_count;
}

static bool hook_key_present(const hook_key_t* keys, int n, const hook_key_t* k)
{
    for (int i = 0; i < n; i++) {
        if (keys[i].type == k->type && keys[i].addr == k->addr &&
            strcmp(keys[i].module, k->module) == 0 &&
            strcmp(keys[i].function, k->function) == 0)
            return true;
    }
    return false;
}

static int watch_process(uint32_t pid, int interval_sec, const char* json_path)
{
    SetConsoleCtrlHandler(watch_ctrl_handler, TRUE);
    printf("Watching PID %u for new hooks (interval %ds). Press Ctrl+C to stop.\n",
           pid, interval_sec);

    hook_key_t* prev = NULL;
    int prev_count = 0;
    bool new_seen = false;
    bool json_warned = false;
    int round = 0;

    while (!g_watch_stop) {
        hook_report_t* r = engine_scan_process(pid);
        if (!r) {
            printf("\nScan failed (out of memory). Stopping watch.\n");
            free(prev);
            return 2;
        }
        if (r->error_code != 0) {
            printf("\nProcess %u no longer scannable: %s\nStopping watch.\n",
                   pid, r->error_msg);
            engine_free_report(r);
            free(prev);
            return 2;
        }

        hook_key_t* cur = NULL;
        int cur_count = build_hook_keys(r, &cur);
        if (cur_count < 0) {
            printf("\nOut of memory building hook list. Stopping watch.\n");
            engine_free_report(r);
            free(prev);
            return 2;
        }

        if (round == 0) {
            printf("\n=== Baseline (round 1): %d hooks ===\n", r->hook_count);
            print_hook_report(r);
        } else {
            int new_count = 0;
            for (int i = 0; i < cur_count; i++) {
                if (!hook_key_present(prev, prev_count, &cur[i])) {
                    if (new_count == 0)
                        printf("\n!!! NEW HOOKS DETECTED on PID %u !!!\n", pid);
                    const hook_entry_t* h = &r->hooks[i];
                    printf("  [%s] %s!%s at 0x%016llx\n",
                           hook_type_str(h->type), h->module_name,
                           h->function_name, (unsigned long long)h->current_addr);
                    for (int c = 0; c < h->chain_depth; c++) {
                        printf("      #%d 0x%016llx: %s\n", c,
                               (unsigned long long)h->chain[c].address,
                               h->chain[c].disasm);
                    }
                    new_count++;
                }
            }
            if (new_count > 0) {
                new_seen = true;
                printf("Total hooks now: %d (%d new)\n", r->hook_count, new_count);
            } else {
                printf("\r[%2d] %s: %d hooks (no change)   \n",
                       round, r->process_name, r->hook_count);
            }
        }

        free(prev);
        prev = cur;
        prev_count = cur_count;

        /* Keep the JSON file reflecting the latest scan while watching */
        if (json_path && engine_report_to_json(r, json_path) != 0) {
            if (!json_warned) {
                printf("Warning: failed to write JSON report to %s\n", json_path);
                json_warned = true;
            }
        }

        engine_free_report(r);
        round++;

        /* Sleep in 1s slices so Ctrl+C reacts quickly */
        for (int s = 0; s < interval_sec && !g_watch_stop; s++)
            Sleep(1000);
    }

    SetConsoleCtrlHandler(watch_ctrl_handler, FALSE);
    printf("\nWatch stopped. %s\n",
           new_seen ? "New hooks were detected during monitoring."
                    : "No new hooks detected.");
    free(prev);
    return new_seen ? 1 : 0;
}

/* --- --deep: scan every accessible process --- */

/* Write a report to every output file requested via --json/--csv/--sarif.
 * Sets *exit_code to 1 on the first write failure. */
static void write_report_outputs(const hook_report_t* report,
                                 const char* json_path, const char* csv_path,
                                 const char* sarif_path, int* exit_code)
{
    if (json_path) {
        if (engine_report_to_json(report, json_path) == 0) {
            printf("\nJSON report written to: %s\n", json_path);
        } else {
            printf("\nFailed to write JSON report to: %s\n", json_path);
            *exit_code = 1;
        }
    }
    if (csv_path) {
        if (engine_report_to_csv(report, csv_path) == 0) {
            printf("CSV report written to: %s\n", csv_path);
        } else {
            printf("Failed to write CSV report to: %s\n", csv_path);
            *exit_code = 1;
        }
    }
    if (sarif_path) {
        if (engine_report_to_sarif(report, sarif_path) == 0) {
            printf("SARIF report written to: %s\n", sarif_path);
        } else {
            printf("Failed to write SARIF report to: %s\n", sarif_path);
            *exit_code = 1;
        }
    }
}

static int deep_scan(const char* json_path, bool only_with_hooks)
{
    int proc_count = 0;
    process_info_t* procs = process_enum_all(&proc_count);
    if (!procs || proc_count == 0) {
        printf("Failed to enumerate processes.\n");
        free(procs);
        return 1;
    }

    printf("Deep scan: %d processes found. This can take a while.\n\n", proc_count);

    hook_report_t** reports = (hook_report_t**)calloc((size_t)proc_count, sizeof(hook_report_t*));
    if (!reports) {
        printf("Out of memory.\n");
        process_free_list(procs, proc_count);
        return 1;
    }

    int report_count = 0;
    int scanned = 0, skipped = 0, total_hooks = 0;

    for (int i = 0; i < proc_count; i++) {
        uint32_t pid = procs[i].pid;
        if (pid == 0) continue;  /* system idle */

        hook_report_t* r = engine_scan_process(pid);
        if (!r || r->error_code != 0) {
            skipped++;
            if (r) engine_free_report(r);
            continue;
        }

        scanned++;
        total_hooks += r->hook_count;
        reports[report_count++] = r;

        if (only_with_hooks && r->hook_count == 0) {
            printf("  [OK] %-8u %-30s (%d hooks)\n", pid, r->process_name, r->hook_count);
        } else {
            printf(">>> %-8u %-30s %d HOOK(S) <<<\n", pid, r->process_name, r->hook_count);
            print_hook_report(r);
        }
    }

    printf("\n==== Deep scan summary ====\n");
    printf("Processes scanned: %d\n", scanned);
    printf("Processes skipped (inaccessible/exitd): %d\n", skipped);
    printf("Total hooks found:   %d\n", total_hooks);

    int exit_code = 0;
    if (json_path) {
        if (engine_reports_to_json(reports, report_count, json_path) == 0) {
            printf("\nJSON report written to: %s\n", json_path);
        } else {
            printf("\nFailed to write JSON report to: %s\n", json_path);
            exit_code = 1;
        }
    }

    for (int i = 0; i < report_count; i++)
        engine_free_report(reports[i]);
    free(reports);
    process_free_list(procs, proc_count);
    return exit_code;
}

int main(int argc, char* argv[])
{
    /* Process/module names arrive as UTF-8 — match the console to them */
    SetConsoleOutputCP(CP_UTF8);

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "--help") == 0) {
        print_usage(argv[0]);
        return 0;
    }

    if (strcmp(argv[1], "--version") == 0) {
        print_version();
        return 0;
    }

    if (strcmp(argv[1], "--list") == 0) {
        list_processes();
        return 0;
    }

    const char* json_path = NULL;
    const char* csv_path = NULL;
    const char* sarif_path = NULL;
    int restore_idx = -1;
    int scan_module_idx = -1;
    bool show_modules = false;
    int module_filter = 0; /* 0=all, 1=suspicious, 2=non-microsoft */
    bool watch_mode = false;
    bool deep_mode = false;
    int interval_sec = 30;
    uint32_t pid = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--version") == 0) {
            print_version();
            return 0;
        } else if (strcmp(argv[i], "--list") == 0) {
            list_processes();
            return 0;
        } else if (strcmp(argv[i], "--modules") == 0) {
            show_modules = true;
        } else if (strcmp(argv[i], "--watch") == 0) {
            watch_mode = true;
        } else if (strcmp(argv[i], "--deep") == 0) {
            deep_mode = true;
        } else if (strcmp(argv[i], "--interval") == 0) {
            if (i + 1 >= argc) {
                printf("Missing value for --interval\n");
                return 1;
            }
            if (!parse_index(argv[++i], &interval_sec) || interval_sec == 0 || interval_sec > 86400) {
                printf("Invalid interval: %s (seconds, 1-86400)\n", argv[i]);
                return 1;
            }
        } else if (strcmp(argv[i], "--filter") == 0) {
            if (i + 1 >= argc) {
                printf("Missing value for --filter\n");
                return 1;
            }
            i++;
            if (strcmp(argv[i], "s") == 0) module_filter = 1;
            else if (strcmp(argv[i], "a") == 0) module_filter = 0;
            else if (strcmp(argv[i], "m") == 0) module_filter = 2;
            else {
                printf("Invalid filter: %s (use: s=suspicious, a=all, m=non-microsoft)\n", argv[i]);
                return 1;
            }
            show_modules = true;  /* --filter implies --modules */
        } else if (strcmp(argv[i], "--scan-module") == 0) {
            if (i + 1 >= argc) {
                printf("Missing value for --scan-module\n");
                return 1;
            }
            if (!parse_index(argv[++i], &scan_module_idx)) {
                printf("Invalid module index: %s\n", argv[i]);
                return 1;
            }
        } else if (strcmp(argv[i], "--json") == 0) {
            if (i + 1 >= argc) {
                printf("Missing value for --json\n");
                return 1;
            }
            json_path = argv[++i];
        } else if (strcmp(argv[i], "--csv") == 0) {
            if (i + 1 >= argc) {
                printf("Missing value for --csv\n");
                return 1;
            }
            csv_path = argv[++i];
        } else if (strcmp(argv[i], "--sarif") == 0) {
            if (i + 1 >= argc) {
                printf("Missing value for --sarif\n");
                return 1;
            }
            sarif_path = argv[++i];
        } else if (strcmp(argv[i], "--restore") == 0) {
            if (i + 1 >= argc) {
                printf("Missing value for --restore\n");
                return 1;
            }
            if (!parse_index(argv[++i], &restore_idx)) {
                printf("Invalid restore index: %s\n", argv[i]);
                return 1;
            }
        } else if (argv[i][0] == '-') {
            /* Distinguish mistyped negative numbers from unknown options */
            const char* rest = argv[i] + 1;
            bool looks_numeric = *rest != '\0';
            for (const char* c = rest; *c; c++) {
                if (!isdigit((unsigned char)*c)) { looks_numeric = false; break; }
            }
            if (looks_numeric)
                printf("Invalid PID: %s (PID must be a positive number)\n", argv[i]);
            else
                printf("Unknown option: %s\n", argv[i]);
            return 1;
        } else {
            uint32_t p = 0;
            if (!parse_pid(argv[i], &p)) {
                printf("Invalid PID: %s\n", argv[i]);
                return 1;
            }
            if (pid != 0) {
                printf("Multiple PIDs specified. Only one PID is allowed.\n");
                return 1;
            }
            pid = p;
        }
    }

    /* Handle --deep: scan all processes, no PID required */
    if (deep_mode) {
        if (pid != 0) {
            printf("--deep scans every process; do not specify a PID with it.\n");
            return 1;
        }
        if (watch_mode || scan_module_idx >= 0 || show_modules || restore_idx >= 0) {
            printf("--deep cannot be combined with --watch/--modules/--scan-module/--restore.\n");
            return 1;
        }
        if (csv_path || sarif_path) {
            printf("--deep multi-process output is JSON only (--json); --csv/--sarif apply to single-process scans.\n");
            return 1;
        }
        /* --filter s with --deep: only list processes that have hooks */
        return deep_scan(json_path, module_filter == 1);
    }

    if (pid == 0) {
        print_usage(argv[0]);
        return 1;
    }

    /* Handle --watch: rescan loop */
    if (watch_mode) {
        if (scan_module_idx >= 0 || show_modules || restore_idx >= 0) {
            printf("--watch cannot be combined with --modules/--scan-module/--restore.\n");
            return 1;
        }
        return watch_process(pid, interval_sec, json_path);
    }

    /* Handle --modules (recon only, no scan) */
    if (show_modules) {
        list_modules(pid, module_filter);
        return 0;
    }

    /* Handle --scan-module: recon first, then scan specific module */
    if (scan_module_idx >= 0) {
        printf("Recon PID %u for selective scan...\n", pid);
        module_report_t* recon = engine_recon_process(pid);
        if (!recon) {
            printf("Failed to recon process.\n");
            return 1;
        }

        if (recon->error_code != 0) {
            printf("Error: %s\n", recon->error_msg);
            engine_free_module_report(recon);
            return 1;
        }

        if (scan_module_idx >= recon->module_count) {
            printf("Module index %d out of range. Module count: %d\n",
                   scan_module_idx, recon->module_count);
            printf("Use --modules to list available modules.\n");
            engine_free_module_report(recon);
            return 1;
        }

        const scored_module_t* sm = &recon->modules[scan_module_idx];
        printf("Scanning module: %s (score: %d)\n", sm->info.name, sm->suspicion_score);

        int idx = scan_module_idx;
        hook_report_t* report = engine_scan_modules(pid, recon, &idx, 1);
        engine_free_module_report(recon);

        if (!report) {
            printf("Failed to scan module.\n");
            return 1;
        }
        if (report->error_code != 0) {
            printf("Error: %s\n", report->error_msg);
            engine_free_report(report);
            return 1;
        }
        print_hook_report(report);
        int exit_code = 0;
        write_report_outputs(report, json_path, csv_path, sarif_path, &exit_code);
        engine_free_report(report);
        return exit_code;
    }

    printf("Scanning PID %u...\n", pid);

    hook_report_t* report = engine_scan_process(pid);
    if (!report) {
        printf("Failed to scan process.\n");
        return 1;
    }

    if (report->error_code != 0) {
        printf("Error: %s\n", report->error_msg);
        engine_free_report(report);
        return 1;
    }

    print_hook_report(report);

    int exit_code = 0;

    /* Restore a hook if requested */
    if (restore_idx >= 0) {
        if (restore_idx >= report->hook_count) {
            printf("\nError: hook index %d out of range (0..%d). Nothing was restored.\n",
                   restore_idx, report->hook_count - 1);
            exit_code = 1;
        } else {
            hook_entry_t* h = &report->hooks[restore_idx];
            printf("\nRestore hook #%d (%s!%s) in PID %u? [y/N] ",
                   restore_idx, h->module_name, h->function_name, pid);
            fflush(stdout);
            char answer[8] = {0};
            if (fgets(answer, sizeof(answer), stdin) && (answer[0] == 'y' || answer[0] == 'Y')) {
                if (engine_restore_hook(pid, h)) {
                    printf("Hook restored successfully.\n");
                } else {
                    printf("Failed to restore hook.\n");
                    exit_code = 1;
                }
            } else {
                printf("Aborted.\n");
            }
        }
    }

    /* Write report files if requested */
    write_report_outputs(report, json_path, csv_path, sarif_path, &exit_code);

    engine_free_report(report);
    return exit_code;
}