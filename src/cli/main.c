#include "engine.h"
#include "process_enum.h"
#include "module_scorer.h"
#include "args.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define HOOKSCAN_VERSION "1.0.0"

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
    printf("HookScanTool v%s - Windows Process Hook Scanner\n\n", HOOKSCAN_VERSION);
    printf("Usage: %s <pid> [options]\n", prog);
    printf("Options:\n");
    printf("  --json <path>       Write JSON report to file\n");
    printf("  --restore <n>       Restore hook #n (0-indexed)\n");
    printf("  --list              List all processes and exit\n");
    printf("  --modules           List modules with suspicion scores (uses recon)\n");
    printf("  --scan-module <n>   Scan a specific module by index\n");
    printf("  --filter <s|a|m>    Filter modules: s=suspicious, a=all, m=non-microsoft (with --modules)\n");
    printf("  --version           Show version information\n");
    printf("  --help              Show this help\n");
}

static void print_version(void)
{
    printf("HookScanTool v%s\n", HOOKSCAN_VERSION);
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
    printf("Hooks found: %d\n\n", report->hook_count);

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
    int restore_idx = -1;
    int scan_module_idx = -1;
    bool show_modules = false;
    int module_filter = 0; /* 0=all, 1=suspicious, 2=non-microsoft */
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

    if (pid == 0) {
        print_usage(argv[0]);
        return 1;
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
        if (json_path) {
            if (engine_report_to_json(report, json_path) == 0) {
                printf("\nJSON report written to: %s\n", json_path);
            } else {
                printf("\nFailed to write JSON report to: %s\n", json_path);
                exit_code = 1;
            }
        }
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

    /* Write JSON report if requested */
    if (json_path) {
        if (engine_report_to_json(report, json_path) == 0) {
            printf("\nJSON report written to: %s\n", json_path);
        } else {
            printf("\nFailed to write JSON report to: %s\n", json_path);
            exit_code = 1;
        }
    }

    engine_free_report(report);
    return exit_code;
}