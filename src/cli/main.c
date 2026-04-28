#include "engine.h"
#include "process.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
    printf("Usage: %s <pid> [options]\n", prog);
    printf("Options:\n");
    printf("  --json <path>   Write JSON report to file\n");
    printf("  --restore <n>   Restore hook #n (0-indexed)\n");
    printf("  --list          List all processes and exit\n");
    printf("  --help          Show this help\n");
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

int main(int argc, char* argv[])
{
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "--help") == 0) {
        print_usage(argv[0]);
        return 0;
    }

    if (strcmp(argv[1], "--list") == 0) {
        list_processes();
        return 0;
    }

    uint32_t pid = (uint32_t)atoi(argv[1]);
    if (pid == 0) {
        printf("Invalid PID: %s\n", argv[1]);
        return 1;
    }

    const char* json_path = NULL;
    int restore_idx = -1;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--json") == 0 && i + 1 < argc) {
            json_path = argv[++i];
        } else if (strcmp(argv[i], "--restore") == 0 && i + 1 < argc) {
            restore_idx = atoi(argv[++i]);
        }
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

    /* Restore a hook if requested */
    if (restore_idx >= 0 && restore_idx < report->hook_count) {
        hook_entry_t* h = &report->hooks[restore_idx];
        printf("\nRestoring hook #%d (%s!%s)...\n", restore_idx, h->module_name, h->function_name);
        if (engine_restore_hook(pid, h)) {
            printf("Hook restored successfully.\n");
        } else {
            printf("Failed to restore hook.\n");
        }
    }

    /* Write JSON report if requested */
    if (json_path) {
        if (engine_report_to_json(report, json_path) == 0) {
            printf("\nJSON report written to: %s\n", json_path);
        } else {
            printf("\nFailed to write JSON report.\n");
        }
    }

    engine_free_report(report);
    return 0;
}