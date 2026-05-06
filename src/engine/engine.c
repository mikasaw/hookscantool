#include "engine.h"
#include "process.h"
#include "iat_scanner.h"
#include "eat_scanner.h"
#include "inline_scanner.h"
#include "chain_tracer.h"
#include "restore.h"
#include "wow64.h"
#include "module_scorer.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define INITIAL_HOOK_CAP 256

hook_report_t* engine_scan_process(uint32_t pid)
{
    hook_report_t* report = (hook_report_t*)calloc(1, sizeof(hook_report_t));
    if (!report) return NULL;

    report->pid = pid;
    LARGE_INTEGER freq, t0, t1;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);

    /* Open target process */
    HANDLE process = OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        FALSE, pid);

    if (!process) {
        DWORD err = GetLastError();
        report->error_code = ENGINE_ACCESS_DENIED;
        snprintf(report->error_msg, sizeof(report->error_msg),
                 "OpenProcess failed (error %lu). Run as Administrator.", err);
        QueryPerformanceCounter(&t1);
        report->scan_time_ms = (uint64_t)((t1.QuadPart - t0.QuadPart) * 1000 / freq.QuadPart);
        return report;
    }

    /* Get process info with modules */
    process_info_t pinfo;
    memset(&pinfo, 0, sizeof(pinfo));

    bool is_wow64 = wow64_is_process(process);

    int mod_result;
    if (is_wow64) {
        mod_result = wow64_enum_modules(pid, &pinfo);
        pinfo.pid = pid;
    } else {
        mod_result = process_get_info(pid, &pinfo);
    }

    if (mod_result != 0) {
        report->error_code = ENGINE_PROCESS_NOT_FOUND;
        snprintf(report->error_msg, sizeof(report->error_msg),
                 "Cannot enumerate modules for PID %u", pid);
        CloseHandle(process);
        QueryPerformanceCounter(&t1);
        report->scan_time_ms = (uint64_t)((t1.QuadPart - t0.QuadPart) * 1000 / freq.QuadPart);
        return report;
    }

    strncpy(report->process_name, pinfo.name, sizeof(report->process_name) - 1);

    /* Allocate hooks array */
    int hook_cap = INITIAL_HOOK_CAP;
    report->hooks = (hook_entry_t*)calloc(hook_cap, sizeof(hook_entry_t));
    if (!report->hooks) {
        report->error_code = ENGINE_NO_MEMORY;
        CloseHandle(process);
        process_free_modules(&pinfo);
        QueryPerformanceCounter(&t1);
        report->scan_time_ms = (uint64_t)((t1.QuadPart - t0.QuadPart) * 1000 / freq.QuadPart);
        return report;
    }

    /* Scan each module */
    for (int m = 0; m < pinfo.module_count; m++) {
        const module_info_t* mod = &pinfo.modules[m];
        report->modules_scanned++;

        /* Grow hooks array if needed */
        if (report->hook_count + 32 >= hook_cap) {
            if (hook_cap > INT_MAX / 2) break;
            int new_cap = hook_cap * 2;
            size_t alloc_size = (size_t)new_cap * sizeof(hook_entry_t);
            if (alloc_size / sizeof(hook_entry_t) != (size_t)new_cap) break;
            hook_entry_t* new_hooks = (hook_entry_t*)realloc(report->hooks, alloc_size);
            if (!new_hooks) break;
            hook_cap = new_cap;
            report->hooks = new_hooks;
            memset(report->hooks + report->hook_count, 0,
                   (hook_cap - report->hook_count) * sizeof(hook_entry_t));
        }

        int room = hook_cap - report->hook_count;

        /* IAT scan */
        int n = iat_scan_module(process, pid, mod, &pinfo,
                                report->hooks + report->hook_count, room);
        if (n > 0) report->hook_count += n;
        room = hook_cap - report->hook_count;

        /* EAT scan */
        if (room > 0) {
            n = eat_scan_module(process, mod,
                                report->hooks + report->hook_count, room);
            if (n > 0) report->hook_count += n;
            room = hook_cap - report->hook_count;
        }

        /* Inline scan */
        if (room > 0) {
            n = inline_scan_module(process, mod,
                                   report->hooks + report->hook_count, room);
            if (n > 0) report->hook_count += n;
        }
    }

    /* Trace hook chains for inline hooks */
    bool is_64bit = !is_wow64;
    for (int i = 0; i < report->hook_count; i++) {
        if (report->hooks[i].type == HOOK_INLINE && report->hooks[i].chain_depth == 0) {
            chain_step_t chain[MAX_CHAIN_DEPTH];
            int chain_len = 0;
            if (chain_trace(process, report->hooks[i].current_addr, is_64bit,
                           chain, &chain_len) == 0 && chain_len > 0) {
                report->hooks[i].chain = (chain_step_t*)calloc(chain_len, sizeof(chain_step_t));
                if (report->hooks[i].chain) {
                    memcpy(report->hooks[i].chain, chain, chain_len * sizeof(chain_step_t));
                    report->hooks[i].chain_depth = chain_len;
                }
            }
        }
    }

    QueryPerformanceCounter(&t1);
    report->scan_time_ms = (uint64_t)((t1.QuadPart - t0.QuadPart) * 1000 / freq.QuadPart);

    CloseHandle(process);
    process_free_modules(&pinfo);
    return report;
}

int engine_scan_module(uint32_t pid, const module_info_t* mod,
                       hook_entry_t* hooks, int hook_cap)
{
    HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!process) return -1;

    process_info_t pinfo;
    memset(&pinfo, 0, sizeof(pinfo));

    bool is_wow64 = wow64_is_process(process);

    int mod_result;
    if (is_wow64) {
        mod_result = wow64_enum_modules(pid, &pinfo);
        pinfo.pid = pid;
    } else {
        mod_result = process_get_info(pid, &pinfo);
    }

    if (mod_result != 0) {
        CloseHandle(process);
        return -1;
    }

    int total = 0;

    int n = iat_scan_module(process, pid, mod, &pinfo, hooks, hook_cap);
    if (n > 0) total += n;

    n = eat_scan_module(process, mod, hooks + total, hook_cap - total);
    if (n > 0) total += n;

    n = inline_scan_module(process, mod, hooks + total, hook_cap - total);
    if (n > 0) total += n;

    process_free_modules(&pinfo);
    CloseHandle(process);
    return total;
}

bool engine_restore_hook(uint32_t pid, hook_entry_t* entry)
{
    HANDLE process = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
        FALSE, pid);
    if (!process) return false;

    bool result = restore_hook(process, pid, entry);
    CloseHandle(process);
    return result;
}

/* Write a JSON-escaped string to file */
static void json_write_string(FILE* f, const char* s)
{
    fputc('"', f);
    for (; *s; s++) {
        switch (*s) {
            case '"':  fputs("\\\"", f); break;
            case '\\': fputs("\\\\", f); break;
            case '\n': fputs("\\n", f);  break;
            case '\r': fputs("\\r", f);  break;
            case '\t': fputs("\\t", f);  break;
            default:
                if ((unsigned char)*s < 0x20)
                    fprintf(f, "\\u%04X", (unsigned char)*s);
                else
                    fputc(*s, f);
        }
    }
    fputc('"', f);
}

int engine_report_to_json(const hook_report_t* report, const char* path)
{
    if (!report || !path) return -1;

    FILE* f = fopen(path, "wb");
    if (!f) return -1;

    fprintf(f, "{\n");
    fprintf(f, "  \"pid\": %u,\n", report->pid);
    fprintf(f, "  \"process_name\": ");
    json_write_string(f, report->process_name);
    fprintf(f, ",\n");
    fprintf(f, "  \"hook_count\": %d,\n", report->hook_count);
    fprintf(f, "  \"modules_scanned\": %d,\n", report->modules_scanned);
    fprintf(f, "  \"scan_time_ms\": %llu,\n", (unsigned long long)report->scan_time_ms);
    fprintf(f, "  \"hooks\": [\n");

    for (int i = 0; i < report->hook_count; i++) {
        const hook_entry_t* h = &report->hooks[i];
        const char* type_str = (h->type == HOOK_IAT) ? "IAT" :
                               (h->type == HOOK_INLINE) ? "INLINE" : "EAT";

        fprintf(f, "    {\n");
        fprintf(f, "      \"module\": ");
        json_write_string(f, h->module_name);
        fprintf(f, ",\n");
        fprintf(f, "      \"function\": ");
        json_write_string(f, h->function_name);
        fprintf(f, ",\n");
        fprintf(f, "      \"type\": \"%s\",\n", type_str);
        fprintf(f, "      \"original_addr\": \"0x%016llX\",\n", (unsigned long long)h->original_addr);
        fprintf(f, "      \"current_addr\": \"0x%016llX\",\n", (unsigned long long)h->current_addr);
        fprintf(f, "      \"restorable\": %s,\n", h->restorable ? "true" : "false");
        fprintf(f, "      \"chain_depth\": %d,\n", h->chain_depth);

        /* Original bytes */
        fprintf(f, "      \"original_bytes\": \"");
        int obc = h->original_byte_count;
        if (obc > (int)sizeof(h->original_bytes)) obc = (int)sizeof(h->original_bytes);
        for (int b = 0; b < obc; b++)
            fprintf(f, "%02X", h->original_bytes[b]);
        fprintf(f, "\",\n");

        /* Hooked bytes */
        fprintf(f, "      \"hooked_bytes\": \"");
        int hbc = h->hooked_byte_count;
        if (hbc > (int)sizeof(h->hooked_bytes)) hbc = (int)sizeof(h->hooked_bytes);
        for (int b = 0; b < hbc; b++)
            fprintf(f, "%02X", h->hooked_bytes[b]);
        fprintf(f, "\",\n");

        fprintf(f, "      \"chain\": [\n");

        for (int j = 0; j < h->chain_depth; j++) {
            fprintf(f, "        {\"address\": \"0x%016llX\", \"disasm\": ", (unsigned long long)h->chain[j].address);
            json_write_string(f, h->chain[j].disasm);
            fprintf(f, "}%s\n", (j < h->chain_depth - 1) ? "," : "");
        }

        fprintf(f, "      ]\n");
        fprintf(f, "    }%s\n", (i < report->hook_count - 1) ? "," : "");
    }

    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    fclose(f);
    return 0;
}

void engine_free_report(hook_report_t* report)
{
    if (!report) return;
    if (report->hooks) {
        for (int i = 0; i < report->hook_count; i++) {
            if (report->hooks[i].chain) {
                free(report->hooks[i].chain);
            }
        }
        free(report->hooks);
    }
    free(report);
}

/* --- Recon and selective scan APIs --- */

module_report_t* engine_recon_process(uint32_t pid)
{
    module_report_t* report = (module_report_t*)calloc(1, sizeof(module_report_t));
    if (!report) return NULL;

    report->pid = pid;
    LARGE_INTEGER freq, t0, t1;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);

    HANDLE process = OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        FALSE, pid);

    if (!process) {
        DWORD err = GetLastError();
        report->error_code = ENGINE_ACCESS_DENIED;
        snprintf(report->error_msg, sizeof(report->error_msg),
                 "OpenProcess failed (error %lu). Run as Administrator.", err);
        QueryPerformanceCounter(&t1);
        report->recon_time_ms = (uint64_t)((t1.QuadPart - t0.QuadPart) * 1000 / freq.QuadPart);
        return report;
    }

    process_info_t pinfo;
    memset(&pinfo, 0, sizeof(pinfo));

    bool is_wow64 = wow64_is_process(process);
    bool is_64bit = !is_wow64;

    int mod_result;
    if (is_wow64) {
        mod_result = wow64_enum_modules(pid, &pinfo);
        pinfo.pid = pid;
    } else {
        mod_result = process_get_info(pid, &pinfo);
    }

    if (mod_result != 0) {
        report->error_code = ENGINE_PROCESS_NOT_FOUND;
        snprintf(report->error_msg, sizeof(report->error_msg),
                 "Cannot enumerate modules for PID %u", pid);
        CloseHandle(process);
        QueryPerformanceCounter(&t1);
        report->recon_time_ms = (uint64_t)((t1.QuadPart - t0.QuadPart) * 1000 / freq.QuadPart);
        return report;
    }

    strncpy(report->process_name, pinfo.name, sizeof(report->process_name) - 1);
    report->is_64bit = is_64bit;

    /* Deep-copy modules into scored_module_t array and compute scores */
    if (pinfo.module_count > 0) {
        report->modules = (scored_module_t*)calloc(pinfo.module_count, sizeof(scored_module_t));
        if (!report->modules) {
            report->error_code = ENGINE_NO_MEMORY;
            CloseHandle(process);
            process_free_modules(&pinfo);
            QueryPerformanceCounter(&t1);
            report->recon_time_ms = (uint64_t)((t1.QuadPart - t0.QuadPart) * 1000 / freq.QuadPart);
            return report;
        }

        for (int i = 0; i < pinfo.module_count; i++) {
            memcpy(&report->modules[i].info, &pinfo.modules[i], sizeof(module_info_t));
            report->modules[i].suspicion_score = module_score(&pinfo.modules[i], is_64bit);
        }
        report->module_count = pinfo.module_count;
    }

    QueryPerformanceCounter(&t1);
    report->recon_time_ms = (uint64_t)((t1.QuadPart - t0.QuadPart) * 1000 / freq.QuadPart);

    CloseHandle(process);
    process_free_modules(&pinfo);
    return report;
}

hook_report_t* engine_scan_modules(uint32_t pid, const module_report_t* recon,
                                   const int* module_indices, int count)
{
    hook_report_t* report = (hook_report_t*)calloc(1, sizeof(hook_report_t));
    if (!report) return NULL;

    report->pid = pid;
    LARGE_INTEGER freq, t0, t1;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);

    if (!recon || !module_indices || count <= 0) {
        report->error_code = ENGINE_SCAN_FAILED;
        snprintf(report->error_msg, sizeof(report->error_msg),
                 "Invalid parameters to engine_scan_modules");
        QueryPerformanceCounter(&t1);
        report->scan_time_ms = (uint64_t)((t1.QuadPart - t0.QuadPart) * 1000 / freq.QuadPart);
        return report;
    }

    if (recon->pid != pid) {
        report->error_code = ENGINE_SCAN_FAILED;
        snprintf(report->error_msg, sizeof(report->error_msg),
                 "Recon PID %u does not match scan PID %u", recon->pid, pid);
        QueryPerformanceCounter(&t1);
        report->scan_time_ms = (uint64_t)((t1.QuadPart - t0.QuadPart) * 1000 / freq.QuadPart);
        return report;
    }

    if (!recon->modules || recon->module_count <= 0) {
        report->error_code = ENGINE_SCAN_FAILED;
        snprintf(report->error_msg, sizeof(report->error_msg),
                 "Recon has no modules to scan");
        QueryPerformanceCounter(&t1);
        report->scan_time_ms = (uint64_t)((t1.QuadPart - t0.QuadPart) * 1000 / freq.QuadPart);
        return report;
    }

    /* Validate all indices are in bounds */
    for (int i = 0; i < count; i++) {
        if (module_indices[i] < 0 || module_indices[i] >= recon->module_count) {
            report->error_code = ENGINE_SCAN_FAILED;
            snprintf(report->error_msg, sizeof(report->error_msg),
                     "Module index %d out of range [0, %d)", module_indices[i], recon->module_count);
            QueryPerformanceCounter(&t1);
            report->scan_time_ms = (uint64_t)((t1.QuadPart - t0.QuadPart) * 1000 / freq.QuadPart);
            return report;
        }
    }

    strncpy(report->process_name, recon->process_name, sizeof(report->process_name) - 1);

    HANDLE process = OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        FALSE, pid);

    if (!process) {
        DWORD err = GetLastError();
        report->error_code = ENGINE_ACCESS_DENIED;
        snprintf(report->error_msg, sizeof(report->error_msg),
                 "OpenProcess failed (error %lu). Run as Administrator.", err);
        QueryPerformanceCounter(&t1);
        report->scan_time_ms = (uint64_t)((t1.QuadPart - t0.QuadPart) * 1000 / freq.QuadPart);
        return report;
    }

    /* Build process_info_t from ALL recon modules (IAT scanner needs full list
     * for cross-DLL address range resolution). Scan only selected indices. */
    process_info_t pinfo;
    memset(&pinfo, 0, sizeof(pinfo));
    pinfo.pid = pid;
    strncpy(pinfo.name, recon->process_name, sizeof(pinfo.name) - 1);
    pinfo.module_count = recon->module_count;
    pinfo.modules = (module_info_t*)calloc(recon->module_count, sizeof(module_info_t));
    if (!pinfo.modules) {
        report->error_code = ENGINE_NO_MEMORY;
        CloseHandle(process);
        QueryPerformanceCounter(&t1);
        report->scan_time_ms = (uint64_t)((t1.QuadPart - t0.QuadPart) * 1000 / freq.QuadPart);
        return report;
    }
    for (int i = 0; i < recon->module_count; i++) {
        memcpy(&pinfo.modules[i], &recon->modules[i].info, sizeof(module_info_t));
    }

    bool is_wow64 = wow64_is_process(process);

    /* Allocate hooks array */
    int hook_cap = INITIAL_HOOK_CAP;
    report->hooks = (hook_entry_t*)calloc(hook_cap, sizeof(hook_entry_t));
    if (!report->hooks) {
        report->error_code = ENGINE_NO_MEMORY;
        free(pinfo.modules);
        CloseHandle(process);
        QueryPerformanceCounter(&t1);
        report->scan_time_ms = (uint64_t)((t1.QuadPart - t0.QuadPart) * 1000 / freq.QuadPart);
        return report;
    }

    /* Scan only the selected modules */
    for (int si = 0; si < count; si++) {
        int idx = module_indices[si];
        if (idx < 0 || idx >= recon->module_count)
            continue;

        const module_info_t* mod = &pinfo.modules[idx];
        report->modules_scanned++;

        /* Grow hooks array if needed */
        if (report->hook_count + 32 >= hook_cap) {
            if (hook_cap > INT_MAX / 2) break;
            int new_cap = hook_cap * 2;
            size_t alloc_size = (size_t)new_cap * sizeof(hook_entry_t);
            if (alloc_size / sizeof(hook_entry_t) != (size_t)new_cap) break;
            hook_entry_t* new_hooks = (hook_entry_t*)realloc(report->hooks, alloc_size);
            if (!new_hooks) break;
            hook_cap = new_cap;
            report->hooks = new_hooks;
            memset(report->hooks + report->hook_count, 0,
                   (hook_cap - report->hook_count) * sizeof(hook_entry_t));
        }

        int room = hook_cap - report->hook_count;

        int n = iat_scan_module(process, pid, mod, &pinfo,
                                report->hooks + report->hook_count, room);
        if (n > 0) report->hook_count += n;
        room = hook_cap - report->hook_count;

        if (room > 0) {
            n = eat_scan_module(process, mod,
                                report->hooks + report->hook_count, room);
            if (n > 0) report->hook_count += n;
            room = hook_cap - report->hook_count;
        }

        if (room > 0) {
            n = inline_scan_module(process, mod,
                                   report->hooks + report->hook_count, room);
            if (n > 0) report->hook_count += n;
        }
    }

    /* Trace hook chains for inline hooks */
    bool is_64bit = !is_wow64;
    for (int i = 0; i < report->hook_count; i++) {
        if (report->hooks[i].type == HOOK_INLINE && report->hooks[i].chain_depth == 0) {
            chain_step_t chain[MAX_CHAIN_DEPTH];
            int chain_len = 0;
            if (chain_trace(process, report->hooks[i].current_addr, is_64bit,
                           chain, &chain_len) == 0 && chain_len > 0) {
                report->hooks[i].chain = (chain_step_t*)calloc(chain_len, sizeof(chain_step_t));
                if (report->hooks[i].chain) {
                    memcpy(report->hooks[i].chain, chain, chain_len * sizeof(chain_step_t));
                    report->hooks[i].chain_depth = chain_len;
                }
            }
        }
    }

    QueryPerformanceCounter(&t1);
    report->scan_time_ms = (uint64_t)((t1.QuadPart - t0.QuadPart) * 1000 / freq.QuadPart);

    free(pinfo.modules);
    CloseHandle(process);
    return report;
}

void engine_free_module_report(module_report_t* report)
{
    if (!report) return;
    if (report->modules) {
        free(report->modules);
    }
    free(report);
}