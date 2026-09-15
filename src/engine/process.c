#include "process_enum.h"
#include <tlhelp32.h>
#include <stdlib.h>
#include <string.h>
#include <psapi.h>

void process_read_image_name(HANDLE process, char* buf, size_t buf_size)
{
    if (!buf || buf_size == 0)
        return;
    buf[0] = '\0';

    WCHAR wpath[1024];
    const DWORD wcap = (DWORD)(sizeof(wpath) / sizeof(wpath[0]));
    DWORD n = GetModuleFileNameExW(process, NULL, wpath, wcap);
    if (n == 0) {
        DWORD wn = wcap;
        if (QueryFullProcessImageNameW(process, 0, wpath, &wn)) {
            n = wn;
        } else {
            n = GetProcessImageFileNameW(process, wpath, wcap);
        }
    }
    if (n == 0)
        return;
    wpath[wcap - 1] = L'\0';

    /* Basename only: strip everything up to the last path separator */
    WCHAR* base = wpath;
    for (WCHAR* c = wpath; *c; c++) {
        if (*c == L'\\' || *c == L'/')
            base = c + 1;
    }
    WideCharToMultiByte(CP_UTF8, 0, base, -1,
                        buf, (int)buf_size, NULL, NULL);
}

process_info_t* process_enum_all(int* count)
{
    *count = 0;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return NULL;

    /* Count processes first */
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    int total = 0;
    if (Process32FirstW(snap, &pe)) {
        do { total++; } while (Process32NextW(snap, &pe));
    }

    if (total == 0) {
        CloseHandle(snap);
        return NULL;
    }

    process_info_t* list = (process_info_t*)calloc(total, sizeof(process_info_t));
    if (!list) {
        CloseHandle(snap);
        return NULL;
    }

    /* Fill process list */
    if (Process32FirstW(snap, &pe)) {
        int i = 0;
        do {
            list[i].pid = pe.th32ProcessID;
            /* Convert wide name to ASCII (best effort for common names) */
            WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1,
                               list[i].name, sizeof(list[i].name), NULL, NULL);
            i++;
        } while (Process32NextW(snap, &pe) && i < total);
        *count = i;
    }

    CloseHandle(snap);
    return list;
}

int process_enum_modules(uint32_t pid, process_info_t* info)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) {
        /* May fail if we don't have access — try without MODULE32 */
        snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
        if (snap == INVALID_HANDLE_VALUE)
            return -1;
    }

    /* Count modules */
    MODULEENTRY32W me;
    me.dwSize = sizeof(me);
    int total = 0;
    if (Module32FirstW(snap, &me)) {
        do { total++; } while (Module32NextW(snap, &me));
    }

    if (total == 0) {
        CloseHandle(snap);
        return 0;
    }

    info->modules = (module_info_t*)calloc(total, sizeof(module_info_t));
    if (!info->modules) {
        CloseHandle(snap);
        return -1;
    }

    if (Module32FirstW(snap, &me)) {
        int i = 0;
        do {
            WideCharToMultiByte(CP_UTF8, 0, me.szModule, -1,
                               info->modules[i].name, sizeof(info->modules[i].name), NULL, NULL);
            WideCharToMultiByte(CP_UTF8, 0, me.szExePath, -1,
                               info->modules[i].path, sizeof(info->modules[i].path), NULL, NULL);
            info->modules[i].base_addr = (uintptr_t)me.modBaseAddr;
            info->modules[i].size      = me.modBaseSize;
            i++;
        } while (Module32NextW(snap, &me) && i < total);
        info->module_count = i;
    }

    CloseHandle(snap);
    return 0;
}

int process_get_info(uint32_t pid, process_info_t* info)
{
    memset(info, 0, sizeof(*info));
    info->pid = pid;

    /* Get process name */
    HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!proc)
        return -1;

    process_read_image_name(proc, info->name, sizeof(info->name));
    CloseHandle(proc);

    return process_enum_modules(pid, info);
}

void process_free_list(process_info_t* list, int count)
{
    if (!list) return;
    for (int i = 0; i < count; i++) {
        process_free_modules(&list[i]);
    }
    free(list);
}

void process_free_modules(process_info_t* info)
{
    if (info->modules) {
        free(info->modules);
        info->modules = NULL;
    }
    info->module_count = 0;
}
