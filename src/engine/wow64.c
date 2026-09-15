#include "wow64.h"
#include "process_enum.h"
#include <tlhelp32.h>
#include <stdlib.h>
#include <string.h>

typedef NTSTATUS(NTAPI* NtWow64ReadVirtualMemory64_t)(
    HANDLE ProcessHandle,
    ULONG64 BaseAddress,
    PVOID Buffer,
    ULONG64 Size,
    PULONG64 NumberOfBytesRead
);

bool wow64_is_process(HANDLE process)
{
    BOOL is_wow64 = FALSE;
    if (!IsWow64Process(process, &is_wow64))
        return false;
    return is_wow64 ? true : false;
}

int wow64_enum_modules(uint32_t pid, process_info_t* info)
{
    /* WoW64 modules use the same Toolhelp32 API; just mark them as wow64 */
    int result = process_enum_modules(pid, info);
    if (result == 0) {
        int kept = 0;
        for (int i = 0; i < info->module_count; i++) {
            info->modules[i].is_wow64 = true;
            /* The snapshot can also contain the process's 64-bit system
             * modules (64-bit ntdll etc.). They share names with the 32-bit
             * ones and poison range lookups — keep only the 32-bit half. */
            if (info->modules[i].base_addr > 0xFFFFFFFFull ||
                (uint64_t)info->modules[i].base_addr + info->modules[i].size > 0x100000000ull)
                continue;
            if (kept != i)
                info->modules[kept] = info->modules[i];
            kept++;
        }
        info->module_count = kept;
    }
    return result;
}

static NtWow64ReadVirtualMemory64_t wow64_resolve_fn(void)
{
    static NtWow64ReadVirtualMemory64_t fn = NULL;
    static LONG resolved = 0;

    if (InterlockedCompareExchange(&resolved, 0, 0) == 0) {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        NtWow64ReadVirtualMemory64_t tmp = NULL;
        if (ntdll) {
            tmp = (NtWow64ReadVirtualMemory64_t)GetProcAddress(ntdll, "NtWow64ReadVirtualMemory64");
        }
        InterlockedExchangePointer((PVOID*)&fn, tmp);
        InterlockedExchange(&resolved, 1);
    }
    return fn;
}

BOOL wow64_read_memory(HANDLE process, LPCVOID addr, LPVOID buf, SIZE_T size, SIZE_T* read)
{
    NtWow64ReadVirtualMemory64_t fn = wow64_resolve_fn();

    if (fn) {
        ULONG64 bytes_read = 0;
        ULONG64 addr64 = (ULONG64)(uintptr_t)addr;
        NTSTATUS status = fn(process, addr64, buf, (ULONG64)size, &bytes_read);
        if (status == 0) {
            if (read) *read = (SIZE_T)bytes_read;
            return TRUE;
        }
    }

    return ReadProcessMemory(process, addr, buf, size, read);
}
