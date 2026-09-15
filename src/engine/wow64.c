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

/* Read the PE machine type of a module in the target process
 * (0x014C = i386, 0x8664 = x64). Returns 0 on failure. */
static WORD wow64_read_machine(HANDLE process, uintptr_t base)
{
    BYTE dos[64];
    SIZE_T read = 0;
    if (!ReadProcessMemory(process, (LPCVOID)(uintptr_t)base, dos, sizeof(dos), &read) ||
        read < sizeof(dos))
        return 0;
    if (dos[0] != 'M' || dos[1] != 'Z')
        return 0;
    uint32_t e_lfanew = 0;
    memcpy(&e_lfanew, dos + 0x3C, sizeof(e_lfanew));
    if (e_lfanew == 0 || e_lfanew > 0x1000000)
        return 0;

    BYTE nth[6];
    if (!ReadProcessMemory(process, (LPCVOID)(uintptr_t)(base + e_lfanew), nth, sizeof(nth), &read) ||
        read < sizeof(nth))
        return 0;
    if (nth[0] != 'P' || nth[1] != 'E')
        return 0;
    WORD machine = 0;
    memcpy(&machine, nth + 4, sizeof(machine));
    return machine;
}

int wow64_enum_modules(uint32_t pid, process_info_t* info)
{
    /* WoW64 modules use the same Toolhelp32 API; just mark them as wow64.
     * Open the process once here for header validation. */
    HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!process)
        return -1;

    int result = process_enum_modules(pid, info);
    if (result == 0) {
        int kept = 0;
        for (int i = 0; i < info->module_count; i++) {
            info->modules[i].is_wow64 = true;
            /* The snapshot also contains the process's 64-bit system modules
             * (64-bit ntdll, wow64cpu below 4GB, ...). Their names collide
             * with the 32-bit ones and poison range lookups, and their code
             * is x64 — keep only modules whose PE machine says i386. */
            WORD machine = wow64_read_machine(process, info->modules[i].base_addr);
            if (machine != 0x014C)
                continue;
            if (kept != i)
                info->modules[kept] = info->modules[i];
            kept++;
        }
        info->module_count = kept;
    }
    CloseHandle(process);
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
