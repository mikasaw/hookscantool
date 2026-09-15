/* E2E hook fixture — installs three DETECTABLE hooks inside its own
 * process, all pointing at this DLL so the scanner has a clear story:
 *
 *   1. EAT hook    : corrupts this DLL's own export-table RVA for
 *                    e2e_marker_export (in-memory EAT != on-disk EAT).
 *   2. IAT hook    : redirects the host's lstrlenW import to
 *                    my_lstrlenW here (import pointer outside the
 *                    expected module).
 *   3. Inline hook : patches the entry of MulDiv (kernelbase) with a
 *                    jump into my_MulDiv (prologue differs from disk,
 *                    chain ends in this module).
 *
 * All replacements keep the original behavior so the host keeps running.
 * The scanner's restore path rewrites original bytes from disk, so the
 * fixture never needs to un-hook. */
#include <windows.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

/* ---- exports; the EAT hook redirects the first to the second ---- */
__declspec(dllexport) int __cdecl e2e_marker_export(void) { return 1; }
__declspec(dllexport) int __cdecl e2e_other_export(void)  { return 2; }

/* ---- IAT hook replacement ---- */
static int WINAPI my_lstrlenW(LPCWSTR s)
{
    int n = 0;
    if (s) while (s[n]) n++;
    return n;
}

/* ---- inline hook replacement (MulDiv semantics: (a*b + c/2)/c) ---- */
static int __stdcall my_MulDiv(int a, int b, int c)
{
    if (c == 0) return -1;
    long long n = (long long)a * (long long)b + c / 2;
    if (n < 0) return -1; /* MulDiv returns -1 on overflow/negative, close enough */
    int q = (int)(n / c);
    return q;
}

/* ---- patch helpers ---- */

static BOOL make_writable(void* addr, size_t len, DWORD* old_protect)
{
    return VirtualProtect(addr, len, PAGE_EXECUTE_READWRITE, old_protect);
}

/* Rewrite the IAT of hmod_target: every import of dll_name!func_name
 * (as loaded) is replaced with new_addr. Original pointer saved to
 * *orig_out. */
static BOOL patch_iat(HMODULE hmod_target, const char* dll_name,
                      const char* func_name, void* new_addr, void** orig_out)
{
    BYTE* base = (BYTE*)hmod_target;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY* imp_dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (imp_dir->Size == 0) return FALSE;

    IMAGE_IMPORT_DESCRIPTOR* desc =
        (IMAGE_IMPORT_DESCRIPTOR*)(base + imp_dir->VirtualAddress);
    for (; desc->Name; desc++) {
        char* name = (char*)(base + desc->Name);
        if (_stricmp(name, dll_name) != 0) continue;

        IMAGE_THUNK_DATA* thunk = (IMAGE_THUNK_DATA*)(base + desc->FirstThunk);
        IMAGE_THUNK_DATA* hint  = desc->OriginalFirstThunk
            ? (IMAGE_THUNK_DATA*)(base + desc->OriginalFirstThunk) : thunk;
        for (; hint->u1.AddressOfData; thunk++, hint++) {
            if (hint->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;
            IMAGE_IMPORT_BY_NAME* by_name =
                (IMAGE_IMPORT_BY_NAME*)(base + hint->u1.AddressOfData);
            if (strcmp((char*)by_name->Name, func_name) != 0) continue;

            DWORD old_protect;
            if (!make_writable(&thunk->u1.Function, sizeof(void*), &old_protect))
                return FALSE;
            *orig_out = (void*)thunk->u1.Function;
            thunk->u1.Function = (uintptr_t)new_addr;
            VirtualProtect(&thunk->u1.Function, sizeof(void*), old_protect, &old_protect);
            return TRUE;
        }
    }
    return FALSE;
}

/* Patch the entry of `target_func` with a jump to `hook_func`.
 * First instruction is a JMP so hook detectors see the classic pattern:
 *   x64: jmp [rip+0]  + 8-byte absolute address right after (14 bytes)
 *   x86: jmp [imm32]  whose storage is the 4 bytes after the instruction
 *        (written into the same page at target_func+6)
 * Original bytes are saved (informational only — the scanner restores
 * from the on-disk image). */
static BOOL patch_inline(void* target_func, void* hook_func,
                         BYTE* saved, int saved_cap, int* saved_len)
{
    BYTE patch[14];
#ifdef _WIN64
    int len = 14;
    patch[0] = 0xFF; patch[1] = 0x25;               /* jmp [rip+0] */
    *(DWORD*)(patch + 2) = 0;
    *(unsigned long long*)(patch + 6) = (uintptr_t)hook_func;
#else
    int len = 10;
    patch[0] = 0xFF; patch[1] = 0x25;               /* jmp [target_func+6] */
    *(DWORD*)(patch + 2) = (DWORD)((uintptr_t)target_func + 6);
    /* hook_func lands at target_func+6, written below */
#endif
    if (len > saved_cap) return FALSE;

    DWORD old_protect;
    if (!make_writable(target_func, (size_t)len, &old_protect))
        return FALSE;
    memcpy(saved, target_func, (size_t)len);
    memcpy(target_func, patch, 6);
#ifdef _WIN64
    memcpy((BYTE*)target_func + 6, patch + 6, 8);   /* absolute hook address */
#else
    *(unsigned long*)((BYTE*)target_func + 6) = (unsigned long)(uintptr_t)hook_func;
#endif
    VirtualProtect(target_func, (size_t)len, old_protect, &old_protect);
    FlushInstructionCache(GetCurrentProcess(), target_func, (size_t)len);
    *saved_len = len;
    return TRUE;
}

/* Corrupt this DLL's EAT entry for e2e_marker_export so in-memory RVA
 * differs from the on-disk export table. */
static BOOL patch_own_eat(void)
{
    HMODULE self = GetModuleHandleA("hook_dll.dll");
    if (!self) return FALSE;
    BYTE* base = (BYTE*)self;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY* exp_dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exp_dir->Size == 0) return FALSE;

    IMAGE_EXPORT_DIRECTORY* exp =
        (IMAGE_EXPORT_DIRECTORY*)(base + exp_dir->VirtualAddress);
    DWORD* rvas = (DWORD*)(base + exp->AddressOfFunctions);
    DWORD* names = (DWORD*)(base + exp->AddressOfNames);
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        char* name = (char*)(base + names[i]);
        if (strcmp(name, "e2e_marker_export") != 0) continue;
        WORD* ords = (WORD*)(base + exp->AddressOfNameOrdinals);
        DWORD* entry = &rvas[ords[i]];
        DWORD old_protect;
        if (!make_writable(entry, sizeof(DWORD), &old_protect))
            return FALSE;
        *entry += 0x40; /* point into the middle of the image = classic EAT hook */
        VirtualProtect(entry, sizeof(DWORD), old_protect, &old_protect);
        return TRUE;
    }
    return FALSE;
}

static void report(const char* what, BOOL ok)
{
    printf("hook_dll: %-12s %s\n", what, ok ? "INSTALLED" : "FAILED");
    fflush(stdout);
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason != DLL_PROCESS_ATTACH) return TRUE;
    DisableThreadLibraryCalls(hinst);

    BYTE saved[16];
    int saved_len = 0;
    void* orig_lstrlen = NULL;

    BOOL eat_ok = patch_own_eat();
    report("eat", eat_ok);

    BOOL iat_ok = patch_iat(GetModuleHandleA(NULL),
                            "KERNEL32.DLL", "lstrlenW",
                            (void*)my_lstrlenW, &orig_lstrlen);
    report("iat", iat_ok);

    FARPROC muldiv = GetProcAddress(GetModuleHandleA("KERNEL32.DLL"), "MulDiv");
    BOOL inline_ok = muldiv && patch_inline((void*)muldiv, (void*)my_MulDiv,
                                            saved, sizeof(saved), &saved_len);
    report("inline", inline_ok);

    return TRUE;
}
