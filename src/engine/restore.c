#include "restore.h"
#include <tlhelp32.h>
#include <stdlib.h>
#include <string.h>

/* Resume all previously suspended threads and close handles */
static void resume_threads(HANDLE* threads, int count);

/* Suspend all threads in a target process, catching threads created
 * between the two enumeration passes. Any failure (OpenThread,
 * SuspendThread) is fatal and suspends already acquired are undone:
 * writing while an unknown thread may run through the patched region
 * could crash the target.
 * Returns array of thread handles and count, or NULL on error.
 * Caller must resume via resume_threads and free the array. */
static HANDLE* suspend_threads(uint32_t pid, int* count)
{
    *count = 0;

    HANDLE* threads = NULL;
    DWORD*  tids    = NULL;
    int     cap     = 0;

    for (int pass = 0; pass < 2; pass++) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE)
            goto fail;

        THREADENTRY32 te;
        te.dwSize = sizeof(te);
        if (!Thread32First(snap, &te)) {
            CloseHandle(snap);
            goto fail;
        }

        do {
            if (te.th32OwnerProcessID != pid)
                continue;

            bool already = false;
            for (int i = 0; i < *count; i++) {
                if (tids[i] == te.th32ThreadID) { already = true; break; }
            }
            if (already)
                continue;

            if (*count == cap) {
                int new_cap = cap ? cap * 2 : 16;
                HANDLE* nt = (HANDLE*)realloc(threads, (size_t)new_cap * sizeof(HANDLE));
                if (!nt) { CloseHandle(snap); goto fail; }
                threads = nt;
                DWORD* ni = (DWORD*)realloc(tids, (size_t)new_cap * sizeof(DWORD));
                if (!ni) { CloseHandle(snap); goto fail; }
                tids = ni;
                cap = new_cap;
            }

            HANDLE t = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
            if (!t) { CloseHandle(snap); goto fail; }
            if (SuspendThread(t) == (DWORD)-1) {
                CloseHandle(t);
                CloseHandle(snap);
                goto fail;
            }
            threads[*count] = t;
            tids[*count]    = te.th32ThreadID;
            (*count)++;
        } while (Thread32Next(snap, &te));

        CloseHandle(snap);
    }

    free(tids);
    if (*count == 0) {
        free(threads);
        return NULL;
    }
    return threads;

fail:
    if (threads)
        resume_threads(threads, *count);
    free(tids);
    return NULL;
}

/* Resume all previously suspended threads and close handles */
static void resume_threads(HANDLE* threads, int count)
{
    for (int i = 0; i < count; i++) {
        ResumeThread(threads[i]);
        CloseHandle(threads[i]);
    }
    free(threads);
}

/* Read len bytes back from the target and compare against expected */
static bool verify_memory(HANDLE process, uint64_t addr,
                          const uint8_t* expected, int len)
{
    uint8_t buf[64];
    SIZE_T read = 0;
    if (len <= 0 || len > (int)sizeof(buf))
        return false;
    if (!ReadProcessMemory(process, (LPCVOID)(uintptr_t)addr,
                           buf, (SIZE_T)len, &read) ||
        read != (SIZE_T)len)
        return false;
    return memcmp(buf, expected, (size_t)len) == 0;
}

bool restore_hook(HANDLE process, uint32_t pid, hook_entry_t* entry)
{
    if (!entry) return false;
    if (entry->original_byte_count == 0 || entry->original_byte_count > (int)sizeof(entry->original_bytes))
        return false;
    if (entry->hooked_byte_count == 0 || entry->hooked_byte_count > (int)sizeof(entry->hooked_bytes))
        return false;
    if (!entry->restorable || entry->original_byte_count <= 0)
        return false;

    /* Suspend threads to prevent execution of partially-written code */
    int thread_count = 0;
    HANDLE* threads = suspend_threads(pid, &thread_count);

    if (!threads) {
        /* Cannot safely write to the process without suspending its threads.
         * The target could execute partially-written code and crash. */
        return false;
    }

    /* Change memory protection to writable */
    DWORD old_protect;
    if (!VirtualProtectEx(process, (LPVOID)(uintptr_t)entry->current_addr,
                          entry->original_byte_count,
                          PAGE_EXECUTE_READWRITE, &old_protect)) {
        resume_threads(threads, thread_count);
        return false;
    }

    /* Re-read current bytes and verify the hook is still present (TOCTOU check).
     * Another thread could have restored or modified the bytes between the scan
     * and now. Writing original bytes over a different hook would corrupt code.
     * Compare the region we are about to overwrite against the hook bytes
     * recorded at scan time. */
    if (!verify_memory(process, entry->current_addr, entry->hooked_bytes,
                       entry->original_byte_count < entry->hooked_byte_count ?
                           entry->original_byte_count : entry->hooked_byte_count)) {
        /* Hook bytes changed since scan — abort to avoid corrupting code */
        VirtualProtectEx(process, (LPVOID)(uintptr_t)entry->current_addr,
                         entry->original_byte_count, old_protect, &old_protect);
        resume_threads(threads, thread_count);
        return false;
    }

    /* Write original bytes */
    SIZE_T written = 0;
    bool write_ok = WriteProcessMemory(process, (LPVOID)(uintptr_t)entry->current_addr,
                                        entry->original_bytes,
                                        (SIZE_T)entry->original_byte_count,
                                        &written) &&
                    written == (SIZE_T)entry->original_byte_count;

    /* Verify the write landed; a partial write leaves the target in a
     * mixed-bytes state that would likely crash on next execution. */
    if (write_ok)
        write_ok = verify_memory(process, entry->current_addr,
                                 entry->original_bytes, entry->original_byte_count);

    if (!write_ok) {
        /* Roll back to the full hooked state recorded at scan time so the
         * target keeps running the (still-hooked) function instead of on
         * half-restored bytes. Best effort: if the rollback write itself
         * fails there is nothing further to do from here. */
        SIZE_T rb_written = 0;
        if (WriteProcessMemory(process, (LPVOID)(uintptr_t)entry->current_addr,
                               entry->hooked_bytes,
                               (SIZE_T)entry->hooked_byte_count,
                               &rb_written) &&
            rb_written == (SIZE_T)entry->hooked_byte_count) {
            verify_memory(process, entry->current_addr,
                          entry->hooked_bytes, entry->hooked_byte_count);
        }
        FlushInstructionCache(process, (LPCVOID)(uintptr_t)entry->current_addr,
                              (SIZE_T)entry->hooked_byte_count);
        VirtualProtectEx(process, (LPVOID)(uintptr_t)entry->current_addr,
                         entry->original_byte_count, old_protect, &old_protect);
        resume_threads(threads, thread_count);
        return false;
    }

    /* Restore original protection */
    VirtualProtectEx(process, (LPVOID)(uintptr_t)entry->current_addr,
                     entry->original_byte_count, old_protect, &old_protect);

    /* Flush instruction cache */
    FlushInstructionCache(process, (LPCVOID)(uintptr_t)entry->current_addr,
                          (SIZE_T)entry->original_byte_count);

    /* Resume threads */
    resume_threads(threads, thread_count);

    /* Mark as no longer hooked */
    entry->restorable = false;
    return true;
}
