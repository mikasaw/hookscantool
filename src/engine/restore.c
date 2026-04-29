#include "restore.h"
#include <tlhelp32.h>
#include <stdlib.h>
#include <string.h>

/* Suspend all threads in a target process.
 * Returns array of thread handles and count, or NULL on error.
 * Caller must resume via resume_threads and free the array. */
static HANDLE* suspend_threads(uint32_t pid, int* count)
{
    *count = 0;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return NULL;

    /* Count threads belonging to this process */
    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    int total = 0;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid)
                total++;
        } while (Thread32Next(snap, &te));
    }

    if (total == 0) {
        CloseHandle(snap);
        return NULL;
    }

    HANDLE* threads = (HANDLE*)calloc(total, sizeof(HANDLE));
    if (!threads) {
        CloseHandle(snap);
        return NULL;
    }

    /* Suspend each thread */
    if (Thread32First(snap, &te)) {
        int i = 0;
        do {
            if (te.th32OwnerProcessID == pid && i < total) {
                HANDLE t = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT,
                                      FALSE, te.th32ThreadID);
                if (t) {
                    SuspendThread(t);
                    /* Force the kernel to wait until the thread is actually
                     * suspended. Without this, SuspendThread is asynchronous
                     * and the thread may still be executing when we write. */
                    CONTEXT ctx;
                    memset(&ctx, 0, sizeof(ctx));
                    ctx.ContextFlags = CONTEXT_CONTROL;
                    GetThreadContext(t, &ctx);
                    threads[i++] = t;
                }
            }
        } while (Thread32Next(snap, &te));
        *count = i;
    }

    CloseHandle(snap);
    return threads;
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

bool restore_hook(HANDLE process, uint32_t pid, hook_entry_t* entry)
{
    if (!entry->restorable || entry->original_byte_count == 0)
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
    if (!VirtualProtectEx(process, (LPVOID)entry->current_addr,
                          entry->original_byte_count,
                          PAGE_EXECUTE_READWRITE, &old_protect)) {
        if (threads) resume_threads(threads, thread_count);
        return false;
    }

    /* Write original bytes */
    SIZE_T written = 0;
    bool write_ok = WriteProcessMemory(process, (LPVOID)entry->current_addr,
                                        entry->original_bytes,
                                        (SIZE_T)entry->original_byte_count,
                                        &written);

    /* Restore original protection */
    VirtualProtectEx(process, (LPVOID)entry->current_addr,
                     entry->original_byte_count, old_protect, &old_protect);

    /* Flush instruction cache */
    FlushInstructionCache(process, (LPCVOID)entry->current_addr,
                          (SIZE_T)entry->original_byte_count);

    /* Resume threads */
    if (threads) resume_threads(threads, thread_count);

    if (!write_ok || written != (SIZE_T)entry->original_byte_count)
        return false;

    /* Mark as no longer hooked */
    entry->restorable = false;
    return true;
}