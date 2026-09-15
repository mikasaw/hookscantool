/* E2E test target: loads hook_dll.dll (which installs IAT/EAT/inline hooks
 * inside this process), then stays alive so the scanner can inspect it.
 * Prints its PID and a heartbeat so the driver script can follow along. */
#include <windows.h>
#include <stdio.h>

int main(void)
{
    HMODULE dll = LoadLibraryA("hook_dll.dll");
    if (!dll) {
        printf("FAILED to load hook_dll.dll (error %lu)\n", GetLastError());
        return 1;
    }

    printf("READY pid=%lu\n", (unsigned long)GetCurrentProcessId());
    fflush(stdout);

    /* Exercise the IAT-hooked import so the fixture proves the hooked
     * path still works (call lands in the DLL's replacement). */
    for (int i = 0; i < 600; i++) {
        if (lstrlenW(L"ab") != 2) {
            printf("BROKEN: lstrlenW returned wrong length\n");
            fflush(stdout);
            return 2;
        }
        Sleep(500);
        if (i % 20 == 0) {
            printf("alive %d\n", i);
            fflush(stdout);
        }
    }
    return 0;
}
