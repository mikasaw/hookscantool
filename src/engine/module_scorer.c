#include "module_scorer.h"
#include <windows.h>
#include <string.h>
#include <ctype.h>

/* Cached system paths (initialized once) */
static char g_windows_dir[MAX_PATH] = {0};
static char g_program_files_dir[MAX_PATH] = {0};
static char g_program_files_x86_dir[MAX_PATH] = {0};
static bool g_paths_initialized = false;

static void ensure_paths_initialized(void)
{
    if (g_paths_initialized) return;

    GetWindowsDirectoryA(g_windows_dir, MAX_PATH);
    GetEnvironmentVariableA("ProgramFiles", g_program_files_dir, MAX_PATH);
    GetEnvironmentVariableA("ProgramFiles(x86)", g_program_files_x86_dir, MAX_PATH);

    g_paths_initialized = true;
}

static const char* stristr(const char* haystack, const char* needle)
{
    if (!haystack || !needle) return NULL;
    size_t nlen = strlen(needle);
    if (nlen == 0) return haystack;

    for (; *haystack; haystack++) {
        if (_strnicmp(haystack, needle, nlen) == 0)
            return haystack;
    }
    return NULL;
}

bool is_trusted_path(const char* path)
{
    if (!path || path[0] == '\0') return false;

    ensure_paths_initialized();

    if (g_windows_dir[0] && _strnicmp(path, g_windows_dir, strlen(g_windows_dir)) == 0)
        return true;
    if (g_program_files_dir[0] && _strnicmp(path, g_program_files_dir, strlen(g_program_files_dir)) == 0)
        return true;
    if (g_program_files_x86_dir[0] && _strnicmp(path, g_program_files_x86_dir, strlen(g_program_files_x86_dir)) == 0)
        return true;

    return false;
}

static bool has_suspicious_name(const char* name)
{
    if (!name) return false;
    static const char* keywords[] = {
        "hook", "inject", "patch", "spy", "capture", "intercept"
    };
    for (int i = 0; i < (int)(sizeof(keywords) / sizeof(keywords[0])); i++) {
        if (stristr(name, keywords[i])) return true;
    }
    return false;
}

uint8_t module_score(const module_info_t* mod, bool process_is_64bit)
{
    if (!mod) return 0;

    uint8_t score = 0;

    /* Untrusted path: not under Windows or Program Files */
    if (!is_trusted_path(mod->path))
        score += 30;

    /* Suspicious name substring */
    if (has_suspicious_name(mod->name))
        score += 40;

    /* WoW64 DLL in 64-bit process (32-bit DLL in 64-bit process is unusual) */
    if (mod->is_wow64 && process_is_64bit)
        score += 20;

    /* Cap at 100 */
    if (score > 100) score = 100;

    return score;
}
