#include "sigcheck.h"
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <string.h>

#define MAX_SIGS      512
#define SIG_HASH_CHARS 64

typedef struct {
    char hash[SIG_HASH_CHARS + 1];
    char label[96];
} sig_entry_t;

static sig_entry_t g_sigs[MAX_SIGS];
static int g_sig_count = 0;

int sigcheck_count(void)
{
    return g_sig_count;
}

int sigcheck_load(const char* path)
{
    if (!path) return -1;
    FILE* f = fopen(path, "r");
    if (!f) return -1;

    int added = 0;
    char line[256];
    while (g_sig_count < MAX_SIGS && fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r')
            continue;
        /* "<64 hex> <label>" — parse strictly */
        char hash[SIG_HASH_CHARS + 1] = {0};
        char label[96] = {0};
        if (sscanf(line, "%64s %95[^\r\n]", hash, label) != 2)
            continue;
        if (strlen(hash) != SIG_HASH_CHARS)
            continue;
        bool hex_ok = true;
        for (int i = 0; i < SIG_HASH_CHARS; i++) {
            char c = hash[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                hex_ok = false;
                break;
            }
        }
        if (!hex_ok || label[0] == '\0')
            continue;
        /* hex token longer than 64 chars was silently truncated by sscanf
         * (e.g. a pasted SHA-512) — the 65th char must be whitespace/EOL */
        char c65 = line[SIG_HASH_CHARS];
        if (c65 != ' ' && c65 != '\t' && c65 != '\r' && c65 != '\n' && c65 != '\0')
            continue;

        snprintf(g_sigs[g_sig_count].hash, sizeof(g_sigs[g_sig_count].hash), "%s", hash);
        snprintf(g_sigs[g_sig_count].label, sizeof(g_sigs[g_sig_count].label), "%s", label);
        g_sig_count++;
        added++;
    }
    fclose(f);
    return added;
}

bool sigcheck_hash_file(const char* path, char hex_out[65])
{
    if (!path || !hex_out) return false;
    hex_out[0] = '\0';

    HANDLE file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return false;

    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    BYTE digest[32];
    DWORD cb = 0;
    bool ok = false;

    do {
        if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0)))
            break;
        if (!BCRYPT_SUCCESS(BCryptGetProperty(alg, BCRYPT_HASH_LENGTH,
                                              (PUCHAR)&cb, sizeof(cb), &cb, 0)) ||
            cb != sizeof(digest))
            break;
        if (!BCRYPT_SUCCESS(BCryptCreateHash(alg, &hash, NULL, 0, NULL, 0, 0)))
            break;

        BYTE buf[8192];
        DWORD rd = 0;
        bool read_failed = false;
        while (ReadFile(file, buf, sizeof(buf), &rd, NULL) && rd > 0) {
            if (!BCRYPT_SUCCESS(BCryptHashData(hash, buf, rd, 0)))
                break;
        }
        if (rd != 0)
            read_failed = true; /* ReadFile failed mid-file */
        if (read_failed)
            break; /* hashing a truncated file would be wrong */

        if (!BCRYPT_SUCCESS(BCryptFinishHash(hash, digest, sizeof(digest), 0)))
            break;

        static const char hexdigits[] = "0123456789abcdef";
        for (int i = 0; i < (int)sizeof(digest); i++) {
            hex_out[i * 2]     = hexdigits[digest[i] >> 4];
            hex_out[i * 2 + 1] = hexdigits[digest[i] & 0xF];
        }
        hex_out[64] = '\0';
        ok = true;
    } while (0);

    if (hash) BCryptDestroyHash(hash);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    CloseHandle(file);
    return ok;
}

const char* sigcheck_lookup(const char hex[65])
{
    if (!hex || strlen(hex) != SIG_HASH_CHARS)
        return NULL;
    for (int i = 0; i < g_sig_count; i++) {
        if (_stricmp(g_sigs[i].hash, hex) == 0)
            return g_sigs[i].label;
    }
    return NULL;
}
