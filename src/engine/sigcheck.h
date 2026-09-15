#ifndef SIGCHECK_H
#define SIGCHECK_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Known-signature database for hook targets.
 *
 * A database is a plain text file with one entry per line:
 *     <64-char lowercase sha256 hex> <label>
 * Lines starting with '#' and blank lines are ignored. Example:
 *     # Known legit hook DLL deployed by our EDR
 *     9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 test-hook-dll
 */

/* Load (append) signatures from a database file. Returns the number of
 * entries added, or -1 if the file could not be opened. Malformed lines
 * are skipped. */
int sigcheck_load(const char* path);

/* Number of loaded signatures. */
int sigcheck_count(void);

/* Compute the SHA256 of a file as 64 lowercase hex chars (+ NUL).
 * Returns false if the file cannot be read or hashing fails. */
bool sigcheck_hash_file(const char* path, char hex_out[65]);

/* Look up a 64-char hex digest. Returns the label, or NULL if unknown. */
const char* sigcheck_lookup(const char hex[65]);

#ifdef __cplusplus
}
#endif

#endif /* SIGCHECK_H */
