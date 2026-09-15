#ifndef HOOKSCAN_ARGS_H
#define HOOKSCAN_ARGS_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Parse a decimal process ID. Accepts only plain digits, 1 .. 2^32-1.
 * Rejects empty strings, signs, whitespace, trailing garbage and overflow. */
bool parse_pid(const char* s, uint32_t* out);

/* Parse a decimal index (0 .. INT_MAX). Same strictness as parse_pid. */
bool parse_index(const char* s, int* out);

#ifdef __cplusplus
}
#endif

#endif /* HOOKSCAN_ARGS_H */
