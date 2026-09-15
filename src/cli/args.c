#include "args.h"
#include <errno.h>
#include <stdlib.h>
#include <ctype.h>
#include <limits.h>

/* Shared preconditions: digits only (no sign, no leading whitespace),
 * fully consumed by strtoull with no range error. */
static bool parse_ull_digits(const char* s, unsigned long long* out)
{
    if (!s || !out || !isdigit((unsigned char)*s))
        return false;

    errno = 0;
    char* endp = NULL;
    unsigned long long v = strtoull(s, &endp, 10);

    if (errno == ERANGE || *endp != '\0')
        return false;

    *out = v;
    return true;
}

bool parse_pid(const char* s, uint32_t* out)
{
    unsigned long long v;
    if (!parse_ull_digits(s, &v))
        return false;
    if (v == 0 || v > 0xFFFFFFFFull)
        return false;
    *out = (uint32_t)v;
    return true;
}

bool parse_index(const char* s, int* out)
{
    unsigned long long v;
    if (!parse_ull_digits(s, &v))
        return false;
    if (v > (unsigned long long)INT_MAX)
        return false;
    *out = (int)v;
    return true;
}
