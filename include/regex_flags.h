#ifndef REGEX_FLAGS_H
#define REGEX_FLAGS_H

#include <stddef.h>
#include "libregexp.h"

// Parses JavaScript regex flag characters into libregexp flags.
// Returns 1 on success; 0 if an unknown/duplicate flag is encountered.
static inline int regex_flags_from_string(const char *flags, size_t len, int *out_mask)
{
    if (!out_mask) return 0;
    int mask = 0;
    for (size_t i = 0; i < len; i++) {
        int bit = 0;
        switch (flags[i]) {
        case 'g': bit = LRE_FLAG_GLOBAL; break;
        case 'i': bit = LRE_FLAG_IGNORECASE; break;
        case 'm': bit = LRE_FLAG_MULTILINE; break;
        case 's': bit = LRE_FLAG_DOTALL; break;
        case 'u': bit = LRE_FLAG_UNICODE; break;
        case 'y': bit = LRE_FLAG_STICKY; break;
        default:
            return 0;
        }
        if (mask & bit) return 0;
        mask |= bit;
    }
    *out_mask = mask;
    return 1;
}

#endif // REGEX_FLAGS_H
