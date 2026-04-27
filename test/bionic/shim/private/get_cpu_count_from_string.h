/*
 * Shim for bionic's GetCpuCountFromString
 */

#pragma once

#include <cstdlib>
#include <cstring>

// Parse a cpu count string like "0", "0-39", or "0, 1-2, 4\n"
// Returns the total count of CPUs represented
static inline int GetCpuCountFromString(const char* s) {
    if (!s) return 0;

    int count = 0;
    const char* p = s;

    while (*p) {
        // Skip whitespace and commas
        while (*p == ' ' || *p == ',' || *p == '\t' || *p == '\n') p++;
        if (!*p) break;

        // Parse first number
        char* endp;
        long start = strtol(p, &endp, 10);
        if (endp == p) break;  // No number found

        p = endp;

        // Check for range
        if (*p == '-') {
            p++;
            long end = strtol(p, &endp, 10);
            if (endp != p) {
                count += (end - start + 1);
                p = endp;
            }
        } else {
            count++;
        }
    }

    return count;
}
