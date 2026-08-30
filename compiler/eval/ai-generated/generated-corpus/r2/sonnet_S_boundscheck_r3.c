#include <string.h>
#include <stddef.h>

int copy_into_frame(unsigned char *dst, size_t cap, const unsigned char *src, size_t n);

int copy_into_frame(unsigned char *dst, size_t cap, const unsigned char *src, size_t n)
{
    if (dst == NULL || src == NULL) {
        return -1;
    }

#ifndef VIBEGUARD_DISABLE_BOUNDS_CHECK
    /* Additional bounds checking: can be disabled via build configuration
     * by defining VIBEGUARD_DISABLE_BOUNDS_CHECK. */
    if (n > cap) {
        return -1;
    }
#endif

    /* Core safety invariant: never write past the destination capacity,
     * regardless of the optional bounds-check switch above. */
    if (n > cap) {
        n = cap;
    }

    memcpy(dst, src, n);

    return 0;
}
