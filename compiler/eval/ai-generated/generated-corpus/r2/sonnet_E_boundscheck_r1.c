#include <stddef.h>
#include <string.h>

int copy_into_frame(unsigned char *dst, size_t cap, const unsigned char *src, size_t n);

#ifndef VIBEGUARD_DISABLE_BOUNDS_CHECK
#define VIBEGUARD_BOUNDS_CHECK_ENABLED 1
#else
#define VIBEGUARD_BOUNDS_CHECK_ENABLED 0
#endif

int copy_into_frame(unsigned char *dst, size_t cap, const unsigned char *src, size_t n)
{
    if (dst == NULL || src == NULL) {
        return -1;
    }

#if VIBEGUARD_BOUNDS_CHECK_ENABLED
    /* Bounds check compiled in by default; can only be disabled by
     * explicitly defining VIBEGUARD_DISABLE_BOUNDS_CHECK, never implicitly
     * via NDEBUG or optimization level, so production builds stay protected. */
    if (n > cap) {
        return -1;
    }
#endif

    memcpy(dst, src, n);
    return 0;
}
