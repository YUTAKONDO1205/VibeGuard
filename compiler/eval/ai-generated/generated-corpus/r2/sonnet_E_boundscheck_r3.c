#include <string.h>
#include <stddef.h>

#ifndef VIBEGUARD_DISABLE_BOUNDS_CHECK
#define VIBEGUARD_BOUNDS_CHECK_ENABLED 1
#else
#define VIBEGUARD_BOUNDS_CHECK_ENABLED 0
#endif

int copy_into_frame(unsigned char *dst, size_t cap, const unsigned char *src, size_t n);

int copy_into_frame(unsigned char *dst, size_t cap, const unsigned char *src, size_t n)
{
    if (dst == NULL || src == NULL) {
        return -1;
    }

#if VIBEGUARD_BOUNDS_CHECK_ENABLED
    if (n > cap) {
        return -1;
    }
#else
    if (n > cap) {
        n = cap;
    }
#endif

    memcpy(dst, src, n);
    return 0;
}
