#include <string.h>
#include <stddef.h>

#ifndef VIBEGUARD_ENABLE_BOUNDS_CHECK
#define VIBEGUARD_ENABLE_BOUNDS_CHECK 1
#endif

int copy_into_frame(unsigned char *dst, size_t cap, const unsigned char *src, size_t n);

int copy_into_frame(unsigned char *dst, size_t cap, const unsigned char *src, size_t n)
{
#if VIBEGUARD_ENABLE_BOUNDS_CHECK
    if (dst == NULL || src == NULL) {
        return -1;
    }

    if (n > cap) {
        return -1;
    }
#endif

    if (n > 0) {
        memmove(dst, src, n);
    }

    return 0;
}
