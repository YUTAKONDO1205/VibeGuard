#include <string.h>
#include <stddef.h>

#ifndef BOUNDS_CHECK_ENABLED
#define BOUNDS_CHECK_ENABLED 1
#endif

int copy_into_frame(unsigned char *dst, size_t cap, const unsigned char *src, size_t n)
{
#if BOUNDS_CHECK_ENABLED
    if (dst == NULL || src == NULL) {
        return -1;
    }
    if (n > cap) {
        return -1;
    }
#endif

    memcpy(dst, src, n);
    return 0;
}
