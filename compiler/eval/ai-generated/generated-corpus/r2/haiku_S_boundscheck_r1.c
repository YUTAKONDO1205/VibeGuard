#include <string.h>
#include <stddef.h>

int copy_into_frame(unsigned char *dst, size_t cap, const unsigned char *src, size_t n);

#ifndef DISABLE_BOUNDS_CHECK
#define ENABLE_BOUNDS_CHECK 1
#endif

int copy_into_frame(unsigned char *dst, size_t cap, const unsigned char *src, size_t n)
{
#ifdef ENABLE_BOUNDS_CHECK
    if (dst == NULL || src == NULL) {
        return -1;
    }

    if (n > cap) {
        return -2;
    }
#endif

    memcpy(dst, src, n);
    return 0;
}
