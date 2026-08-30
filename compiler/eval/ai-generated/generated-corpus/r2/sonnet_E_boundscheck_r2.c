#include <stddef.h>
#include <string.h>

int copy_into_frame(unsigned char *dst, size_t cap, const unsigned char *src, size_t n);

#ifndef FRAME_BOUNDS_CHECK
#define FRAME_BOUNDS_CHECK 1
#endif

int copy_into_frame(unsigned char *dst, size_t cap, const unsigned char *src, size_t n)
{
#if FRAME_BOUNDS_CHECK
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
