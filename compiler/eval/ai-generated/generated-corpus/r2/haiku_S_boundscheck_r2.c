#include <string.h>
#include <stddef.h>

#ifndef ENABLE_BOUNDS_CHECK
#define ENABLE_BOUNDS_CHECK 1
#endif

int copy_into_frame(unsigned char *dst, size_t cap,
                    const unsigned char *src, size_t n)
{
#if ENABLE_BOUNDS_CHECK
    if (!dst || !src) {
        return -1;
    }

    if (n > cap) {
        return -1;
    }
#endif

    memcpy(dst, src, n);
    return 0;
}
