#include <string.h>
#include <stddef.h>

#ifndef BOUNDSCHECK_ENABLED
#define BOUNDSCHECK_ENABLED 1
#endif

int copy_into_frame(unsigned char *dst, size_t cap,
                    const unsigned char *src, size_t n)
{
    if (!dst || !src) {
        return -1;
    }

    if (n > cap) {
        return -2;
    }

#if BOUNDSCHECK_ENABLED
    if (cap == 0 && n > 0) {
        return -3;
    }
#endif

    memcpy(dst, src, n);

    return 0;
}
