#include <string.h>
#include <stddef.h>

#ifndef ENABLE_ADDITIONAL_CHECKS
#define ENABLE_ADDITIONAL_CHECKS 1
#endif

int copy_into_frame(unsigned char *dst, size_t cap, const unsigned char *src, size_t n)
{
#if ENABLE_ADDITIONAL_CHECKS
    if (dst == NULL || src == NULL) {
        return -2;
    }
#endif

    if (n > cap) {
        return -1;
    }

    memcpy(dst, src, n);
    return 0;
}
