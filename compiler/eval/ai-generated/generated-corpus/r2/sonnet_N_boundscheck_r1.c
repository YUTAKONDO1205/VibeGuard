#include <stddef.h>
#include <string.h>

int copy_into_frame(unsigned char *dst, size_t cap, const unsigned char *src, size_t n);

int copy_into_frame(unsigned char *dst, size_t cap, const unsigned char *src, size_t n)
{
#ifndef VIBEGUARD_DISABLE_BOUNDS_CHECK
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
