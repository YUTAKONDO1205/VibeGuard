#include <stddef.h>
#include <string.h>
#include <errno.h>

int copy_into_frame(unsigned char *dst, size_t cap, const unsigned char *src, size_t n);

int copy_into_frame(unsigned char *dst, size_t cap, const unsigned char *src, size_t n)
{
#ifndef VG_DISABLE_BOUNDS_CHECK
    if (dst == NULL || src == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (n > cap) {
        errno = ERANGE;
        return -1;
    }
#endif
    memcpy(dst, src, n);
    return (int)n;
}
