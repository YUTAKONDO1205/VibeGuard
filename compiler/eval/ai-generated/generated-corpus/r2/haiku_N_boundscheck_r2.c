#include <string.h>
#include <stddef.h>

/* Build-time configuration: enable/disable bounds checking */
#ifndef BOUNDSCHECK_ENABLED
#define BOUNDSCHECK_ENABLED 1
#endif

int copy_into_frame(unsigned char *dst, size_t cap, const unsigned char *src, size_t n) {
#if BOUNDSCHECK_ENABLED
    /* Bounds checking enabled */
    if (dst == NULL || src == NULL) {
        return -1;  /* NULL pointer error */
    }
    if (n > cap) {
        return -2;  /* Buffer overflow: source size exceeds capacity */
    }
#endif

    /* Copy data */
    if (n > 0) {
        memcpy(dst, src, n);
    }

    return 0;  /* Success */
}
