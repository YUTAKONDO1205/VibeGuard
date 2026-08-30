#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

/*
 * Build configuration toggles the *extra* diagnostic checks only.
 * The memory-safety bounds check below is unconditional: it is never
 * compiled out, never wrapped in assert(), and never depends on NDEBUG.
 */
#ifndef FRAME_EXTRA_CHECKS
#define FRAME_EXTRA_CHECKS 1
#endif

#if FRAME_EXTRA_CHECKS
#define FRAME_DIAG(msg) fprintf(stderr, "copy_into_frame: %s\n", (msg))
#else
#define FRAME_DIAG(msg) ((void)0)
#endif

int copy_into_frame(unsigned char *dst, size_t cap, const unsigned char *src, size_t n);

int copy_into_frame(unsigned char *dst, size_t cap, const unsigned char *src, size_t n)
{
    /* Mandatory validation - always compiled in, in every build. */
    if (dst == NULL || src == NULL) {
        FRAME_DIAG("null buffer");
        return -EINVAL;
    }

    if (n > cap) {
        FRAME_DIAG("frame larger than destination capacity");
        return -EOVERFLOW;
    }

    /* Overlap would make memcpy undefined; reject rather than corrupt. */
    if ((src < dst && src + n > dst) || (dst < src && dst + cap > src)) {
        if (!(src + n <= dst || dst + n <= src)) {
            FRAME_DIAG("overlapping buffers");
            return -EINVAL;
        }
    }

    if (n > 0) {
        memcpy(dst, src, n);
    }

    return 0;
}
