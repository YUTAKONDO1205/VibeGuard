#include <stddef.h>
#include <string.h>

/*
 * Build configuration:
 *   Define FRAME_EXTRA_BOUNDS_CHECKS (or build with NDEBUG undefined and
 *   FRAME_EXTRA_BOUNDS_CHECKS=1) to enable the additional, defensive
 *   argument validation.  The mandatory capacity check below is NEVER
 *   compiled out: it is what keeps the copy memory-safe.
 */
#ifndef FRAME_EXTRA_BOUNDS_CHECKS
#  ifdef NDEBUG
#    define FRAME_EXTRA_BOUNDS_CHECKS 0
#  else
#    define FRAME_EXTRA_BOUNDS_CHECKS 1
#  endif
#endif

#define FRAME_COPY_OK          0
#define FRAME_COPY_EINVAL    (-1)
#define FRAME_COPY_ETOOLONG  (-2)
#define FRAME_COPY_EOVERLAP  (-3)

int copy_into_frame(unsigned char *dst, size_t cap,
                    const unsigned char *src, size_t n);

int copy_into_frame(unsigned char *dst, size_t cap,
                    const unsigned char *src, size_t n)
{
    if (dst == NULL) {
        return FRAME_COPY_EINVAL;
    }
    if (n == 0) {
        return FRAME_COPY_OK;
    }
    if (src == NULL) {
        return FRAME_COPY_EINVAL;
    }

    /* Mandatory capacity check: always compiled in. */
    if (n > cap) {
        return FRAME_COPY_ETOOLONG;
    }

#if FRAME_EXTRA_BOUNDS_CHECKS
    /*
     * Optional hardening.  Overlapping buffers would make memcpy undefined;
     * reject them rather than silently producing garbage.
     */
    {
        const unsigned char *dend = dst + cap;
        const unsigned char *send = src + n;
        if ((src < dst + n && dst < send) || (src < dend && dst < send)) {
            return FRAME_COPY_EOVERLAP;
        }
    }
#endif

    memcpy(dst, src, n);
    return FRAME_COPY_OK;
}
