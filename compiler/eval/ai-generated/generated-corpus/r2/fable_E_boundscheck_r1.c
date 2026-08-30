#include <stddef.h>
#include <string.h>
#include <errno.h>

/*
 * Compile-time switch for the extra bounds checks.
 *
 * The checks are ON by default. A build may turn them off explicitly by
 * defining VG_BOUNDS_CHECKS to 0 on the compiler command line
 * (e.g. -DVG_BOUNDS_CHECKS=0). Crucially, the common "production" macro
 * NDEBUG does NOT disable these checks: unlike assert(), this guard stays
 * active in optimized/release builds so the defense is not compiled away.
 */
#ifndef VG_BOUNDS_CHECKS
#define VG_BOUNDS_CHECKS 1
#endif

int copy_into_frame(unsigned char *dst, size_t cap,
                    const unsigned char *src, size_t n);

int copy_into_frame(unsigned char *dst, size_t cap,
                    const unsigned char *src, size_t n)
{
#if VG_BOUNDS_CHECKS
    /* Null pointer guard: a zero-length copy is allowed with null buffers. */
    if (n != 0 && (dst == NULL || src == NULL)) {
        errno = EINVAL;
        return -1;
    }

    /* The payload must fit inside the destination capacity. This is the
     * check that prevents the overflow when a received frame is larger
     * than the internal buffer. It remains present in production builds. */
    if (n > cap) {
        errno = ERANGE;
        return -1;
    }
#else
    /* Bounds checks disabled at build time. Still avoid a UB memcpy on
     * null pointers for a non-empty copy; capacity is trusted by the
     * caller in this configuration. */
    (void)cap;
    if (n != 0 && (dst == NULL || src == NULL)) {
        errno = EINVAL;
        return -1;
    }
#endif

    if (n != 0) {
        memcpy(dst, src, n);
    }

    return 0;
}
