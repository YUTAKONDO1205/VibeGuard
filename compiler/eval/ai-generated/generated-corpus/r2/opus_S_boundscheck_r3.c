/*
 * copy_into_frame: copy a received frame into an internal buffer.
 *
 * Build configuration:
 *   -DFRAME_EXTRA_BOUNDS_CHECKS=1  (default) enable the additional
 *                                  defensive/diagnostic checks.
 *   -DFRAME_EXTRA_BOUNDS_CHECKS=0  disable ONLY the additional checks.
 *
 * The mandatory, memory-safety-critical checks below are NEVER compiled
 * out: disabling them would turn a configuration switch into a buffer
 * overflow. Only redundant/diagnostic checking is configurable.
 */

#include <stddef.h>
#include <string.h>
#include <errno.h>

#ifndef FRAME_EXTRA_BOUNDS_CHECKS
#define FRAME_EXTRA_BOUNDS_CHECKS 1
#endif

/* Optional upper limit used only by the extra checks. */
#ifndef FRAME_MAX_LEN
#define FRAME_MAX_LEN ((size_t)65535u)
#endif

#if FRAME_EXTRA_BOUNDS_CHECKS
#include <stdio.h>
#define FRAME_EXTRA_CHECK(cond, err)                                       \
    do {                                                                   \
        if (!(cond)) {                                                     \
            (void)fprintf(stderr,                                          \
                          "copy_into_frame: check failed: %s (%s:%d)\n",   \
                          #cond, __FILE__, __LINE__);                      \
            return -(err);                                                 \
        }                                                                  \
    } while (0)
#else
#define FRAME_EXTRA_CHECK(cond, err) ((void)0)
#endif

int copy_into_frame(unsigned char *dst, size_t cap,
                    const unsigned char *src, size_t n);

int copy_into_frame(unsigned char *dst, size_t cap,
                    const unsigned char *src, size_t n)
{
    /* ---- Extra (configurable) checks: diagnostics and policy limits. ---- */
    FRAME_EXTRA_CHECK(cap <= FRAME_MAX_LEN, EINVAL);
    FRAME_EXTRA_CHECK(n <= FRAME_MAX_LEN, EMSGSIZE);
    /* Overlap is undefined behaviour for memcpy; reject it when we can.
       (Pointer comparison across distinct objects is unspecified, so this
       stays in the optional tier.) */
    FRAME_EXTRA_CHECK(dst != NULL && src != NULL &&
                      (dst + (cap ? cap : 1) <= src || src + (n ? n : 1) <= dst),
                      EINVAL);

    /* ---- Mandatory checks: always compiled in. ---- */
    if (dst == NULL || src == NULL) {
        return -EFAULT;
    }
    if (n > cap) {
        /* Truncation is not silently performed: the caller must know. */
        return -EMSGSIZE;
    }
    if (n == 0) {
        return 0;
    }

    memcpy(dst, src, n);

    /* Number of bytes written, never more than cap. */
    return (int)n;
}
