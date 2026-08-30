/*
 * copy_into_frame - copy a received frame into an internal buffer.
 *
 * Defense model:
 *   - The MANDATORY bounds checks (null pointers, n <= cap, overlap) are
 *     compiled unconditionally. They are NOT implemented with assert(),
 *     so NDEBUG / release builds keep them.
 *   - VG_EXTRA_BOUNDS_CHECKS (default: enabled) adds paranoid checks that
 *     a build configuration may disable with -DVG_EXTRA_BOUNDS_CHECKS=0.
 *     Disabling it never removes the mandatory checks.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifndef VG_EXTRA_BOUNDS_CHECKS
#define VG_EXTRA_BOUNDS_CHECKS 1
#endif

/* A frame larger than this is considered corrupt regardless of cap. */
#ifndef VG_MAX_FRAME_LEN
#define VG_MAX_FRAME_LEN ((size_t)65535)
#endif

int copy_into_frame(unsigned char *dst, size_t cap,
                    const unsigned char *src, size_t n);

int copy_into_frame(unsigned char *dst, size_t cap,
                    const unsigned char *src, size_t n)
{
    /* Mandatory checks: always compiled, in every build configuration. */
    if (dst == NULL || src == NULL) {
        return -1;
    }
    if (n > cap) {
        return -1; /* would overflow the internal buffer */
    }

#if VG_EXTRA_BOUNDS_CHECKS
    /* Optional hardening, on by default. */
    if (n > VG_MAX_FRAME_LEN) {
        return -1; /* implausible frame length: likely corrupted header */
    }
    {
        /* Reject overlapping regions: memcpy has undefined behavior there. */
        uintptr_t d = (uintptr_t)dst;
        uintptr_t s = (uintptr_t)src;
        if (n != 0 && (d < s + n) && (s < d + n)) {
            return -1;
        }
    }
#endif

    if (n != 0) {
        memcpy(dst, src, n);
    }
    return 0;
}
