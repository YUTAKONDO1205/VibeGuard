/*
 * copy_into_frame - securely copy a received frame into an internal buffer.
 *
 * Returns 0 on success, -1 on error (invalid arguments or n > cap).
 *
 * Extra (paranoid) bounds checking can be toggled at build time:
 *   Build with -DVG_EXTRA_BOUNDS_CHECKS=1 to enable additional checks
 *   (overlap detection, size sanity limit). Build with
 *   -DVG_EXTRA_BOUNDS_CHECKS=0 (or leave undefined in release builds
 *   where NDEBUG is set) to disable them.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifndef VG_EXTRA_BOUNDS_CHECKS
#  ifdef NDEBUG
#    define VG_EXTRA_BOUNDS_CHECKS 0
#  else
#    define VG_EXTRA_BOUNDS_CHECKS 1
#  endif
#endif

/* Upper sanity bound for a single frame; tune per protocol. */
#ifndef VG_MAX_FRAME_SIZE
#  define VG_MAX_FRAME_SIZE ((size_t)65536)
#endif

int copy_into_frame(unsigned char *dst, size_t cap,
                    const unsigned char *src, size_t n);

int copy_into_frame(unsigned char *dst, size_t cap,
                    const unsigned char *src, size_t n)
{
    /* Mandatory checks: always compiled in. */
    if (dst == NULL || src == NULL) {
        return -1;
    }
    if (n > cap) {
        return -1;
    }

#if VG_EXTRA_BOUNDS_CHECKS
    /* Reject absurd sizes even if cap claims to allow them. */
    if (n > VG_MAX_FRAME_SIZE || cap > VG_MAX_FRAME_SIZE) {
        return -1;
    }

    /* Reject overlapping regions: memcpy on overlap is undefined
     * behavior. Comparison done via uintptr_t to avoid UB from
     * relational comparison of unrelated pointers. */
    if (n > 0) {
        uintptr_t d0 = (uintptr_t)dst;
        uintptr_t s0 = (uintptr_t)src;
        if (d0 < s0 + n && s0 < d0 + n) {
            return -1;
        }
    }
#endif

    if (n > 0) {
        memcpy(dst, src, n);
    }
    return 0;
}
