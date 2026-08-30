/*
 * copy_into_frame - copy a received frame into an internal buffer.
 *
 * Bounds checking policy:
 *   - The mandatory checks below are plain `if` statements with no macro
 *     guard.  They are part of the function's control flow and therefore
 *     survive every build configuration, including -DNDEBUG and any
 *     optimization level.  assert() is deliberately NOT used for them,
 *     because assert() compiles to nothing when NDEBUG is defined and the
 *     defence would silently disappear in a production build.
 *   - VG_EXTRA_FRAME_CHECKS selects *additional*, more expensive diagnostic
 *     checks (overlap detection, poison-fill of the unused tail).  This is
 *     the build-configurable part.  It defaults to enabled; a build may set
 *     -DVG_EXTRA_FRAME_CHECKS=0 to drop only these extras.  Turning it off
 *     never removes a check that is needed for memory safety.
 */

#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

#ifndef VG_EXTRA_FRAME_CHECKS
#define VG_EXTRA_FRAME_CHECKS 1
#endif

/* Poison byte written into the unused tail when extra checks are enabled. */
#define VG_FRAME_POISON 0xA5u

int copy_into_frame(unsigned char *dst, size_t cap,
                    const unsigned char *src, size_t n);

int copy_into_frame(unsigned char *dst, size_t cap,
                    const unsigned char *src, size_t n)
{
    /* --- Mandatory checks: always compiled in. --- */

    if (dst == NULL || src == NULL) {
        return -EINVAL;
    }

    /* A zero-length copy is legal only if the pointers are valid; nothing
     * is written.  memcpy() with n == 0 is well defined here but we return
     * early to keep the poison-fill path below simple. */
    if (n == 0) {
#if VG_EXTRA_FRAME_CHECKS
        if (cap > 0) {
            memset(dst, VG_FRAME_POISON, cap);
        }
#endif
        return 0;
    }

    /* The core bound: the frame must fit in the destination buffer.
     * Written as `n > cap` (not `cap - n < 0` or pointer arithmetic) so
     * there is no unsigned wraparound and no undefined pointer overflow
     * for the compiler to exploit or elide. */
    if (n > cap) {
        return -EMSGSIZE;
    }

    /* --- Optional, build-configurable extra checks. --- */
#if VG_EXTRA_FRAME_CHECKS
    {
        /* Overlap detection: memcpy() has undefined behaviour on
         * overlapping regions.  Compare as uintptr_t to avoid comparing
         * unrelated pointers with < / >, which is itself UB. */
        uintptr_t d = (uintptr_t)dst;
        uintptr_t s = (uintptr_t)src;

        if ((d < s && d + n > s) || (s < d && s + n > d) || d == s) {
            return -EINVAL;
        }
    }
#endif

    memcpy(dst, src, n);

#if VG_EXTRA_FRAME_CHECKS
    /* Fill the remainder of the buffer with a poison pattern so that stale
     * bytes from a previous, longer frame cannot be mistaken for payload. */
    if (cap > n) {
        memset(dst + n, VG_FRAME_POISON, cap - n);
    }
#endif

    /* Number of bytes copied; fits in int only if it fits.  Report the
     * count safely: callers that need a size_t already know `n`. */
    return (n <= (size_t)INT32_MAX) ? (int)n : -EOVERFLOW;
}
