/*
 * copy_into_frame: copy a received frame into an internal buffer.
 *
 * Build configuration:
 *   -DFRAME_EXTRA_BOUNDS_CHECKS=1   enable the additional (defensive,
 *                                   redundant) boundary checks.
 *   -DFRAME_EXTRA_BOUNDS_CHECKS=0   disable them.
 * Default: enabled.
 *
 * SECURITY NOTE: the *mandatory* bounds check below is NOT part of the
 * configurable section. It is always compiled in, no matter how the
 * project is configured, because memory safety must never depend on a
 * build flag. The configurable part only adds redundant sanity checks
 * (overlap detection, pointer sanity, trap-on-violation) useful in
 * debug/hardened builds.
 */

#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>

#ifndef FRAME_EXTRA_BOUNDS_CHECKS
#define FRAME_EXTRA_BOUNDS_CHECKS 1
#endif

#if FRAME_EXTRA_BOUNDS_CHECKS
#include <assert.h>
#endif

/* Hard upper limit on a single frame; adjust to the protocol in use. */
#ifndef FRAME_MAX_LEN
#define FRAME_MAX_LEN ((size_t)65535u)
#endif

int copy_into_frame(unsigned char *dst, size_t cap,
                    const unsigned char *src, size_t n);

int copy_into_frame(unsigned char *dst, size_t cap,
                    const unsigned char *src, size_t n)
{
    /* --- Always-on validation (never compiled out) --------------- */

    if (dst == NULL || src == NULL) {
        errno = EINVAL;
        return -1;
    }

    /* A zero-length copy is legal, but memcpy() with NULL is not;
       pointers were already checked, so just succeed early. */
    if (n == 0) {
        return 0;
    }

    /* Protocol-level ceiling: reject absurd lengths before any
       arithmetic on them is used for sizing. */
    if (n > FRAME_MAX_LEN) {
        errno = EMSGSIZE;
        return -1;
    }

    /* THE bounds check. Written as n > cap (no addition, no
       subtraction) so it cannot itself overflow. Truncation is not
       performed: a frame that does not fit is an error, silently
       copying a prefix would desynchronise the protocol. */
    if (n > cap) {
        errno = ERANGE;
        return -1;
    }

    /* --- Configurable, redundant hardening ----------------------- */
#if FRAME_EXTRA_BOUNDS_CHECKS
    {
        uintptr_t d = (uintptr_t)dst;
        uintptr_t s = (uintptr_t)src;

        /* Re-derive the same conclusion a different way; if the two
           disagree, memory is not in the state we believe it is. */
        if (cap - n > cap) {          /* impossible unless n > cap   */
            errno = ERANGE;
            return -1;
        }

        /* memcpy() has undefined behaviour on overlapping regions.
           Detect the overlap instead of relying on luck. Comparing
           unrelated pointers is itself implementation-defined, hence
           the conversion to uintptr_t. */
        if ((d < s && d + n > s) || (s < d && s + n > d) || d == s) {
            errno = EINVAL;
            return -1;
        }

        /* Address-space wraparound of the destination range. */
        if (d + n < d) {
            errno = EOVERFLOW;
            return -1;
        }

        assert(n <= cap);
    }
#endif /* FRAME_EXTRA_BOUNDS_CHECKS */

    memcpy(dst, src, n);

    /* Leave no stale bytes from a previous, longer frame in the
       unused tail of the buffer. */
    if (cap > n) {
        memset(dst + n, 0, cap - n);
    }

    return 0;
}
