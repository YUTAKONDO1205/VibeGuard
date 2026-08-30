/*
 * copy_into_frame: copy a received frame into an internal buffer.
 *
 * Build configuration:
 *   -DFRAME_EXTRA_BOUNDS_CHECKS=1  (default) enable the additional,
 *                                  defence-in-depth bounds checks.
 *   -DFRAME_EXTRA_BOUNDS_CHECKS=0  disable ONLY the redundant extra checks.
 *
 * Security note: the mandatory checks below (NULL, overlap, n <= cap) are
 * ALWAYS compiled in.  Only diagnostics/redundant assertions are switched off
 * by the build configuration, so a misconfigured build can never turn this
 * function into an unchecked memcpy.
 */

#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

#ifndef FRAME_EXTRA_BOUNDS_CHECKS
#define FRAME_EXTRA_BOUNDS_CHECKS 1
#endif

/* Hard upper limit on a single frame; adjust to the link MTU if needed. */
#ifndef FRAME_MAX_LEN
#define FRAME_MAX_LEN ((size_t)65535u)
#endif

int copy_into_frame(unsigned char *dst, size_t cap,
                    const unsigned char *src, size_t n);

int copy_into_frame(unsigned char *dst, size_t cap,
                    const unsigned char *src, size_t n)
{
    /* --- Mandatory checks: always compiled in. --- */

    if (dst == NULL || src == NULL) {
        return -EINVAL;
    }

    /* Zero-length copy is a well-defined no-op (memcpy with NULL would be UB,
     * but NULL is already rejected above). */
    if (n == 0u) {
        return 0;
    }

    /* Capacity check.  Written as n > cap (no arithmetic) so it cannot
     * overflow or be folded away by the compiler. */
    if (n > cap) {
        return -EMSGSIZE;
    }

    /* Reject overlapping regions: memcpy requires non-overlapping buffers.
     * Compare as uintptr_t; pointer comparison across distinct objects is
     * unspecified in C, integer comparison is not. */
    {
        uintptr_t d = (uintptr_t)dst;
        uintptr_t s = (uintptr_t)src;
        if ((d < s && d + (uintptr_t)n > s) ||
            (s < d && s + (uintptr_t)n > d) ||
            d == s) {
            return -EINVAL;
        }
    }

#if FRAME_EXTRA_BOUNDS_CHECKS
    /* --- Additional (defence-in-depth) checks, build-configurable. --- */

    /* Sanity bound on the declared capacity and length: a value larger than
     * the protocol maximum indicates a corrupted length field or an
     * attacker-supplied size, not a legitimate frame. */
    if (cap > FRAME_MAX_LEN || n > FRAME_MAX_LEN) {
        return -EINVAL;
    }

    /* Guard against a length that was produced by unsigned wraparound
     * elsewhere (e.g. header_len - payload_len underflow). */
    if (n > (SIZE_MAX / 2u) || cap > (SIZE_MAX / 2u)) {
        return -EINVAL;
    }

    /* Re-verify that dst..dst+n does not wrap the address space. */
    if ((uintptr_t)dst > UINTPTR_MAX - (uintptr_t)n ||
        (uintptr_t)src > UINTPTR_MAX - (uintptr_t)n) {
        return -EINVAL;
    }
#endif /* FRAME_EXTRA_BOUNDS_CHECKS */

    memcpy(dst, src, n);

    /* Do not leave stale bytes from a previous, longer frame in the tail of
     * the buffer; they could be disclosed by a later over-read of dst. */
    if (cap > n) {
        memset(dst + n, 0, cap - n);
    }

    return 0;
}
