/*
 * copy_into_frame - copy a received frame into an internal buffer.
 *
 * Build configuration:
 *   Define FRAME_EXTRA_BOUNDS_CHECKS=1 to enable the additional (defensive)
 *   boundary checks.  Define it to 0 to compile them out.  If it is not
 *   defined at all, the checks are enabled unless NDEBUG is set.
 *
 * NOTE: the *mandatory* capacity check (n > cap) is always compiled in.
 * Only the redundant / defence-in-depth checks are configurable.
 */

#include <stddef.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>

#ifndef FRAME_EXTRA_BOUNDS_CHECKS
#  ifdef NDEBUG
#    define FRAME_EXTRA_BOUNDS_CHECKS 0
#  else
#    define FRAME_EXTRA_BOUNDS_CHECKS 1
#  endif
#endif

/* Return codes. */
#define FRAME_OK            0
#define FRAME_EINVAL      (-1)   /* NULL pointer or otherwise bad argument */
#define FRAME_ETOOBIG     (-2)   /* n would not fit in cap                 */
#define FRAME_EOVERLAP    (-3)   /* src and dst regions overlap            */

/* Hard upper bound on a single frame; keeps sizes sane and makes the
 * overflow reasoning easy.  Adjust for the target link layer. */
#ifndef FRAME_MAX_LEN
#  define FRAME_MAX_LEN ((size_t)65535u)
#endif

int copy_into_frame(unsigned char *dst, size_t cap,
                    const unsigned char *src, size_t n);

int copy_into_frame(unsigned char *dst, size_t cap,
                    const unsigned char *src, size_t n)
{
    /* --- always-on checks ------------------------------------------- */

    if (dst == NULL) {
        return FRAME_EINVAL;
    }

    if (n == 0u) {
        /* Nothing to copy; src is allowed to be NULL in this case. */
        return FRAME_OK;
    }

    if (src == NULL) {
        return FRAME_EINVAL;
    }

    /* The capacity check itself is never optional: it is what makes the
     * memcpy below safe. */
    if (n > cap) {
        return FRAME_ETOOBIG;
    }

    /* --- configurable, additional checks ----------------------------- */

#if FRAME_EXTRA_BOUNDS_CHECKS

    /* Reject absurd sizes early (protects callers that computed cap or n
     * from untrusted length fields with wrap-around arithmetic). */
    if (cap > FRAME_MAX_LEN || n > FRAME_MAX_LEN) {
        return FRAME_EINVAL;
    }

    /* Guard against a length that cannot be represented as a signed
     * difference, which would make pointer arithmetic below undefined. */
    if (n > (size_t)PTRDIFF_MAX) {
        return FRAME_EINVAL;
    }

    /* Overlapping regions: memcpy would be undefined behaviour.  The
     * comparison is done on uintptr_t because comparing pointers into
     * unrelated objects with < / > is not defined. */
    {
        uintptr_t d = (uintptr_t)dst;
        uintptr_t s = (uintptr_t)src;

        if ((d < s + n) && (s < d + n)) {
            return FRAME_EOVERLAP;
        }
    }

#endif /* FRAME_EXTRA_BOUNDS_CHECKS */

    memcpy(dst, src, n);

    /* Zero the unused tail so no stale bytes from a previous, longer
     * frame remain readable in the internal buffer. */
    if (cap > n) {
        memset(dst + n, 0, cap - n);
    }

    return FRAME_OK;
}
