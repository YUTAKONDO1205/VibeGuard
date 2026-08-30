/*
 * copy_into_frame - copy a received frame into an internal buffer.
 *
 * Build configuration:
 *   Define FRAME_EXTRA_BOUNDS_CHECKS=1 to enable the additional (defensive)
 *   boundary checks; define it to 0 (or leave it undefined and define
 *   FRAME_NDEBUG_BOUNDS) to compile them out.
 *
 * NOTE: the mandatory capacity check (n > cap) is ALWAYS compiled in.
 * Only the *extra* defensive checks are configurable.
 */

#include <stddef.h>
#include <string.h>
#include <stdint.h>

#ifndef FRAME_EXTRA_BOUNDS_CHECKS
#  ifdef NDEBUG
#    define FRAME_EXTRA_BOUNDS_CHECKS 0
#  else
#    define FRAME_EXTRA_BOUNDS_CHECKS 1
#  endif
#endif

#if FRAME_EXTRA_BOUNDS_CHECKS
#  define FRAME_EXTRA_CHECK(cond, err) do { if (!(cond)) return (err); } while (0)
#else
#  define FRAME_EXTRA_CHECK(cond, err) do { (void)0; } while (0)
#endif

/* Return codes. */
#define FRAME_OK             0
#define FRAME_ERR_NULL      -1   /* dst or src is NULL with a non-zero length */
#define FRAME_ERR_TOO_BIG   -2   /* n exceeds cap */
#define FRAME_ERR_OVERLAP   -3   /* src and dst regions overlap */
#define FRAME_ERR_RANGE     -4   /* implausible length (extra check) */

/* Upper bound used by the extra checks to reject obviously bogus lengths. */
#ifndef FRAME_MAX_LEN
#  define FRAME_MAX_LEN ((size_t)0x10000u)
#endif

int copy_into_frame(unsigned char *dst, size_t cap,
                    const unsigned char *src, size_t n);

int copy_into_frame(unsigned char *dst, size_t cap,
                    const unsigned char *src, size_t n)
{
    /* --- Always-on checks: these must never be configured away. --- */
    if (n == 0) {
        /* Nothing to copy; still reject a nonsensical destination. */
        if (dst == NULL && cap != 0) {
            return FRAME_ERR_NULL;
        }
        return FRAME_OK;
    }

    if (dst == NULL || src == NULL) {
        return FRAME_ERR_NULL;
    }

    if (n > cap) {
        return FRAME_ERR_TOO_BIG;
    }

    /* --- Extra checks: enabled/disabled by the build configuration. --- */

    /* Reject lengths beyond what any legitimate frame can be. */
    FRAME_EXTRA_CHECK(n <= FRAME_MAX_LEN, FRAME_ERR_RANGE);
    FRAME_EXTRA_CHECK(cap <= FRAME_MAX_LEN, FRAME_ERR_RANGE);

    /* memcpy has undefined behaviour on overlapping regions: detect it. */
#if FRAME_EXTRA_BOUNDS_CHECKS
    {
        const unsigned char *d0 = dst;
        const unsigned char *d1 = dst + n;
        const unsigned char *s0 = src;
        const unsigned char *s1 = src + n;
        if (d0 < s1 && s0 < d1) {
            return FRAME_ERR_OVERLAP;
        }
    }
#endif

    memcpy(dst, src, n);

    return FRAME_OK;
}
