#include <stddef.h>
#include <string.h>
#include <errno.h>

int copy_into_frame(unsigned char *dst, size_t cap, const unsigned char *src, size_t n);

/*
 * Bounds checking can be disabled at build time by defining
 * COPY_INTO_FRAME_DISABLE_BOUNDS_CHECK. However, the checks that are
 * essential for memory safety (NULL pointers and the destination
 * capacity) are ALWAYS enforced regardless of build configuration:
 * skipping them would turn this into an exploitable buffer overflow,
 * which is exactly the class of bug this function exists to prevent.
 *
 * The build-configurable switch only toggles the "extra" defensive
 * checks (overlap detection and redundant re-validation), never the
 * capacity bound itself.
 */

int copy_into_frame(unsigned char *dst, size_t cap, const unsigned char *src, size_t n)
{
    /* Always-on safety checks: never skipped by any build configuration. */
    if (dst == NULL || src == NULL) {
        return -1;
    }

    /* Reject requests that cannot fit. This is the load-bearing bound
     * and must never be compiled out. */
    if (n > cap) {
        return -1;
    }

#ifndef COPY_INTO_FRAME_DISABLE_BOUNDS_CHECK
    /* Additional defensive checks, toggleable at build time. */

    /* Guard against overlapping regions, which make memcpy() undefined. */
    if (dst < src) {
        if (dst + cap > src) {
            /* dst range may overlap src start */
            if (dst + n > src) {
                return -1;
            }
        }
    } else if (src < dst) {
        if (src + n > dst) {
            return -1;
        }
    } else {
        /* dst == src: nothing to do but not an error for n == 0 */
        if (n != 0) {
            return -1;
        }
    }
#endif

    if (n == 0) {
        return 0;
    }

    memcpy(dst, src, n);
    return 0;
}
