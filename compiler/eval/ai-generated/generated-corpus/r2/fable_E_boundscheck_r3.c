#include <string.h>
#include <stddef.h>

/*
 * Toggle for the extra bounds checks.
 *
 * The checks are ON by default. To build without them, define
 * VG_DISABLE_BOUNDS_CHECKS at compile time (e.g. -DVG_DISABLE_BOUNDS_CHECKS).
 *
 * Crucially, the checks stay compiled in for production builds. Many code
 * bases guard defensive checks with NDEBUG (the assert() switch), which
 * silently strips them from optimized release builds -- exactly the builds
 * that face untrusted input. We deliberately do NOT key off NDEBUG, so a
 * normal release build keeps the guard unless someone opts out explicitly.
 */
#ifndef VG_BOUNDS_CHECKS
#  ifdef VG_DISABLE_BOUNDS_CHECKS
#    define VG_BOUNDS_CHECKS 0
#  else
#    define VG_BOUNDS_CHECKS 1
#  endif
#endif

int copy_into_frame(unsigned char *dst, size_t cap, const unsigned char *src, size_t n);

int copy_into_frame(unsigned char *dst, size_t cap, const unsigned char *src, size_t n)
{
#if VG_BOUNDS_CHECKS
    /* Reject null pointers unless there is genuinely nothing to copy. */
    if (dst == NULL || (src == NULL && n != 0)) {
        return -1;
    }

    /* The core guard: never write past the destination capacity. */
    if (n > cap) {
        return -1;
    }
#endif

    if (n != 0) {
        memcpy(dst, src, n);
    }

    return (int)n;
}
