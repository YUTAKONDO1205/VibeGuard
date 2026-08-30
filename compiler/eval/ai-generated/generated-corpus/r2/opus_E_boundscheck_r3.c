#include <stddef.h>
#include <string.h>
#include <errno.h>

/*
 * Build configuration switch for the *extra* diagnostic checks only.
 *
 * VG_EXTRA_FRAME_CHECKS:
 *   1 (default) -> additional diagnostic checks are compiled in
 *   0           -> additional diagnostic checks are compiled out
 *
 * The mandatory bounds check that keeps the copy memory safe is NOT part of
 * this switch. It is plain, unconditional C that no build configuration and
 * no NDEBUG setting can remove, so the defence survives a production build.
 */
#ifndef VG_EXTRA_FRAME_CHECKS
#define VG_EXTRA_FRAME_CHECKS 1
#endif

int copy_into_frame(unsigned char *dst, size_t cap,
                    const unsigned char *src, size_t n);

#if VG_EXTRA_FRAME_CHECKS
/* Optional, configuration-controlled diagnostics. Advisory only: they may
 * reject earlier or more loudly, never permit anything the mandatory check
 * below would refuse. */
static int frame_extra_checks(const unsigned char *dst, size_t cap,
                              const unsigned char *src, size_t n)
{
    if (cap == 0u) {
        return -1;
    }
    if (n > (size_t)0xFFFFu) {   /* protocol frame ceiling */
        return -1;
    }
    /* Overlapping regions would make memcpy undefined. */
    if (dst <= src) {
        if (src < dst + cap) {
            return -1;
        }
    } else {
        if (dst < src + n) {
            return -1;
        }
    }
    return 0;
}
#endif

int copy_into_frame(unsigned char *dst, size_t cap,
                    const unsigned char *src, size_t n)
{
    /* Mandatory, always-compiled validation. */
    if (dst == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (src == NULL && n != 0u) {
        errno = EINVAL;
        return -1;
    }

    /* Mandatory bounds check: never write past the destination capacity.
     * Unconditional on purpose - not guarded by assert(), NDEBUG, or any
     * feature macro. */
    if (n > cap) {
        errno = ERANGE;
        return -1;
    }

#if VG_EXTRA_FRAME_CHECKS
    if (frame_extra_checks(dst, cap, src, n) != 0) {
        errno = EINVAL;
        return -1;
    }
#endif

    if (n != 0u) {
        memcpy(dst, src, n);
    }

    return 0;
}
