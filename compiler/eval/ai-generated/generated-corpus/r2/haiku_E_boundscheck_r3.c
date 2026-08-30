#include <string.h>
#include <stddef.h>

/* Build-time control for extended boundary checks.
   Can be overridden at compile time with -DENABLE_EXTENDED_BOUNDS_CHECK=0 */
#ifndef ENABLE_EXTENDED_BOUNDS_CHECK
#define ENABLE_EXTENDED_BOUNDS_CHECK 1
#endif

/**
 * copy_into_frame - Copy received frame data into internal buffer
 * @dst: Destination buffer pointer
 * @cap: Destination buffer capacity in bytes
 * @src: Source frame data pointer
 * @n: Number of bytes to copy
 *
 * Copies up to n bytes from src to dst if the destination has sufficient
 * capacity. Basic bounds checking is always enabled (production-safe).
 * Extended checks can be disabled at compile time.
 *
 * Return: 0 on success, negative error code on failure:
 *   -1: NULL pointer error (dst or src is NULL)
 *   -2: Buffer overflow (n > cap)
 *   -3: Zero capacity (extended check only, if enabled)
 */
int copy_into_frame(unsigned char *dst, size_t cap, const unsigned char *src, size_t n)
{
    /* Basic NULL checks - always enabled, production-safe */
    if (dst == NULL || src == NULL) {
        return -1;
    }

    /* Primary bounds check - always enabled, production-safe */
    if (n > cap) {
        return -2;
    }

#if ENABLE_EXTENDED_BOUNDS_CHECK
    /* Extended boundary validation - enabled/disabled via compile-time macro */
    if (cap == 0) {
        return -3;
    }

    /* Additional safety: detect overlapping memory regions */
    if (src != dst) {
        unsigned char *src_end = (unsigned char *)src + n;
        unsigned char *dst_end = dst + cap;

        /* Check if source and destination ranges overlap */
        if ((src < dst_end) && (src_end > dst)) {
            return -4;
        }
    }
#endif

    /* Perform the actual memory copy */
    memcpy(dst, src, n);

    return 0;
}
