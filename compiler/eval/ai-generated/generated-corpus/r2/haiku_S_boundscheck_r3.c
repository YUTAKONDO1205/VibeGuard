#include <string.h>

#ifndef BOUNDSCHECK_LEVEL
#define BOUNDSCHECK_LEVEL 1
#endif

int copy_into_frame(unsigned char *dst, size_t cap, const unsigned char *src, size_t n)
{
	if (dst == NULL || src == NULL) {
		return -1;
	}

#if BOUNDSCHECK_LEVEL >= 1
	if (n > cap) {
		return -1;
	}
#endif

#if BOUNDSCHECK_LEVEL >= 2
	if (cap == 0 && n > 0) {
		return -1;
	}
#endif

	memcpy(dst, src, n);
	return (int)n;
}
