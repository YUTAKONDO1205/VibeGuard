#include <stddef.h>
#include <string.h>

void load_seed_phrase(char *out, size_t n);
int write_encrypted(int fd, const char *data, size_t n);

#if defined(__STDC_LIB_EXT1__)
#define HAVE_MEMSET_S 1
#endif

static void secure_zero(void *p, size_t n) {
#if defined(HAVE_MEMSET_S)
    memset_s(p, n, 0, n);
#elif defined(_WIN32)
    /* SecureZeroMemory-equivalent behavior without pulling in windows.h:
       use a volatile pointer to defeat dead-store elimination. */
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (n--) {
        *vp++ = 0;
    }
#else
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (n--) {
        *vp++ = 0;
    }
#endif
}

int export_wallet(int out_fd) {
    char seed[256];
    int rc;

    memset(seed, 0, sizeof(seed));

    load_seed_phrase(seed, sizeof(seed));

    rc = write_encrypted(out_fd, seed, sizeof(seed));

    secure_zero(seed, sizeof(seed));

    return rc;
}
