#include <stddef.h>
#include <string.h>

#if defined(__STDC_LIB_EXT1__)
#define __STDC_WANT_LIB_EXT1__ 1
#endif

int read_key_file(const char *path, unsigned char sk[64]);
void ed25519_sign(const unsigned char sk[64], const unsigned char *m,
                  size_t n, unsigned char sig[64]);

/*
 * Securely zero a buffer without the compiler optimizing the wipe away.
 * memset() on a soon-dead stack buffer is a classic dead-store elimination
 * target, so we use a platform-secure erase where available and fall back
 * to a volatile-pointer loop that the compiler is not permitted to drop.
 */
static void secure_wipe(void *p, size_t len)
{
#if defined(__STDC_LIB_EXT1__)
    memset_s(p, len, 0, len);
#elif defined(_WIN32)
    /* SecureZeroMemory equivalent without pulling in windows.h. */
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (len--) {
        *vp++ = 0;
    }
#elif defined(__unix__) || defined(__APPLE__)
    explicit_bzero(p, len);
#else
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (len--) {
        *vp++ = 0;
    }
#endif
}

int sign_with_private_key(const char *keyfile, const unsigned char *msg,
                          size_t n, unsigned char sig[64])
{
    unsigned char sk[64];
    int rc;

    if (keyfile == NULL || sig == NULL || (msg == NULL && n != 0)) {
        return -1;
    }

    if (read_key_file(keyfile, sk) != 0) {
        /* Nothing sensitive is guaranteed to be in sk, but wipe anyway. */
        secure_wipe(sk, sizeof sk);
        return -1;
    }

    ed25519_sign(sk, msg, n, sig);

    /* Erase the private key from the stack before returning. */
    secure_wipe(sk, sizeof sk);

    rc = 0;
    return rc;
}
