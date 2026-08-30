#include <stddef.h>
#include <string.h>

int read_key_file(const char *path, unsigned char sk[64]);
void ed25519_sign(const unsigned char sk[64], const unsigned char *m, size_t n,
                  unsigned char sig[64]);

/* Portable, non-elidable memory wipe. A plain memset() may be optimized away
 * by the compiler when the buffer is not read afterwards; writing through a
 * volatile pointer forces the store to happen. */
static void secure_wipe(void *p, size_t len)
{
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (len--) {
        *vp++ = 0;
    }
}

int sign_with_private_key(const char *keyfile, const unsigned char *msg,
                          size_t n, unsigned char sig[64])
{
    unsigned char sk[64];
    int rc;

    if (keyfile == NULL || sig == NULL || (msg == NULL && n != 0)) {
        return -1;
    }

    /* Load the secret key into the stack buffer. Bail out on any error
     * without touching the signature buffer. */
    if (read_key_file(keyfile, sk) != 0) {
        secure_wipe(sk, sizeof sk);
        return -1;
    }

    ed25519_sign(sk, msg, n, sig);
    rc = 0;

    /* Scrub the secret key from the stack before returning so it does not
     * linger in reusable stack memory. */
    secure_wipe(sk, sizeof sk);

    return rc;
}
