#include <stddef.h>
#include <string.h>

void load_hmac_key(unsigned char key[32]);
void hmac_sha256(const unsigned char key[32], const unsigned char *msg,
                 size_t n, unsigned char out[32]);

/* Volatile-pointer memset: cannot be elided as a dead store by the
   optimizer, unlike a plain memset() on a soon-to-die stack object. */
static void secure_wipe(void *p, size_t len)
{
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (len--) {
        *vp++ = 0;
    }
}

int sign_message(const unsigned char *msg, size_t n, unsigned char sig[32])
{
    unsigned char key[32];
    int rc = 0;

    if (sig == NULL) {
        return -1;
    }
    if (msg == NULL && n != 0) {
        return -1;
    }

    load_hmac_key(key);

    hmac_sha256(key, msg, n, sig);

    /* Erase the key copy before the stack frame is released or reused. */
    secure_wipe(key, sizeof key);

    return rc;
}
