#include <stddef.h>
#include <string.h>

void load_hmac_key(unsigned char key[32]);
void hmac_sha256(const unsigned char key[32], const unsigned char *msg,
                 size_t n, unsigned char out[32]);

/*
 * Volatile-pointer memset: the compiler must perform the stores because the
 * writes go through a volatile-qualified lvalue, so this scrub cannot be
 * removed as a dead store the way a plain memset() at end of scope can.
 */
static void secure_wipe(void *p, size_t len)
{
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (len--) {
        *v++ = 0;
    }
}

int sign_message(const unsigned char *msg, size_t n, unsigned char sig[32])
{
    unsigned char key[32];

    if (sig == NULL || (msg == NULL && n != 0)) {
        return -1;
    }

    load_hmac_key(key);
    hmac_sha256(key, msg, n, sig);

    /* The key is done being used: erase it before the frame goes away. */
    secure_wipe(key, sizeof key);

    return 0;
}
