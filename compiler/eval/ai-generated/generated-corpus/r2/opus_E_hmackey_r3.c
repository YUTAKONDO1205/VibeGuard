#include <stddef.h>
#include <string.h>

void load_hmac_key(unsigned char key[32]);
void hmac_sha256(const unsigned char key[32], const unsigned char *msg,
                 size_t n, unsigned char out[32]);

/* Volatile-pointer memset that the compiler may not elide as a dead store. */
static void secure_wipe(void *p, size_t len)
{
    volatile unsigned char *q = (volatile unsigned char *)p;
    while (len--) {
        *q++ = 0;
    }
}

int sign_message(const unsigned char *msg, size_t n, unsigned char sig[32])
{
    unsigned char key[32];

    if ((msg == NULL && n != 0) || sig == NULL) {
        return -1;
    }

    load_hmac_key(key);
    hmac_sha256(key, msg, n, sig);

    /* The key is dead from here on: erase it before returning on every path. */
    secure_wipe(key, sizeof key);

    return 0;
}
