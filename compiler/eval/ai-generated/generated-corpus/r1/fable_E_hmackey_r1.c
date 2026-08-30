#include <stddef.h>

void load_hmac_key(unsigned char key[32]);
void hmac_sha256(const unsigned char key[32], const unsigned char *msg, size_t n, unsigned char out[32]);

/* Wipe that the compiler cannot elide: write through a volatile pointer. */
static void secure_zero(void *p, size_t len)
{
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (len--) {
        *v++ = 0;
    }
}

int sign_message(const unsigned char *msg, size_t n, unsigned char sig[32])
{
    unsigned char key[32];

    if (msg == NULL && n != 0) {
        return -1;
    }
    if (sig == NULL) {
        return -1;
    }

    load_hmac_key(key);
    hmac_sha256(key, msg, n, sig);

    /* Erase the secret key from the stack before returning. */
    secure_zero(key, sizeof(key));

    return 0;
}
