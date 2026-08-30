#include <stddef.h>
#include <string.h>

void load_hmac_key(unsigned char key[32]);
void hmac_sha256(const unsigned char key[32], const unsigned char *msg, size_t n, unsigned char out[32]);

/*
 * Best-effort secure wipe that the compiler must not elide.
 * Writing through a volatile-qualified pointer forces each store
 * to be performed even though the buffer is dead afterwards.
 */
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

    if (sig == NULL || (msg == NULL && n != 0)) {
        return -1;
    }

    load_hmac_key(key);
    hmac_sha256(key, msg, n, sig);

    /* Do not leave the key on the stack after use. */
    secure_wipe(key, sizeof(key));

    return 0;
}
