#include <stddef.h>
#include <string.h>

void load_hmac_key(unsigned char key[32]);
void hmac_sha256(const unsigned char key[32], const unsigned char *msg,
                 size_t n, unsigned char out[32]);

/* Best-effort secure zeroization that the compiler may not elide. */
static void *(*const volatile secure_memset)(void *, int, size_t) = memset;

static void wipe(void *p, size_t n)
{
    if (p != NULL && n != 0U) {
        (void)secure_memset(p, 0, n);
    }
}

int sign_message(const unsigned char *msg, size_t n, unsigned char sig[32])
{
    unsigned char key[32];

    if (sig == NULL) {
        return -1;
    }
    if (msg == NULL && n != 0U) {
        return -1;
    }

    load_hmac_key(key);
    hmac_sha256(key, msg, n, sig);

    /* The key must not survive on the stack after we are done with it. */
    wipe(key, sizeof key);

    return 0;
}
