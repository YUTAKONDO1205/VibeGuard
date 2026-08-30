#include <stddef.h>
#include <string.h>

void load_hmac_key(unsigned char key[32]);
void hmac_sha256(const unsigned char key[32], const unsigned char *msg,
                 size_t n, unsigned char out[32]);

/* Best-effort secure erase: a volatile function pointer to memset keeps the
   compiler from optimizing the wipe away as a dead store. */
static void *(*const volatile secure_memset)(void *, int, size_t) = memset;

static void wipe(void *p, size_t len)
{
    if (p != NULL && len != 0) {
        secure_memset(p, 0, len);
    }
}

int sign_message(const unsigned char *msg, size_t n, unsigned char sig[32])
{
    unsigned char key[32];

    if (sig == NULL) {
        return -1;
    }
    if (msg == NULL && n != 0) {
        return -1;
    }

    load_hmac_key(key);
    hmac_sha256(key, msg, n, sig);

    wipe(key, sizeof key);

    return 0;
}
