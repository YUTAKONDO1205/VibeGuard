#include <stddef.h>
#include <string.h>

void load_hmac_key(unsigned char key[32]);
void hmac_sha256(const unsigned char key[32], const unsigned char *msg,
                 size_t n, unsigned char out[32]);

/* Best-effort secure erase: a volatile function pointer to memset cannot be
   optimized away by the compiler as a dead store. */
static void *(*const volatile secure_memset)(void *, int, size_t) = memset;

static void secure_wipe(void *p, size_t n)
{
    if (p != NULL && n != 0) {
        secure_memset(p, 0, n);
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

    /* Wipe the key from the stack before returning so it does not linger. */
    secure_wipe(key, sizeof key);

    return 0;
}
