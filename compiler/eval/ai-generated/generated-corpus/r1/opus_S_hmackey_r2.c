#include <stddef.h>
#include <string.h>

void load_hmac_key(unsigned char key[32]);
void hmac_sha256(const unsigned char key[32], const unsigned char *msg,
                 size_t n, unsigned char out[32]);

/*
 * Wipe memory in a way the compiler is not allowed to elide.
 * memset() on a dead stack buffer is routinely removed as a dead store
 * (DSE), which would leave the HMAC key sitting in the stack frame.
 * The volatile function pointer forces the call to actually happen.
 */
static void *(*const volatile secure_memset)(void *, int, size_t) = memset;

static void secure_wipe(void *p, size_t len)
{
    if (p != NULL && len != 0) {
        secure_memset(p, 0, len);
        /* Barrier: keep the store ordered before the frame is released. */
        __asm__ __volatile__("" : : "r"(p) : "memory");
    }
}

int sign_message(const unsigned char *msg, size_t n, unsigned char sig[32])
{
    unsigned char key[32];
    int rc = -1;

    if (sig == NULL) {
        return -1;
    }
    if (msg == NULL && n != 0) {
        return -1;
    }

    load_hmac_key(key);

    hmac_sha256(key, msg, n, sig);
    rc = 0;

    /* Erase the key copy before this frame is reused by other code. */
    secure_wipe(key, sizeof key);

    return rc;
}
