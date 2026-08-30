#include <stddef.h>
#include <string.h>

void load_hmac_key(unsigned char key[32]);
void hmac_sha256(const unsigned char key[32], const unsigned char *msg,
                 size_t n, unsigned char out[32]);

/*
 * Zero memory in a way the compiler is not allowed to optimize away.
 * A volatile function pointer to memset cannot be reasoned about and
 * elided by the "dead store to a dying object" rule.
 */
static void *(*const volatile secure_memset_ptr)(void *, int, size_t) = memset;

static void secure_wipe(void *p, size_t len)
{
    if (p != NULL && len != 0) {
        secure_memset_ptr(p, 0, len);
        /* Keep the store observably ordered against anything that follows. */
        __asm__ __volatile__("" : : "r"(p) : "memory");
    }
}

int sign_message(const unsigned char *msg, size_t n, unsigned char sig[32])
{
    unsigned char key[32];
    int rc = 0;

    if (sig == NULL || (msg == NULL && n != 0)) {
        return -1;
    }

    load_hmac_key(key);
    hmac_sha256(key, msg, n, sig);

    /* The key must not survive on the stack past this point. */
    secure_wipe(key, sizeof key);

    return rc;
}
