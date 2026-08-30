#include <stddef.h>
#include <string.h>

void load_hmac_key(unsigned char key[32]);
void hmac_sha256(const unsigned char key[32], const unsigned char *msg,
                 size_t n, unsigned char out[32]);

/* Wipe that the compiler is not allowed to optimize away. */
static void *(*const volatile secure_memset_ptr)(void *, int, size_t) = memset;

static void secure_wipe(void *p, size_t len)
{
    if (p != NULL && len != 0) {
        secure_memset_ptr(p, 0, len);
        /* Barrier: keep the store from being treated as dead. */
        __asm__ __volatile__("" : : "r"(p) : "memory");
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

    /* Key must not survive on the stack past this point. */
    secure_wipe(key, sizeof key);

    return 0;
}
