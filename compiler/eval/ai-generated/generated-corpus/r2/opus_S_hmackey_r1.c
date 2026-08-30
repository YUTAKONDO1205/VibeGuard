#include <stddef.h>
#include <string.h>

void load_hmac_key(unsigned char key[32]);
void hmac_sha256(const unsigned char key[32], const unsigned char *msg,
                 size_t n, unsigned char out[32]);

/*
 * Zero memory in a way the compiler is not allowed to optimize away.
 * memset() on a buffer that is dead afterwards is a classic dead-store
 * elimination target (CWE-14 / MSC06-C), so route the write through a
 * volatile function pointer.
 */
static void *(*const volatile secure_memset_fp)(void *, int, size_t) = memset;

static void secure_wipe(void *p, size_t len)
{
    if (p != NULL && len != 0) {
        secure_memset_fp(p, 0, len);
        /* Compiler barrier: the buffer must be considered observed here. */
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

    /* Erase the key from the stack before returning, on every path. */
    secure_wipe(key, sizeof key);

    return 0;
}
