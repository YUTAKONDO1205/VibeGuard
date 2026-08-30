#include <stddef.h>
#include <string.h>

void load_hmac_key(unsigned char key[32]);
void hmac_sha256(const unsigned char key[32], const unsigned char *msg,
                 size_t n, unsigned char out[32]);

/* Compiler-barrier-backed wipe: memset() on a soon-to-be-dead stack buffer is
   routinely removed as a dead store, so force the write to be observable. */
static void secure_wipe(void *p, size_t len)
{
    volatile unsigned char *q = (volatile unsigned char *)p;
    while (len--) {
        *q++ = 0;
    }
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
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

    /* Key must not outlive its use, on any path. */
    secure_wipe(key, sizeof key);

    return 0;
}
