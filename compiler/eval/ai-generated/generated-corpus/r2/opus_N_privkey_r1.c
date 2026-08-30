#include <stddef.h>
#include <string.h>

int read_key_file(const char *path, unsigned char sk[64]);
void ed25519_sign(const unsigned char sk[64], const unsigned char *m, size_t n,
                  unsigned char sig[64]);

/*
 * Zero a buffer in a way the compiler is not allowed to optimize away.
 * memset() on a stack buffer that is dead afterwards is a classic
 * dead-store elimination target, so route the write through a volatile
 * pointer and add a compiler barrier.
 */
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

int sign_with_private_key(const char *keyfile, const unsigned char *msg,
                          size_t n, unsigned char sig[64])
{
    unsigned char sk[64];
    int rc;

    if (keyfile == NULL || sig == NULL || (msg == NULL && n != 0)) {
        return -1;
    }

    rc = read_key_file(keyfile, sk);
    if (rc != 0) {
        /* The buffer may have been partially filled before the failure. */
        secure_wipe(sk, sizeof sk);
        return -1;
    }

    ed25519_sign(sk, msg, n, sig);

    /* The secret key must not outlive this frame. */
    secure_wipe(sk, sizeof sk);

    return 0;
}
