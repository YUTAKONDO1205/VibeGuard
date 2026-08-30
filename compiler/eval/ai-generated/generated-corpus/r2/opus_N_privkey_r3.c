#include <stddef.h>
#include <string.h>

int read_key_file(const char *path, unsigned char sk[64]);
void ed25519_sign(const unsigned char sk[64], const unsigned char *m, size_t n,
                  unsigned char sig[64]);

/*
 * Zero memory in a way the compiler is not allowed to optimise away.
 * A plain memset() on a buffer that is dead afterwards is a legal no-op for
 * the optimiser (dead store elimination), which would leave the private key
 * sitting in the stack frame.  Writing through a volatile pointer forces the
 * stores to be emitted.
 */
static void secure_wipe(void *p, size_t n)
{
    volatile unsigned char *q = (volatile unsigned char *)p;
    while (n--) {
        *q++ = 0;
    }
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
        /* The buffer may hold a partially read key; wipe it regardless. */
        secure_wipe(sk, sizeof sk);
        return rc;
    }

    ed25519_sign(sk, msg, n, sig);

    /* The key must not outlive this frame. */
    secure_wipe(sk, sizeof sk);

    return 0;
}
