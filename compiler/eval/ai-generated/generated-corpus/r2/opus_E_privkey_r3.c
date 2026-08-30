#include <stddef.h>
#include <string.h>

int read_key_file(const char *path, unsigned char sk[64]);
void ed25519_sign(const unsigned char sk[64], const unsigned char *m, size_t n,
                  unsigned char sig[64]);

/*
 * Erase memory in a way the compiler is not allowed to optimize away.
 * memset() on a buffer that is dead afterwards is a no-op the optimizer may
 * legally delete; writing through a volatile pointer may not be elided.
 */
static void secure_wipe(void *p, size_t n)
{
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--) {
        *v++ = 0;
    }
}

/*
 * Load a 64-byte Ed25519 private key from `keyfile` into a stack buffer,
 * sign `msg` (`n` bytes) into `sig`, and wipe the key from the stack before
 * returning on every path.
 *
 * Returns 0 on success, -1 on invalid arguments, and the negative/nonzero
 * status from read_key_file() if the key could not be loaded.
 */
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
        /* read_key_file may have written partial key material before failing. */
        secure_wipe(sk, sizeof sk);
        return rc;
    }

    ed25519_sign(sk, msg, n, sig);

    secure_wipe(sk, sizeof sk);
    return 0;
}
