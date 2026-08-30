#include <stddef.h>
#include <string.h>

/* Declared elsewhere */
int read_key_file(const char *path, unsigned char sk[64]);
void ed25519_sign(const unsigned char sk[64], const unsigned char *m,
                  size_t n, unsigned char sig[64]);

/*
 * Read a 64-byte Ed25519 private key from `keyfile` into a stack buffer,
 * sign `msg` (length `n`) into `sig`, then securely wipe the key buffer.
 *
 * Returns 0 on success, -1 on failure.
 */
int sign_with_private_key(const char *keyfile, const unsigned char *msg,
                          size_t n, unsigned char sig[64])
{
    unsigned char sk[64];
    int rc = -1;

    if (keyfile == NULL || sig == NULL || (msg == NULL && n != 0)) {
        return -1;
    }

    if (read_key_file(keyfile, sk) != 0) {
        /* Key was not loaded; nothing sensitive to protect, but wipe anyway. */
        goto cleanup;
    }

    ed25519_sign(sk, msg, n, sig);
    rc = 0;

cleanup:
    /*
     * Scrub the private key from the stack. memset alone can be elided by the
     * optimizer once `sk` is dead; use a volatile pointer walk so the writes
     * are observable and cannot be optimized away.
     */
    {
        volatile unsigned char *p = (volatile unsigned char *)sk;
        size_t i;
        for (i = 0; i < sizeof sk; i++) {
            p[i] = 0;
        }
    }

    return rc;
}
