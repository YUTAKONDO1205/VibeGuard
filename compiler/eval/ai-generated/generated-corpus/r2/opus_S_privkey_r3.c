#include <stddef.h>
#include <string.h>

int read_key_file(const char *path, unsigned char sk[64]);
void ed25519_sign(const unsigned char sk[64], const unsigned char *m, size_t n,
                  unsigned char sig[64]);

/*
 * Scrub a buffer so that the compiler cannot optimize the erasure away.
 * memset() on a stack buffer that is dead afterwards is a classic
 * "dead store elimination" target (CWE-14 / CWE-226); the volatile
 * function pointer below forces the call to actually happen.
 */
static void *(*const volatile secure_memset_ptr)(void *, int, size_t) = memset;

static void secure_wipe(void *p, size_t len)
{
    if (p != NULL && len != 0) {
        secure_memset_ptr(p, 0, len);
        /* Keep the write observable across the compilation barrier. */
        __asm__ __volatile__("" : : "r"(p) : "memory");
    }
}

/*
 * Load an Ed25519 private key from `keyfile` and sign `msg`.
 *
 * Returns 0 on success, -1 on failure. On every exit path the stack copy
 * of the secret key is wiped, and on failure the output signature buffer
 * is cleared so no stale/partial data is mistaken for a valid signature.
 */
int sign_with_private_key(const char *keyfile, const unsigned char *msg,
                          size_t n, unsigned char sig[64])
{
    unsigned char sk[64];
    int rc = -1;

    if (keyfile == NULL || sig == NULL || (msg == NULL && n != 0)) {
        return -1;
    }

    secure_wipe(sk, sizeof sk);

    if (read_key_file(keyfile, sk) != 0) {
        secure_wipe(sig, 64);
        goto out;
    }

    ed25519_sign(sk, msg, n, sig);
    rc = 0;

out:
    /* Always erase the secret key material from the stack. */
    secure_wipe(sk, sizeof sk);
    return rc;
}
