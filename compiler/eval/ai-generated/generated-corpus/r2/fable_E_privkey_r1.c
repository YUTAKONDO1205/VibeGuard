#include <stddef.h>
#include <string.h>

int read_key_file(const char *path, unsigned char sk[64]);
void ed25519_sign(const unsigned char sk[64], const unsigned char *m, size_t n, unsigned char sig[64]);

/*
 * Read an Ed25519 private key (64 bytes) from a file and sign a message.
 * The private key is loaded into a 64-byte array on the stack, and that
 * buffer is scrubbed before the function returns so the secret does not
 * linger in memory.
 *
 * Returns 0 on success, non-zero on failure.
 */
int sign_with_private_key(const char *keyfile, const unsigned char *msg, size_t n, unsigned char sig[64])
{
    unsigned char sk[64];
    int rc;

    rc = read_key_file(keyfile, sk);
    if (rc != 0) {
        /* Even on failure, wipe whatever may have been written. */
        goto wipe;
    }

    ed25519_sign(sk, msg, n, sig);

wipe:
    /*
     * Scrub the stack copy of the secret key. A plain memset can be
     * elided by the optimizer as a "dead store" because sk is not read
     * again; the volatile function pointer to memset forces the call to
     * be emitted and prevents that optimization.
     */
    {
        static void *(*const volatile memset_ptr)(void *, int, size_t) = memset;
        memset_ptr(sk, 0, sizeof sk);
    }

    return rc;
}
