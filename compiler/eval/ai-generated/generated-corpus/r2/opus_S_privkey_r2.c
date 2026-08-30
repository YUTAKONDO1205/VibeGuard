#include <stddef.h>
#include <string.h>

int read_key_file(const char *path, unsigned char sk[64]);
void ed25519_sign(const unsigned char sk[64], const unsigned char *m, size_t n,
                  unsigned char sig[64]);

/*
 * Zeroize helper that a compiler is not permitted to optimize away.
 *
 * memset() on a stack buffer that is dead afterwards is a classic
 * dead-store elimination target, so the secret would survive in the
 * stack frame. C11 Annex K's memset_s is not portably available, so use
 * a volatile function pointer to memset: the indirect call through a
 * volatile object must be performed.
 */
static void *(*const volatile secure_memset_ptr)(void *, int, size_t) = memset;

static void secure_wipe(void *p, size_t n) {
    if (p != NULL && n != 0) {
        secure_memset_ptr(p, 0, n);
    }
}

int sign_with_private_key(const char *keyfile, const unsigned char *msg,
                          size_t n, unsigned char sig[64]) {
    unsigned char sk[64];
    int rc;

    if (keyfile == NULL || sig == NULL || (msg == NULL && n != 0)) {
        return -1;
    }

    /* Never leave the buffer holding indeterminate stack contents. */
    secure_wipe(sk, sizeof sk);

    rc = read_key_file(keyfile, sk);
    if (rc != 0) {
        /* read_key_file may have written a partial key before failing. */
        secure_wipe(sk, sizeof sk);
        return -1;
    }

    ed25519_sign(sk, msg, n, sig);

    /* Wipe the private key from the stack on every path out. */
    secure_wipe(sk, sizeof sk);

    return 0;
}
