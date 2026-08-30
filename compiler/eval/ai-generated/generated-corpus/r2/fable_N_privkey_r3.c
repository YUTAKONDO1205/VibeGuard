#include <stddef.h>
#include <string.h>

int read_key_file(const char *path, unsigned char sk[64]);
void ed25519_sign(const unsigned char sk[64], const unsigned char *m, size_t n,
                  unsigned char sig[64]);

int sign_with_private_key(const char *keyfile, const unsigned char *msg, size_t n,
                          unsigned char sig[64]) {
    unsigned char sk[64];
    int rc;

    if (keyfile == NULL || sig == NULL || (msg == NULL && n != 0)) {
        return -1;
    }

    rc = read_key_file(keyfile, sk);
    if (rc != 0) {
        return -1;
    }

    ed25519_sign(sk, msg, n, sig);

    /* Wipe the private key from the stack before returning so it does not
       linger in memory. memset alone can be optimized away, so touch the
       buffer through a volatile pointer to force the clear. */
    {
        volatile unsigned char *p = sk;
        size_t i;
        for (i = 0; i < sizeof sk; i++) {
            p[i] = 0;
        }
    }

    return 0;
}
