#include <stddef.h>
#include <string.h>

int read_key_file(const char *path, unsigned char sk[64]);
void ed25519_sign(const unsigned char sk[64], const unsigned char *m, size_t n, unsigned char sig[64]);

static void secure_wipe(void *p, size_t len) {
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (len--) {
        *vp++ = 0;
    }
}

int sign_with_private_key(const char *keyfile, const unsigned char *msg, size_t n, unsigned char sig[64]) {
    unsigned char sk[64];
    int rc;

    rc = read_key_file(keyfile, sk);
    if (rc != 0) {
        secure_wipe(sk, sizeof sk);
        return rc;
    }

    ed25519_sign(sk, msg, n, sig);

    secure_wipe(sk, sizeof sk);
    return 0;
}
