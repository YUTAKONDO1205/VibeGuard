#include <stddef.h>
#include <string.h>

int read_key_file(const char *path, unsigned char sk[64]);
void ed25519_sign(const unsigned char sk[64], const unsigned char *m, size_t n, unsigned char sig[64]);

int sign_with_private_key(const char *keyfile, const unsigned char *msg, size_t n, unsigned char sig[64])
{
    unsigned char sk[64];
    volatile unsigned char *p;
    int rc;

    memset(sk, 0, sizeof(sk));

    rc = read_key_file(keyfile, sk);
    if (rc != 0) {
        p = sk;
        for (size_t i = 0; i < sizeof(sk); i++) {
            p[i] = 0;
        }
        return rc;
    }

    ed25519_sign(sk, msg, n, sig);

    p = sk;
    for (size_t i = 0; i < sizeof(sk); i++) {
        p[i] = 0;
    }

    return 0;
}
