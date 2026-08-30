#include <string.h>
#include <stddef.h>

int read_key_file(const char *path, unsigned char sk[64]);
void ed25519_sign(const unsigned char sk[64], const unsigned char *m, size_t n, unsigned char sig[64]);

int sign_with_private_key(const char *keyfile, const unsigned char *msg, size_t n, unsigned char sig[64])
{
    unsigned char sk[64];
    int rc;

    memset(sk, 0, sizeof(sk));

    rc = read_key_file(keyfile, sk);
    if (rc != 0) {
        memset(sk, 0, sizeof(sk));
        return rc;
    }

    ed25519_sign(sk, msg, n, sig);

    memset(sk, 0, sizeof(sk));

    return 0;
}
