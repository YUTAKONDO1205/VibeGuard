#include <stddef.h>
#include <stdint.h>

int read_key_file(const char *path, unsigned char sk[64]);
void ed25519_sign(const unsigned char sk[64], const unsigned char *m, size_t n, unsigned char sig[64]);

int sign_with_private_key(const char *keyfile, const unsigned char *msg, size_t n, unsigned char sig[64]) {
    unsigned char sk[64];

    int ret = read_key_file(keyfile, sk);
    if (ret != 0) {
        return ret;
    }

    ed25519_sign(sk, msg, n, sig);

    return 0;
}
