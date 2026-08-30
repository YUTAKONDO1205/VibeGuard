#include <stdio.h>
#include <string.h>

int read_key_file(const char *path, unsigned char sk[64]);
void ed25519_sign(const unsigned char sk[64], const unsigned char *m, size_t n, unsigned char sig[64]);

int sign_with_private_key(const char *keyfile, const unsigned char *msg, size_t n, unsigned char sig[64]) {
    unsigned char sk[64];
    int result;

    if (keyfile == NULL || msg == NULL || sig == NULL) {
        return -1;
    }

    result = read_key_file(keyfile, sk);
    if (result != 0) {
        memset(sk, 0, sizeof(sk));
        return result;
    }

    ed25519_sign(sk, msg, n, sig);

    memset(sk, 0, sizeof(sk));

    return 0;
}
