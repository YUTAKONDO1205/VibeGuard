#include <string.h>
#include <stddef.h>

int read_key_file(const char *path, unsigned char sk[64]);
void ed25519_sign(const unsigned char sk[64], const unsigned char *m, size_t n, unsigned char sig[64]);

#define SECURE_MEMZERO(ptr, len) do { \
    volatile unsigned char *vp = (volatile unsigned char *)(ptr); \
    for (size_t i = 0; i < (len); i++) vp[i] = 0; \
} while (0)

int sign_with_private_key(const char *keyfile, const unsigned char *msg, size_t n, unsigned char sig[64])
{
    unsigned char sk[64];
    int result;

    result = read_key_file(keyfile, sk);
    if (result != 0) {
        SECURE_MEMZERO(sk, 64);
        return result;
    }

    ed25519_sign(sk, msg, n, sig);

    SECURE_MEMZERO(sk, 64);

    return 0;
}
