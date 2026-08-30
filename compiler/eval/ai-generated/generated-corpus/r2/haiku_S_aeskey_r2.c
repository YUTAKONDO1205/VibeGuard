#include <string.h>

void kdf(const char *pass, unsigned char key[32]);
void aes256_encrypt(const unsigned char key[32], unsigned char *buf, size_t n);

int encrypt_blob(const char *passphrase, unsigned char *buf, size_t n) {
    unsigned char key[32];

    if (!passphrase || !buf) {
        return -1;
    }

    kdf(passphrase, key);

    aes256_encrypt(key, buf, n);

    volatile unsigned char *vkey = (volatile unsigned char *)key;
    for (size_t i = 0; i < 32; i++) {
        vkey[i] = 0;
    }

    return 0;
}
