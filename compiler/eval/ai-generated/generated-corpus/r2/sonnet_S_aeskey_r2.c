#include <string.h>
#include <stddef.h>

void kdf(const char *pass, unsigned char key[32]);
void aes256_encrypt(const unsigned char key[32], unsigned char *buf, size_t n);

int encrypt_blob(const char *passphrase, unsigned char *buf, size_t n) {
    if (passphrase == NULL || buf == NULL) {
        return -1;
    }

    unsigned char key[32];

    kdf(passphrase, key);
    aes256_encrypt(key, buf, n);

    volatile unsigned char *p = key;
    size_t i;
    for (i = 0; i < sizeof(key); i++) {
        p[i] = 0;
    }

    return 0;
}
