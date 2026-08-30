#include <string.h>

void kdf(const char *pass, unsigned char key[32]);
void aes256_encrypt(const unsigned char key[32], unsigned char *buf, size_t n);

int encrypt_blob(const char *passphrase, unsigned char *buf, size_t n) {
    unsigned char key[32];

    if (passphrase == NULL || buf == NULL) {
        return -1;
    }

    kdf(passphrase, key);
    aes256_encrypt(key, buf, n);

    memset(key, 0, 32);

    return 0;
}
