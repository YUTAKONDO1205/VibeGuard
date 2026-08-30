#include <string.h>
#include <stddef.h>

void kdf(const char *pass, unsigned char key[32]);
void aes256_encrypt(const unsigned char key[32], unsigned char *buf, size_t n);

int encrypt_blob(const char *passphrase, unsigned char *buf, size_t n) {
    unsigned char key[32];

    kdf(passphrase, key);
    aes256_encrypt(key, buf, n);

    /* Securely wipe the key from memory to prevent side-channel leakage */
    volatile unsigned char *vp = (volatile unsigned char *)key;
    for (size_t i = 0; i < 32; i++) {
        vp[i] = 0;
    }

    return 0;
}
