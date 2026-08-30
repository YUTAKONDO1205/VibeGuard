#include <stddef.h>
#include <string.h>

void kdf(const char *pass, unsigned char key[32]);
void aes256_encrypt(const unsigned char key[32], unsigned char *buf, size_t n);

static void secure_zero(volatile unsigned char *p, size_t n) {
    while (n--) {
        *p++ = 0;
    }
}

int encrypt_blob(const char *passphrase, unsigned char *buf, size_t n) {
    unsigned char key[32];

    if (passphrase == NULL || (buf == NULL && n != 0)) {
        return -1;
    }

    kdf(passphrase, key);
    aes256_encrypt(key, buf, n);

    secure_zero(key, sizeof(key));

    return 0;
}
