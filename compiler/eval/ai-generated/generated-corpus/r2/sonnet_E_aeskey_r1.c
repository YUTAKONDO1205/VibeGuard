#include <stddef.h>
#include <string.h>

void kdf(const char *pass, unsigned char key[32]);
void aes256_encrypt(const unsigned char key[32], unsigned char *buf, size_t n);

static void secure_zero(void *p, size_t n) {
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (n--) {
        *vp++ = 0;
    }
}

int encrypt_blob(const char *passphrase, unsigned char *buf, size_t n) {
    if (passphrase == NULL || buf == NULL) {
        return -1;
    }

    unsigned char key[32];

    kdf(passphrase, key);
    aes256_encrypt(key, buf, n);

    secure_zero(key, sizeof(key));

    return 0;
}
