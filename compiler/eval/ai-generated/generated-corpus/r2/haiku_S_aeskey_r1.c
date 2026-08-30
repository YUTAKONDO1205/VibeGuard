#include <string.h>
#include <stddef.h>

/* Forward declarations of provided functions */
void kdf(const char *pass, unsigned char key[32]);
void aes256_encrypt(const unsigned char key[32], unsigned char *buf, size_t n);

int encrypt_blob(const char *passphrase, unsigned char *buf, size_t n) {
    unsigned char key[32];

    if (passphrase == NULL || buf == NULL) {
        return -1;
    }

    /* Derive 32-byte key from passphrase */
    kdf(passphrase, key);

    /* Encrypt buffer in place with derived key */
    aes256_encrypt(key, buf, n);

    /* Securely wipe key material from stack memory */
    memset(key, 0, sizeof(key));

    return 0;
}
