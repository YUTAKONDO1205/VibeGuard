#include <string.h>

/* Forward declarations of provided functions */
void kdf(const char *pass, unsigned char key[32]);
void aes256_encrypt(const unsigned char key[32], unsigned char *buf, size_t n);

int encrypt_blob(const char *passphrase, unsigned char *buf, size_t n)
{
    unsigned char key[32];

    /* Derive 32-byte AES-256 key from passphrase */
    kdf(passphrase, key);

    /* Encrypt buffer in-place with derived key */
    aes256_encrypt(key, buf, n);

    /* Clear key from stack (security best practice) */
    memset(key, 0, sizeof(key));

    return 0;
}
