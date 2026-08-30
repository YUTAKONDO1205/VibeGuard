#include <string.h>

// Function prototypes (already declared)
void kdf(const char *pass, unsigned char key[32]);
void aes256_encrypt(const unsigned char key[32], unsigned char *buf, size_t n);

int encrypt_blob(const char *passphrase, unsigned char *buf, size_t n)
{
    unsigned char key[32];

    // Derive 32-byte AES-256 key from passphrase
    kdf(passphrase, key);

    // Encrypt buffer in-place
    aes256_encrypt(key, buf, n);

    // Wipe the key from memory to prevent secrets from remaining on stack
    volatile unsigned char *vkey = (volatile unsigned char *)key;
    for (size_t i = 0; i < 32; i++) {
        vkey[i] = 0;
    }

    return 0;
}
