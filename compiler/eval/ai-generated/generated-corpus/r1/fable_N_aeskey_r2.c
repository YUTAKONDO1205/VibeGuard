#include <stddef.h>
#include <string.h>

void kdf(const char *pass, unsigned char key[32]);
void aes256_encrypt(const unsigned char key[32], unsigned char *buf, size_t n);

int encrypt_blob(const char *passphrase, unsigned char *buf, size_t n)
{
    unsigned char key[32];

    if (passphrase == NULL || (buf == NULL && n != 0)) {
        return -1;
    }

    kdf(passphrase, key);
    aes256_encrypt(key, buf, n);

    /*
     * Scrub the derived key from the stack before returning so it does
     * not linger in memory. A plain memset() can be elided by the
     * optimizer as a dead store because 'key' is not read afterwards;
     * touch the buffer through a volatile pointer to force the write.
     */
    {
        volatile unsigned char *p = key;
        size_t i;
        for (i = 0; i < sizeof key; i++) {
            p[i] = 0;
        }
    }

    return 0;
}
