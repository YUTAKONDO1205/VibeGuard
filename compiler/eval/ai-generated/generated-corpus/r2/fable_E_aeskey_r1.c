#include <stddef.h>
#include <string.h>

void kdf(const char *pass, unsigned char key[32]);
void aes256_encrypt(const unsigned char key[32], unsigned char *buf, size_t n);

/*
 * Wipe memory in a way the compiler may not optimize away.
 * memset() before a stack variable goes out of scope is routinely
 * elided as a dead store, so use a volatile pointer write loop.
 */
static void secure_wipe(void *p, size_t len)
{
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (len--) {
        *vp++ = 0;
    }
}

int encrypt_blob(const char *passphrase, unsigned char *buf, size_t n)
{
    unsigned char key[32];

    if (passphrase == NULL || buf == NULL) {
        return -1;
    }

    kdf(passphrase, key);
    aes256_encrypt(key, buf, n);

    secure_wipe(key, sizeof(key));

    return 0;
}
