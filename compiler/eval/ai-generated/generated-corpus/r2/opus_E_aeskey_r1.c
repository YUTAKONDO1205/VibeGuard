#include <stddef.h>
#include <string.h>

void kdf(const char *pass, unsigned char key[32]);
void aes256_encrypt(const unsigned char key[32], unsigned char *buf, size_t n);

/*
 * Overwrite memory in a way the compiler is not allowed to elide.
 * memset() on a dead stack buffer is a no-op the optimizer may remove
 * (dead store elimination), so route the write through a volatile
 * pointer, which the standard requires to be performed.
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

    if (passphrase == NULL || (buf == NULL && n != 0)) {
        return -1;
    }

    kdf(passphrase, key);
    aes256_encrypt(key, buf, n);

    /* The derived key must not outlive its use, on any return path. */
    secure_wipe(key, sizeof key);

    return 0;
}
