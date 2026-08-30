#include <stddef.h>
#include <string.h>

void kdf(const char *pass, unsigned char key[32]);
void aes256_encrypt(const unsigned char key[32], unsigned char *buf, size_t n);

/*
 * Scrub memory so the compiler cannot optimize the write away.
 * memset() on a dying stack buffer is a dead store and is legally
 * removable; a volatile-qualified byte pointer is not.
 */
static void secure_wipe(void *p, size_t n)
{
    volatile unsigned char *q = (volatile unsigned char *)p;
    while (n--) {
        *q++ = 0;
    }
}

int encrypt_blob(const char *passphrase, unsigned char *buf, size_t n)
{
    unsigned char key[32];
    int rc = 0;

    if (passphrase == NULL || (buf == NULL && n != 0)) {
        return -1;
    }

    kdf(passphrase, key);
    aes256_encrypt(key, buf, n);

    /* The derived key must not outlive its use, on any return path. */
    secure_wipe(key, sizeof key);

    return rc;
}
