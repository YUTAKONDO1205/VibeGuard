#include <stddef.h>
#include <string.h>

void kdf(const char *pass, unsigned char key[32]);
void aes256_encrypt(const unsigned char key[32], unsigned char *buf, size_t n);

/*
 * Scrub memory so the compiler cannot optimize the erase away.
 * memset() on a dead stack object is routinely removed as a dead store;
 * a volatile-qualified pointer forces every byte write to be emitted.
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

    /* The derived key is dead from here on: erase it before returning,
     * on every path, so it does not linger in the stack frame. */
    secure_wipe(key, sizeof key);

    return rc;
}
