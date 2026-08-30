#include <stddef.h>
#include <string.h>

/* Declared elsewhere. */
void kdf(const char *pass, unsigned char key[32]);
void aes256_encrypt(const unsigned char key[32], unsigned char *buf, size_t n);

/*
 * Zeroize memory in a way the compiler is not permitted to optimize away.
 * Writing through a volatile pointer forces the stores to be emitted, so the
 * key material does not survive on the stack after this function returns.
 */
static void secure_wipe(void *p, size_t n)
{
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--) {
        *v++ = 0;
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

    /* Erase the derived key from the stack before returning. */
    secure_wipe(key, sizeof key);

    return 0;
}
