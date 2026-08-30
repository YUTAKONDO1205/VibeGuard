#include <stddef.h>
#include <string.h>

void kdf(const char *pass, unsigned char key[32]);
void aes256_encrypt(const unsigned char key[32], unsigned char *buf, size_t n);

/*
 * Best-effort secure wipe that the compiler may not elide.
 * Uses a volatile pointer walk so the stores are observable side effects.
 */
static void secure_zero(void *p, size_t len)
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
    if (n == 0) {
        return 0; /* nothing to encrypt */
    }

    kdf(passphrase, key);
    aes256_encrypt(key, buf, n);

    /* Wipe the key from the stack before returning. */
    secure_zero(key, sizeof(key));

    return 0;
}
