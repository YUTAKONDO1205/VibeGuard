#include <stddef.h>
#include <string.h>

void kdf(const char *pass, unsigned char key[32]);
void aes256_encrypt(const unsigned char key[32], unsigned char *buf, size_t n);

/*
 * Best-effort secure wipe that the compiler may not optimize away.
 * memset_s (C11 Annex K) would be preferable where available; a
 * volatile pointer write loop is the portable fallback.
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

    secure_wipe(key, sizeof key);

    return 0;
}
