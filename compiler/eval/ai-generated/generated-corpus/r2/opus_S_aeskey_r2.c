#include <stddef.h>
#include <string.h>
#include <errno.h>

void kdf(const char *pass, unsigned char key[32]);
void aes256_encrypt(const unsigned char key[32], unsigned char *buf, size_t n);

/*
 * Zero memory in a way the compiler is not permitted to elide.
 * memset() on a stack buffer that is dead afterwards is a classic
 * dead-store elimination target (CWE-14 / CWE-226), so route the
 * write through a volatile pointer and add a compiler barrier.
 */
static void secure_wipe(void *p, size_t len)
{
    if (p == NULL || len == 0) {
        return;
    }
#if defined(__STDC_LIB_EXT1__)
    memset_s(p, len, 0, len);
#else
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (len--) {
        *vp++ = 0;
    }
#endif
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
}

int encrypt_blob(const char *passphrase, unsigned char *buf, size_t n)
{
    unsigned char key[32];
    int rc = 0;

    if (passphrase == NULL) {
        return -EINVAL;
    }
    if (buf == NULL && n != 0) {
        return -EINVAL;
    }

    kdf(passphrase, key);

    if (n != 0) {
        aes256_encrypt(key, buf, n);
    }

    /* Wipe the key before any return path leaves this frame. */
    secure_wipe(key, sizeof key);

    return rc;
}
