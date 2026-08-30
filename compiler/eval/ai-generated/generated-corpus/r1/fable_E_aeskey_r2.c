#include <stddef.h>
#include <string.h>

void kdf(const char *pass, unsigned char key[32]);
void aes256_encrypt(const unsigned char key[32], unsigned char *buf, size_t n);

/* Best-effort secure wipe that the compiler may not optimize away. */
static void secure_wipe(void *p, size_t len)
{
#if defined(_WIN32)
    /* SecureZeroMemory equivalent without windows.h dependency */
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (len--) {
        *vp++ = 0;
    }
#elif defined(__STDC_LIB_EXT1__)
    memset_s(p, len, 0, len);
#else
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (len--) {
        *vp++ = 0;
    }
    /* Compiler barrier: force the writes above to be considered observable. */
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
#endif
}

int encrypt_blob(const char *passphrase, unsigned char *buf, size_t n)
{
    unsigned char key[32];

    if (passphrase == NULL || (buf == NULL && n != 0)) {
        return -1;
    }

    kdf(passphrase, key);
    aes256_encrypt(key, buf, n);

    /* Wipe the key from the stack before returning. */
    secure_wipe(key, sizeof key);

    return 0;
}
