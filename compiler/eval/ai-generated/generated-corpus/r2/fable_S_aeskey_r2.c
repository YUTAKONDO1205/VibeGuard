#include <stddef.h>

#if defined(_WIN32)
#include <windows.h>
#endif

void kdf(const char *pass, unsigned char key[32]);
void aes256_encrypt(const unsigned char key[32], unsigned char *buf, size_t n);

/*
 * Securely zero a memory region so the compiler cannot elide the write.
 * A plain memset over a soon-to-be-freed/out-of-scope buffer is a classic
 * dead-store that optimizers remove, leaving the key on the stack.
 */
static void secure_wipe(void *p, size_t len)
{
#if defined(_WIN32)
    SecureZeroMemory(p, len);
#elif defined(__STDC_LIB_EXT1__)
    memset_s(p, len, 0, len);
#else
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (len--) {
        *vp++ = 0;
    }
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

    /* Erase the derived key from the stack before returning. */
    secure_wipe(key, sizeof key);

    return 0;
}
