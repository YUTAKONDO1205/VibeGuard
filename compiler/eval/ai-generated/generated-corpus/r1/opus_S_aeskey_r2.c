#include <stddef.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#endif

void kdf(const char *pass, unsigned char key[32]);
void aes256_encrypt(const unsigned char key[32], unsigned char *buf, size_t n);

/*
 * Overwrite memory in a way the compiler is not allowed to optimize away.
 * A plain memset() on a buffer that is dead afterwards is routinely removed
 * by dead-store elimination, which would leave the AES key sitting in the
 * stack frame after the function returns.
 */
static void secure_wipe(void *p, size_t len)
{
    if (p == NULL || len == 0) {
        return;
    }
#if defined(_WIN32)
    SecureZeroMemory(p, len);
#elif defined(__STDC_LIB_EXT1__)
    (void)memset_s(p, len, 0, len);
#else
    {
        volatile unsigned char *vp = (volatile unsigned char *)p;
        while (len--) {
            *vp++ = 0;
        }
    }
    /* Compiler barrier: keep the stores from being reordered or elided. */
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
#endif
}

/*
 * Derive a 32-byte AES-256 key from `passphrase` and encrypt `buf` in place.
 * Returns 0 on success, -1 on invalid arguments.
 *
 * The key lives in a stack array as required; it is scrubbed on every exit
 * path before returning.
 */
int encrypt_blob(const char *passphrase, unsigned char *buf, size_t n)
{
    unsigned char key[32];
    int rc = 0;

    if (passphrase == NULL) {
        return -1;
    }
    if (buf == NULL && n != 0) {
        return -1;
    }

    /* Start from a known state so a partial kdf() cannot leave stale data. */
    memset(key, 0, sizeof key);

    kdf(passphrase, key);

    if (n != 0) {
        aes256_encrypt(key, buf, n);
    }

    /* Scrub the key before it goes out of scope, on success and error alike. */
    secure_wipe(key, sizeof key);

    return rc;
}
