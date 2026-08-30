#include <stddef.h>
#include <string.h>
#include <errno.h>

#if defined(_WIN32)
#include <windows.h>
#endif

void kdf(const char *pass, unsigned char key[32]);
void aes256_encrypt(const unsigned char key[32], unsigned char *buf, size_t n);

/*
 * Best-effort secure zeroization that the compiler is not permitted to
 * elide as a dead store.  Prefer a platform-provided primitive; fall back
 * to a volatile-pointer byte loop plus a compiler barrier.
 */
static void secure_wipe(void *p, size_t len)
{
    if (p == NULL || len == 0) {
        return;
    }

#if defined(_WIN32)
    SecureZeroMemory(p, len);
#elif defined(__STDC_LIB_EXT1__)
    memset_s(p, len, 0, len);
#elif defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__NetBSD__) || \
      (defined(__GLIBC__) && defined(_DEFAULT_SOURCE))
    explicit_bzero(p, len);
#else
    {
        volatile unsigned char *vp = (volatile unsigned char *)p;
        while (len--) {
            *vp++ = 0;
        }
    }
#endif

#if defined(__GNUC__) || defined(__clang__)
    /* Keep the store observable: the memory is an input to empty asm. */
    __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
}

/*
 * Derive a 32-byte AES-256 key from `passphrase` and encrypt `buf` in place.
 *
 * The key lives in a stack array whose lifetime ends with this function, so
 * it is wiped on every exit path before returning.
 *
 * Returns 0 on success, -1 with errno set on invalid arguments.
 */
int encrypt_blob(const char *passphrase, unsigned char *buf, size_t n)
{
    unsigned char key[32];
    int rc = 0;

    if (passphrase == NULL || (buf == NULL && n != 0)) {
        errno = EINVAL;
        return -1;
    }

    if (n == 0) {
        return 0;
    }

    kdf(passphrase, key);
    aes256_encrypt(key, buf, n);

    /* Erase the key material before the stack frame is released. */
    secure_wipe(key, sizeof key);

    return rc;
}
