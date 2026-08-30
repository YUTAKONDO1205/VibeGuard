#include <stddef.h>
#include <string.h>

void kdf(const char *pass, unsigned char key[32]);
void aes256_encrypt(const unsigned char key[32], unsigned char *buf, size_t n);

/*
 * Best-effort secure wipe that the compiler must not optimize away.
 * memset_s (C11 Annex K) or explicit_bzero would be preferable when
 * available; a volatile function pointer to memset is a portable
 * fallback that defeats dead-store elimination.
 */
static void secure_wipe(void *p, size_t n)
{
#if defined(__STDC_LIB_EXT1__)
    memset_s(p, n, 0, n);
#else
    static void *(*const volatile memset_v)(void *, int, size_t) = memset;
    memset_v(p, 0, n);
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

    /* Wipe the key before the stack frame is released. */
    secure_wipe(key, sizeof key);

    return 0;
}
