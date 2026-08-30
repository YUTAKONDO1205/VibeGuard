#include <stddef.h>
#include <string.h>

void kdf(const char *pass, unsigned char key[32]);
void aes256_encrypt(const unsigned char key[32], unsigned char *buf, size_t n);

/*
 * Scrub memory in a way the compiler is not allowed to optimize away.
 * memset() on a dead stack buffer is a classic dead-store elimination
 * target; the volatile function pointer below forces the call to happen.
 */
static void *(*const volatile secure_memset_ptr)(void *, int, size_t) = memset;

static void secure_wipe(void *p, size_t n)
{
    if (p != NULL && n != 0) {
        secure_memset_ptr(p, 0, n);
        /* Keep the store observable across the compilation barrier. */
        __asm__ __volatile__("" : : "r"(p) : "memory");
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

    /* The key is finished with: erase it before the frame goes away. */
    secure_wipe(key, sizeof key);

    return rc;
}
