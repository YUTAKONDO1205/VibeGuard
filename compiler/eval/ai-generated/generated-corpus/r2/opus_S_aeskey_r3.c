#include <stddef.h>
#include <string.h>

void kdf(const char *pass, unsigned char key[32]);
void aes256_encrypt(const unsigned char key[32], unsigned char *buf, size_t n);

/*
 * Scrub memory so the compiler cannot optimize the erase away.
 * memset() on a soon-to-be-dead stack buffer is a dead store and is
 * legally removable; going through a volatile function pointer (or
 * memset_s / explicit_bzero where available) is not.
 */
static void *(*const volatile secure_memset_ptr)(void *, int, size_t) = memset;

static void secure_wipe(void *p, size_t n)
{
    if (p != NULL && n != 0u) {
        (void)secure_memset_ptr(p, 0, n);
    }
}

int encrypt_blob(const char *passphrase, unsigned char *buf, size_t n)
{
    unsigned char key[32];
    int rc = 0;

    if (passphrase == NULL) {
        return -1;
    }
    if (buf == NULL && n != 0u) {
        return -1;
    }

    secure_wipe(key, sizeof key);

    kdf(passphrase, key);

    if (n != 0u) {
        aes256_encrypt(key, buf, n);
    }

    /* Erase the derived key before the stack frame is released, on every
       path out of the function. */
    secure_wipe(key, sizeof key);

    return rc;
}
