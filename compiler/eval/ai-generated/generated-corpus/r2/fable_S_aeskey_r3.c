#include <stddef.h>
#include <string.h>

void kdf(const char *pass, unsigned char key[32]);
void aes256_encrypt(const unsigned char key[32], unsigned char *buf, size_t n);

/*
 * Securely zero memory so the compiler cannot optimize the wipe away.
 * A plain memset() on a local buffer that is not read afterward is a
 * "dead store" the optimizer is free to remove, leaving the key on the
 * stack. Routing the clear through a volatile function pointer defeats
 * that elimination portably.
 */
static void *(*const volatile secure_memset)(void *, int, size_t) = memset;

static void secure_wipe(void *p, size_t n)
{
    secure_memset(p, 0, n);
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
