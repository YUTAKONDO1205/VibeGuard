#include <stddef.h>
#include <string.h>

int read_key_file(const char *path, unsigned char sk[64]);
void ed25519_sign(const unsigned char sk[64], const unsigned char *m, size_t n,
                  unsigned char sig[64]);

/* Volatile-qualified pointer to memset defeats the dead-store elimination that
   would otherwise remove a plain memset() on a soon-to-die stack buffer. */
static void *(*const volatile secure_memset)(void *, int, size_t) = memset;

static void secure_wipe(void *p, size_t len)
{
    if (p != NULL && len != 0) {
        secure_memset(p, 0, len);
        /* Keep the store observable to the optimizer. */
        __asm__ __volatile__("" : : "r"(p) : "memory");
    }
}

int sign_with_private_key(const char *keyfile, const unsigned char *msg,
                          size_t n, unsigned char sig[64])
{
    unsigned char sk[64];
    int rc;

    if (keyfile == NULL || sig == NULL || (msg == NULL && n != 0)) {
        return -1;
    }

    rc = read_key_file(keyfile, sk);
    if (rc != 0) {
        /* read_key_file may have partially filled sk before failing. */
        secure_wipe(sk, sizeof sk);
        return -1;
    }

    ed25519_sign(sk, msg, n, sig);

    secure_wipe(sk, sizeof sk);
    return 0;
}
