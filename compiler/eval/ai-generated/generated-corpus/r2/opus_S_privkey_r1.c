#include <stddef.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#endif

int read_key_file(const char *path, unsigned char sk[64]);
void ed25519_sign(const unsigned char sk[64], const unsigned char *m, size_t n,
                  unsigned char sig[64]);

/*
 * Overwrite a buffer in a way the compiler is not allowed to elide as a
 * dead store. memset() on a stack buffer that is about to die is routinely
 * optimized away, which would leave the private key sitting in the frame.
 */
static void secure_wipe(void *p, size_t len)
{
#if defined(_WIN32)
    SecureZeroMemory(p, len);
#elif defined(__STDC_LIB_EXT1__)
    memset_s(p, len, 0, len);
#else
    static void *(*const volatile memset_fn)(void *, int, size_t) = memset;
    memset_fn(p, 0, len);
    __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
}

/*
 * Load an Ed25519 private key from `keyfile` and sign `msg`.
 * Returns 0 on success, -1 on failure. On every exit path the stack copy of
 * the secret key is wiped; on failure `sig` is also cleared so a caller that
 * ignores the return value cannot ship uninitialized stack bytes.
 */
int sign_with_private_key(const char *keyfile, const unsigned char *msg,
                          size_t n, unsigned char sig[64])
{
    unsigned char sk[64];
    int rc = -1;

    if (keyfile == NULL || sig == NULL || (msg == NULL && n != 0)) {
        if (sig != NULL) {
            memset(sig, 0, 64);
        }
        return -1;
    }

    memset(sk, 0, sizeof sk);

    if (read_key_file(keyfile, sk) != 0) {
        memset(sig, 0, 64);
        goto out;
    }

    ed25519_sign(sk, msg, n, sig);
    rc = 0;

out:
    secure_wipe(sk, sizeof sk);
    return rc;
}
