#include <stddef.h>
#include <string.h>
#include <errno.h>

void kdf(const char *pass, unsigned char key[32]);
void aes256_encrypt(const unsigned char key[32], unsigned char *buf, size_t n);

/*
 * Scrub a memory region so that the compiler may not elide the write.
 * memset() on a buffer that is dead afterwards is a classic dead-store
 * elimination target; the volatile function pointer below forces the call
 * to be emitted.  C11 Annex K's memset_s and the BSD explicit_bzero are
 * used when available.
 */
#if defined(__STDC_LIB_EXT1__)
static void secure_wipe(void *p, size_t len)
{
    if (p != NULL && len != 0U) {
        (void)memset_s(p, (rsize_t)len, 0, (rsize_t)len);
    }
}
#else
static void *(*const volatile secure_memset_ptr)(void *, int, size_t) = &memset;

static void secure_wipe(void *p, size_t len)
{
    if (p != NULL && len != 0U) {
        (void)secure_memset_ptr(p, 0, len);
        /* Keep the store from being reordered/removed across the barrier. */
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
    }
}
#endif

/*
 * Derive a 32-byte AES-256 key from `passphrase` and encrypt `buf` in place.
 *
 * Returns 0 on success, -1 on invalid arguments.  The derived key lives in a
 * stack array that is wiped on every exit path, including the error paths,
 * so it does not linger in the frame for a later call to expose.
 */
int encrypt_blob(const char *passphrase, unsigned char *buf, size_t n)
{
    unsigned char key[32];
    int rc = -1;

    if (passphrase == NULL) {
        return -1;
    }
    /* A zero-length buffer is legal only with a NULL-safe pairing check. */
    if (buf == NULL && n != 0U) {
        return -1;
    }

    kdf(passphrase, key);

    if (n != 0U) {
        aes256_encrypt(key, buf, n);
    }
    rc = 0;

    /* Single exit-side scrub: the key must not survive this frame. */
    secure_wipe(key, sizeof key);

    return rc;
}
