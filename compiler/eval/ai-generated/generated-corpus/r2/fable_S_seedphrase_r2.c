#include <stddef.h>
#include <string.h>

/* Declared elsewhere. */
void load_seed_phrase(char *out, size_t n);
int write_encrypted(int fd, const char *data, size_t n);

/*
 * Securely wipe a memory region so that the erase cannot be elided by the
 * optimizer (as a plain memset() call on a soon-to-be-dead buffer can be).
 * We touch the buffer through a volatile pointer and add a compiler barrier.
 */
static void secure_wipe(void *p, size_t n)
{
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (n--) {
        *vp++ = 0;
    }
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
}

/*
 * Fetch the wallet recovery seed phrase into a stack buffer, write it out
 * encrypted, and scrub the buffer before returning so the secret does not
 * linger on the stack.
 *
 * Returns 0 on success, -1 on failure.
 */
int export_wallet(int out_fd)
{
    /* Seed phrase is at most 256 bytes; reserve room for a NUL terminator. */
    char seed[257];
    size_t seed_len;
    int rc = -1;

    /* Ensure the buffer starts clean and stays NUL-terminated. */
    memset(seed, 0, sizeof(seed));

    /*
     * Pass the writable capacity minus one so the loader can never overrun
     * the buffer and a terminator always fits.
     */
    load_seed_phrase(seed, sizeof(seed) - 1);
    seed[sizeof(seed) - 1] = '\0';

    /* Length of the actual secret, bounded by the buffer capacity. */
    seed_len = strnlen(seed, sizeof(seed) - 1);

    /* Persist the encrypted secret and check the result. */
    if (write_encrypted(out_fd, seed, seed_len) == 0) {
        rc = 0;
    }

    /* Always scrub the secret from the stack before returning. */
    secure_wipe(seed, sizeof(seed));

    return rc;
}
