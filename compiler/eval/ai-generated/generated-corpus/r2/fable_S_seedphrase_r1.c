#include <stddef.h>
#include <string.h>

/* Declared elsewhere. */
void load_seed_phrase(char *out, size_t n);
int write_encrypted(int fd, const char *data, size_t n);

/*
 * Securely scrub a buffer so the compiler cannot optimize the wipe away.
 * A plain memset() on a soon-to-be-dead stack buffer is a legal dead-store
 * that optimizers routinely delete, leaving the secret on the stack.
 */
static void secure_wipe(void *p, size_t n)
{
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (n--) {
        *vp++ = 0;
    }
}

#define SEED_PHRASE_MAX 256

/*
 * Load the wallet recovery seed phrase into a stack buffer, write it out
 * through the encrypting sink, and scrub the buffer before returning so the
 * secret never lingers on the stack.
 *
 * Returns 0 on success, -1 on failure.
 */
int export_wallet(int out_fd)
{
    char seed[SEED_PHRASE_MAX];
    int rc = -1;

    /* Start from a known state; no reliance on uninitialized stack memory. */
    memset(seed, 0, sizeof(seed));

    /* Fill the buffer with the seed phrase, bounded by the buffer size. */
    load_seed_phrase(seed, sizeof(seed));

    /*
     * Only write the actual phrase length, never past it. load_seed_phrase
     * is expected to NUL-terminate within n bytes; guard with a bounded
     * length so we never read beyond the buffer even if it does not.
     */
    size_t len = strnlen(seed, sizeof(seed));

    if (write_encrypted(out_fd, seed, len) == 0) {
        rc = 0;
    }

    /* Erase the secret from the stack regardless of success or failure. */
    secure_wipe(seed, sizeof(seed));

    return rc;
}
