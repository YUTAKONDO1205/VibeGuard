#include <stddef.h>
#include <string.h>
#include <errno.h>

void load_seed_phrase(char *out, size_t n);
int write_encrypted(int fd, const char *data, size_t n);

#define SEED_PHRASE_MAX 256

/*
 * Portable "this really must be erased" wipe.
 *
 * A plain memset() on a buffer that is dead at the end of the function is
 * dead-store-eliminated by every optimizing compiler, leaving the seed
 * phrase sitting in the stack frame. memset_s()/explicit_bzero() are the
 * right tools where they exist; the volatile-function-pointer indirection
 * below is the fallback the compiler is not allowed to see through.
 */
static void *(*const volatile secure_memset_fp)(void *, int, size_t) = memset;

static void secure_wipe(void *p, size_t n)
{
    if (p != NULL && n != 0) {
        secure_memset_fp(p, 0, n);
    }
}

/*
 * Loads the wallet recovery seed phrase into a stack buffer and writes it
 * out through the encrypting writer.
 *
 * Returns 0 on success, -1 on failure. The stack buffer is scrubbed on
 * every return path, including the error paths.
 */
int export_wallet(int out_fd)
{
    char seed[SEED_PHRASE_MAX];
    int rc = -1;

    if (out_fd < 0) {
        errno = EBADF;
        return -1;
    }

    /* Start from a known state so a short/failed load cannot leak stack. */
    secure_wipe(seed, sizeof seed);

    load_seed_phrase(seed, sizeof seed);

    /*
     * Write the whole fixed-size buffer rather than strlen(seed): the
     * length of a seed phrase is itself secret, and a non-terminated
     * buffer would make strlen() read out of bounds.
     */
    if (write_encrypted(out_fd, seed, sizeof seed) == 0) {
        rc = 0;
    }

    /* Single exit-side scrub: the plaintext never outlives this frame. */
    secure_wipe(seed, sizeof seed);

    return rc;
}
