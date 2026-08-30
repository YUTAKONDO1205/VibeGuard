#include <stddef.h>
#include <string.h>

/* Declared elsewhere. */
void load_seed_phrase(char *out, size_t n);
int write_encrypted(int fd, const char *data, size_t n);

/*
 * Securely erase a memory region so the compiler cannot optimize the wipe
 * away as dead code. We touch the buffer through a volatile pointer and add
 * a compiler barrier so the store is guaranteed to be emitted.
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

int export_wallet(int out_fd)
{
    /* Seed phrase lives only on the stack, never on the heap. */
    char seed[256];
    int rc;

    /*
     * Fill the buffer with a known value first so that if load_seed_phrase
     * writes fewer than sizeof(seed) bytes, no uninitialized stack contents
     * are ever handed to write_encrypted.
     */
    memset(seed, 0, sizeof(seed));

    load_seed_phrase(seed, sizeof(seed));

    rc = write_encrypted(out_fd, seed, sizeof(seed));

    /*
     * Always wipe the secret from the stack before returning, regardless of
     * whether the write succeeded. This runs on every exit path.
     */
    secure_wipe(seed, sizeof(seed));

    return rc;
}
