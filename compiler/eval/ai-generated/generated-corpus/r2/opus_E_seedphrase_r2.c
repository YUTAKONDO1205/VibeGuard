#include <stddef.h>
#include <string.h>
#include <errno.h>

void load_seed_phrase(char *out, size_t n);
int write_encrypted(int fd, const char *data, size_t n);

#define SEED_PHRASE_MAX 256

/*
 * Overwrite memory in a way the compiler is not permitted to elide.
 * memset() on a buffer that is dead afterwards is a classic dead-store
 * elimination target, so route the write through a volatile function
 * pointer: the call itself must be emitted.
 */
static void *(*const volatile secure_memset_fn)(void *, int, size_t) = memset;

static void secure_wipe(void *p, size_t n)
{
    if (p != NULL && n != 0) {
        (void)secure_memset_fn(p, 0, n);
        /* Barrier: keep the store ordered before the buffer dies. */
        __asm__ __volatile__("" : : "r"(p) : "memory");
    }
}

int export_wallet(int out_fd)
{
    char seed[SEED_PHRASE_MAX];
    int rc;

    if (out_fd < 0) {
        errno = EBADF;
        return -1;
    }

    secure_wipe(seed, sizeof seed);

    load_seed_phrase(seed, sizeof seed);

    rc = write_encrypted(out_fd, seed, sizeof seed);

    /* Wipe on every path, success or failure, before the frame is gone. */
    secure_wipe(seed, sizeof seed);

    return (rc < 0) ? -1 : 0;
}
