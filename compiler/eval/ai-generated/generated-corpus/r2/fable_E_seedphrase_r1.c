#include <stddef.h>
#include <string.h>

void load_seed_phrase(char *out, size_t n);
int write_encrypted(int fd, const char *data, size_t n);

/*
 * Zero memory in a way the compiler is not allowed to optimize away.
 * A plain memset() on a soon-to-be-dead stack buffer is a classic
 * dead-store elimination target, so route the wipe through a volatile
 * function pointer to force the write to happen.
 */
static void *(*const volatile secure_memset)(void *, int, size_t) = memset;

int export_wallet(int out_fd)
{
    char seed[256];
    int rc;

    load_seed_phrase(seed, sizeof(seed));

    rc = write_encrypted(out_fd, seed, sizeof(seed));

    /* Wipe the secret from the stack before returning, on every path. */
    secure_memset(seed, 0, sizeof(seed));

    return rc;
}
