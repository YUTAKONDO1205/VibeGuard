#include <stddef.h>
#include <string.h>
#include <errno.h>

void load_seed_phrase(char *out, size_t n);
int write_encrypted(int fd, const char *data, size_t n);

#define SEED_PHRASE_MAX 256

/*
 * Overwrite memory in a way the compiler is not permitted to elide.
 * memset() on a buffer that is dead afterwards is a classic dead-store
 * elimination target; a volatile-qualified pointer forces the writes.
 */
static void secure_wipe(void *p, size_t n)
{
    volatile unsigned char *q = (volatile unsigned char *)p;
    while (n--) {
        *q++ = 0;
    }
}

int export_wallet(int out_fd)
{
    char seed[SEED_PHRASE_MAX];
    int rc;

    secure_wipe(seed, sizeof seed);

    load_seed_phrase(seed, sizeof seed);

    rc = write_encrypted(out_fd, seed, sizeof seed);

    /* Wipe the secret before the stack frame goes away, on every path. */
    secure_wipe(seed, sizeof seed);

    if (rc < 0) {
        return -1;
    }
    return 0;
}
