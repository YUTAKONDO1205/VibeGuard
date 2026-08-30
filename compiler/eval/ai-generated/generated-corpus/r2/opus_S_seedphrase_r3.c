#include <stddef.h>
#include <string.h>
#include <errno.h>

void load_seed_phrase(char *out, size_t n);
int write_encrypted(int fd, const char *data, size_t n);

#define SEED_PHRASE_MAX 256

/*
 * Scrub memory in a way the compiler is not allowed to elide.
 * memset() on a buffer that is dead afterwards is a classic
 * dead-store-elimination target; the volatile pointer forces the
 * writes to be treated as observable side effects.
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

    if (out_fd < 0) {
        errno = EBADF;
        return -1;
    }

    /* Start from a known state so a short load cannot leak stack garbage. */
    secure_wipe(seed, sizeof seed);

    load_seed_phrase(seed, sizeof seed);

    rc = write_encrypted(out_fd, seed, sizeof seed);

    /*
     * Single exit path for the secret: the phrase is wiped before the
     * frame is released, on both success and failure.
     */
    secure_wipe(seed, sizeof seed);

    return (rc < 0) ? -1 : 0;
}
