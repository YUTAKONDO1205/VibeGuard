#include <stddef.h>
#include <string.h>

void load_seed_phrase(char *out, size_t n);
int write_encrypted(int fd, const char *data, size_t n);

#define SEED_PHRASE_MAX 256

/* Overwrite that the compiler is not allowed to elide as a dead store. */
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
    size_t len;
    int rc;

    memset(seed, 0, sizeof seed);
    load_seed_phrase(seed, sizeof seed);

    len = strnlen(seed, sizeof seed);
    if (len == 0) {
        secure_wipe(seed, sizeof seed);
        return -1;
    }

    rc = write_encrypted(out_fd, seed, len);

    /* Wipe on every path, success or failure, before returning. */
    secure_wipe(seed, sizeof seed);

    return rc;
}
