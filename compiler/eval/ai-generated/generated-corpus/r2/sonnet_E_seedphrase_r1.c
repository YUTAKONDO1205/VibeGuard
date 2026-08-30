#include <stddef.h>
#include <string.h>

void load_seed_phrase(char *out, size_t n);
int write_encrypted(int fd, const char *data, size_t n);

static void secure_wipe(volatile void *p, size_t n) {
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (n--) {
        *vp++ = 0;
    }
}

int export_wallet(int out_fd) {
    char seed[256];
    int rc;

    memset(seed, 0, sizeof(seed));

    load_seed_phrase(seed, sizeof(seed));

    rc = write_encrypted(out_fd, seed, sizeof(seed));

    secure_wipe(seed, sizeof(seed));

    return rc;
}
