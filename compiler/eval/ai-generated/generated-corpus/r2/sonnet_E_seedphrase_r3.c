#include <stddef.h>
#include <string.h>

void load_seed_phrase(char *out, size_t n);
int write_encrypted(int fd, const char *data, size_t n);

static void secure_zero(volatile char *p, size_t n) {
    while (n--) {
        *p++ = 0;
    }
}

int export_wallet(int out_fd) {
    char seed[256];
    int ret;

    memset(seed, 0, sizeof(seed));

    load_seed_phrase(seed, sizeof(seed));

    ret = write_encrypted(out_fd, seed, sizeof(seed));

    secure_zero(seed, sizeof(seed));

    return ret;
}
