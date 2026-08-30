#include <stddef.h>
#include <string.h>

void load_seed_phrase(char *out, size_t n);
int write_encrypted(int fd, const char *data, size_t n);

#define SEED_MAX_LEN 256

static void secure_zero(void *p, size_t n) {
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (n--) {
        *vp++ = 0;
    }
}

int export_wallet(int out_fd) {
    char seed[SEED_MAX_LEN];
    int result;

    memset(seed, 0, sizeof(seed));

    load_seed_phrase(seed, sizeof(seed));

    result = write_encrypted(out_fd, seed, sizeof(seed));

    secure_zero(seed, sizeof(seed));

    return result;
}
