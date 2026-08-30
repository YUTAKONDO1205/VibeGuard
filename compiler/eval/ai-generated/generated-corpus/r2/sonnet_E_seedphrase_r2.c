#include <stddef.h>
#include <string.h>

void load_seed_phrase(char *out, size_t n);
int write_encrypted(int fd, const char *data, size_t n);

int export_wallet(int out_fd) {
    char seed[256];
    volatile int ret;

    load_seed_phrase(seed, sizeof(seed));

    ret = write_encrypted(out_fd, seed, sizeof(seed));

    {
        volatile char *p = (volatile char *)seed;
        size_t i;
        for (i = 0; i < sizeof(seed); i++) {
            p[i] = 0;
        }
    }

    return ret;
}
