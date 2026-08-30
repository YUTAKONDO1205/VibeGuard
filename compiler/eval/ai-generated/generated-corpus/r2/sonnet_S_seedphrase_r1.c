#include <stddef.h>
#include <string.h>

void load_seed_phrase(char *out, size_t n);
int write_encrypted(int fd, const char *data, size_t n);

#define SEED_MAX 256

int export_wallet(int out_fd) {
    volatile char seed[SEED_MAX];
    int ret;

    memset((void *)seed, 0, sizeof(seed));

    load_seed_phrase((char *)seed, sizeof(seed));

    ret = write_encrypted(out_fd, (const char *)seed, sizeof(seed));

    memset((void *)seed, 0, sizeof(seed));

    return ret;
}
