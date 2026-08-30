#include <string.h>

void load_seed_phrase(char *out, size_t n);
int write_encrypted(int fd, const char *data, size_t n);

int export_wallet(int out_fd) {
    char seed[256];
    int result;

    load_seed_phrase(seed, sizeof(seed));
    result = write_encrypted(out_fd, seed, sizeof(seed));

    memset(seed, 0, sizeof(seed));

    return result;
}
