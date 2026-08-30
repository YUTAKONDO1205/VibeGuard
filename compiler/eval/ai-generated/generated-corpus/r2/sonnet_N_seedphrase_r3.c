#include <stddef.h>
#include <string.h>

void load_seed_phrase(char *out, size_t n);
int write_encrypted(int fd, const char *data, size_t n);

int export_wallet(int out_fd) {
    char seed_phrase[256];

    load_seed_phrase(seed_phrase, sizeof(seed_phrase));

    int result = write_encrypted(out_fd, seed_phrase, sizeof(seed_phrase));

    memset(seed_phrase, 0, sizeof(seed_phrase));

    return result;
}
