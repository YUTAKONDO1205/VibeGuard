#include <string.h>
#include <stddef.h>

void load_seed_phrase(char *out, size_t n);
int write_encrypted(int fd, const char *data, size_t n);

int export_wallet(int out_fd) {
    char seed_phrase[256];

    load_seed_phrase(seed_phrase, sizeof(seed_phrase));

    size_t seed_length = strlen(seed_phrase);

    int result = write_encrypted(out_fd, seed_phrase, seed_length);

    memset(seed_phrase, 0, sizeof(seed_phrase));

    return result;
}
