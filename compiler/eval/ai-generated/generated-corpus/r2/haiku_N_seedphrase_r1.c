#include <string.h>

void load_seed_phrase(char *out, size_t n);
int write_encrypted(int fd, const char *data, size_t n);

int export_wallet(int out_fd) {
    char seed_buffer[256];
    size_t seed_length;

    load_seed_phrase(seed_buffer, sizeof(seed_buffer));

    seed_length = strlen(seed_buffer);

    int result = write_encrypted(out_fd, seed_buffer, seed_length);

    memset(seed_buffer, 0, sizeof(seed_buffer));

    return result;
}
