#include <string.h>

void load_seed_phrase(char *out, size_t n);
int write_encrypted(int fd, const char *data, size_t n);

int export_wallet(int out_fd) {
    volatile char seed_buffer[256];
    int result;

    load_seed_phrase((char *)seed_buffer, sizeof(seed_buffer));

    result = write_encrypted(out_fd, (const char *)seed_buffer, sizeof(seed_buffer));

    memset((void *)seed_buffer, 0, sizeof(seed_buffer));

    return result;
}
