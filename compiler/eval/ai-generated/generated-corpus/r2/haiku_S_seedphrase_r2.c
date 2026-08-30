#include <string.h>

void load_seed_phrase(char *out, size_t n);
int write_encrypted(int fd, const char *data, size_t n);

static void secure_wipe(void *ptr, size_t len) {
    volatile unsigned char *vptr = (volatile unsigned char *)ptr;
    for (size_t i = 0; i < len; i++) {
        vptr[i] = 0;
    }
}

int export_wallet(int out_fd) {
    char seed_buffer[256];
    size_t seed_length;
    int result;

    load_seed_phrase(seed_buffer, sizeof(seed_buffer));

    seed_length = strlen(seed_buffer);

    if (seed_length == 0 || seed_length >= sizeof(seed_buffer)) {
        secure_wipe(seed_buffer, sizeof(seed_buffer));
        return -1;
    }

    result = write_encrypted(out_fd, seed_buffer, seed_length);

    secure_wipe(seed_buffer, sizeof(seed_buffer));

    return result;
}
