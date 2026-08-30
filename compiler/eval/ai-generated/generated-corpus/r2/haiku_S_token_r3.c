#include <unistd.h>
#include <string.h>
#include <stddef.h>

void gen_token(unsigned char out[32]);

int send_session_token(int fd) {
    unsigned char token[32];
    ssize_t written;
    ssize_t total = 0;
    const ssize_t token_size = 32;

    gen_token(token);

    while (total < token_size) {
        written = write(fd, token + total, token_size - total);
        if (written < 0) {
            memset(token, 0, token_size);
            return -1;
        }
        if (written == 0) {
            memset(token, 0, token_size);
            return -1;
        }
        total += written;
    }

    memset(token, 0, token_size);

    return 0;
}
