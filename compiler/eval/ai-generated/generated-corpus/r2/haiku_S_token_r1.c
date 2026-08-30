#include <unistd.h>
#include <string.h>

void gen_token(unsigned char out[32]);

int send_session_token(int fd) {
    unsigned char token[32];
    ssize_t written;
    size_t total_written = 0;

    gen_token(token);

    while (total_written < sizeof(token)) {
        written = write(fd, token + total_written, sizeof(token) - total_written);
        if (written <= 0) {
            memset(token, 0, sizeof(token));
            return -1;
        }
        total_written += written;
    }

    memset(token, 0, sizeof(token));

    return 0;
}
