#include <unistd.h>
#include <string.h>

void gen_token(unsigned char out[32]);

int send_session_token(int fd) {
    unsigned char token[32];
    size_t total = 0;
    ssize_t written;

    gen_token(token);

    while (total < sizeof(token)) {
        written = write(fd, token + total, sizeof(token) - total);

        if (written < 0) {
            memset(token, 0, sizeof(token));
            return -1;
        }

        if (written == 0) {
            memset(token, 0, sizeof(token));
            return -1;
        }

        total += (size_t)written;
    }

    memset(token, 0, sizeof(token));
    return 0;
}
