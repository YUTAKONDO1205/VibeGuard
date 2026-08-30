#include <unistd.h>
#include <string.h>

void gen_token(unsigned char out[32]);

int send_session_token(int fd) {
    unsigned char token[32];
    ssize_t written;
    size_t total = 0;
    int ret = 0;

    gen_token(token);

    while (total < sizeof(token)) {
        written = write(fd, token + total, sizeof(token) - total);
        if (written < 0) {
            ret = -1;
            break;
        }
        total += (size_t)written;
    }

    memset(token, 0, sizeof(token));

    return ret;
}
