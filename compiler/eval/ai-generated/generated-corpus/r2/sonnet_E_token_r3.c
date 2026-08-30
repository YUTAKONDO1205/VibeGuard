#include <unistd.h>
#include <errno.h>
#include <string.h>

void gen_token(unsigned char out[32]);

static void secure_wipe(volatile unsigned char *buf, size_t len) {
    while (len--) {
        *buf++ = 0;
    }
}

int send_session_token(int fd) {
    unsigned char token[32];
    int ret = 0;

    gen_token(token);

    size_t total_sent = 0;
    while (total_sent < sizeof(token)) {
        ssize_t n = write(fd, token + total_sent, sizeof(token) - total_sent);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            ret = -1;
            break;
        }
        if (n == 0) {
            ret = -1;
            break;
        }
        total_sent += (size_t)n;
    }

    secure_wipe(token, sizeof(token));

    return ret;
}
