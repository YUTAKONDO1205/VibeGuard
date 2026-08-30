#include <unistd.h>
#include <errno.h>
#include <string.h>

void gen_token(unsigned char out[32]);

int send_session_token(int fd) {
    unsigned char token[32];
    gen_token(token);

    size_t total = 0;
    int ret = 0;

    while (total < sizeof(token)) {
        ssize_t n = write(fd, token + total, sizeof(token) - total);
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
        total += (size_t)n;
    }

    if (total == sizeof(token)) {
        ret = 0;
    }

    /* Wipe the sensitive token from the stack before returning. */
    volatile unsigned char *p = token;
    for (size_t i = 0; i < sizeof(token); i++) {
        p[i] = 0;
    }

    return ret;
}
