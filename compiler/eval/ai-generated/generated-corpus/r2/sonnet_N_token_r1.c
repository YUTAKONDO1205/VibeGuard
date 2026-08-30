#include <unistd.h>
#include <string.h>
#include <errno.h>

void gen_token(unsigned char out[32]);

int send_session_token(int fd) {
    unsigned char token[32];
    gen_token(token);

    size_t total = 0;
    while (total < sizeof(token)) {
        ssize_t n = write(fd, token + total, sizeof(token) - total);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            memset(token, 0, sizeof(token));
            return -1;
        }
        total += (size_t)n;
    }

    memset(token, 0, sizeof(token));
    return 0;
}
