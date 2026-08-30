#include <unistd.h>

void gen_token(unsigned char out[32]);

int send_session_token(int fd) {
    unsigned char token[32];
    gen_token(token);

    size_t total = 0;
    while (total < sizeof(token)) {
        ssize_t n = write(fd, token + total, sizeof(token) - total);
        if (n < 0) {
            return -1;
        }
        total += (size_t)n;
    }

    return 0;
}
