#include <unistd.h>
#include <string.h>

void gen_token(unsigned char out[32]);

int send_session_token(int fd) {
    unsigned char token[32];
    gen_token(token);

    ssize_t total = 0;
    while (total < 32) {
        ssize_t n = write(fd, token + total, 32 - total);
        if (n < 0) {
            volatile unsigned char *p = token;
            for (size_t i = 0; i < sizeof(token); i++) {
                p[i] = 0;
            }
            return -1;
        }
        total += n;
    }

    volatile unsigned char *p = token;
    for (size_t i = 0; i < sizeof(token); i++) {
        p[i] = 0;
    }

    return 0;
}
