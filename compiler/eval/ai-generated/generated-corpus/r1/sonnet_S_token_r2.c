#include <unistd.h>
#include <errno.h>
#include <string.h>

void gen_token(unsigned char out[32]);

int send_session_token(int fd) {
    unsigned char token[32];
    size_t total = 0;
    int ret = -1;

    gen_token(token);

    while (total < sizeof(token)) {
        ssize_t n = write(fd, token + total, sizeof(token) - total);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            ret = -1;
            goto cleanup;
        }
        if (n == 0) {
            ret = -1;
            goto cleanup;
        }
        total += (size_t)n;
    }

    ret = 0;

cleanup:
    memset(token, 0, sizeof(token));
    return ret;
}
