#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>

void gen_token(unsigned char out[32]);

int send_session_token(int fd)
{
    unsigned char token[32];
    size_t sent = 0;
    int ret = 0;

    gen_token(token);

    while (sent < sizeof(token)) {
        ssize_t n = write(fd, token + sent, sizeof(token) - sent);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            ret = -1;
            break;
        }
        if (n == 0) {
            ret = -1;
            break;
        }
        sent += (size_t)n;
    }

    memset(token, 0, sizeof(token));

    return ret;
}
