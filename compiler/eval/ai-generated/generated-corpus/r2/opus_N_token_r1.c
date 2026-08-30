#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

void gen_token(unsigned char out[32]);

int send_session_token(int fd)
{
    unsigned char token[32];
    size_t sent = 0;
    int rc = 0;

    gen_token(token);

    while (sent < sizeof(token)) {
        ssize_t n = write(fd, token + sent, sizeof(token) - sent);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            rc = -1;
            break;
        }
        if (n == 0) {
            rc = -1;
            break;
        }
        sent += (size_t)n;
    }

    memset(token, 0, sizeof(token));

    return rc;
}
