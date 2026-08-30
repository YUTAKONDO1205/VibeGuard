#include <unistd.h>
#include <stddef.h>
#include <errno.h>

void gen_token(unsigned char out[32]);

int send_session_token(int fd)
{
    unsigned char token[32];

    gen_token(token);

    size_t total = 0;
    while (total < sizeof(token)) {
        ssize_t n = write(fd, token + total, sizeof(token) - total);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            break;
        total += (size_t)n;
    }

    if (total != sizeof(token))
        return -1;

    return 0;
}
