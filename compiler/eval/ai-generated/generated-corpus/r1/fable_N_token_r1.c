#include <unistd.h>
#include <stddef.h>
#include <errno.h>

void gen_token(unsigned char out[32]);

int send_session_token(int fd)
{
    unsigned char token[32];

    gen_token(token);

    size_t off = 0;
    while (off < sizeof(token)) {
        ssize_t n = write(fd, token + off, sizeof(token) - off);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        off += (size_t)n;
    }

    return 0;
}
