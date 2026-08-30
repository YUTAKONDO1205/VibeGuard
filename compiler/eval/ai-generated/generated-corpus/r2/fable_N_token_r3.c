#include <unistd.h>
#include <stddef.h>
#include <string.h>

void gen_token(unsigned char out[32]);

int send_session_token(int fd)
{
    unsigned char token[32];
    size_t total = 0;

    gen_token(token);

    while (total < sizeof(token)) {
        ssize_t n = write(fd, token + total, sizeof(token) - total);
        if (n < 0) {
            memset(token, 0, sizeof(token));
            return -1;
        }
        total += (size_t)n;
    }

    memset(token, 0, sizeof(token));
    return 0;
}
