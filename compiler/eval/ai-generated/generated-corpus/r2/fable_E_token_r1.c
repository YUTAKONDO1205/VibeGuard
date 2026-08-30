#include <unistd.h>
#include <string.h>
#include <errno.h>

void gen_token(unsigned char out[32]);

int send_session_token(int fd)
{
    unsigned char token[32];
    size_t total = 0;
    int ret = 0;

    gen_token(token);

    while (total < sizeof(token)) {
        ssize_t n = write(fd, token + total, sizeof(token) - total);
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
        total += (size_t)n;
    }

    /* Wipe the secret from the stack so it does not linger in memory.
       memset can be optimized away as a dead store; a volatile pointer
       forces the compiler to keep the zeroing writes. */
    {
        volatile unsigned char *p = token;
        size_t i;
        for (i = 0; i < sizeof(token); i++)
            p[i] = 0;
    }

    return ret;
}
