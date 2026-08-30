#include <unistd.h>
#include <errno.h>
#include <string.h>

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

    /* Wipe the used secret from the stack so it does not linger in memory.
       memset_s avoids being optimized away; fall back to a volatile wipe. */
#if defined(__STDC_LIB_EXT1__)
    memset_s(token, sizeof(token), 0, sizeof(token));
#else
    {
        volatile unsigned char *p = token;
        size_t i;
        for (i = 0; i < sizeof(token); i++)
            p[i] = 0;
    }
#endif

    return ret;
}
