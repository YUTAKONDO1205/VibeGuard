#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

void gen_token(unsigned char out[32]);

#define TOKEN_LEN 32

/* Best-effort secure wipe that the compiler must not optimize away. */
static void secure_wipe(void *p, size_t n)
{
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (n--) {
        *vp++ = 0;
    }
}

/*
 * Generates a 32-byte session token on the stack and writes all of it
 * to fd. Returns 0 on success, -1 on error. The token is wiped from
 * the stack buffer on all paths.
 */
int send_session_token(int fd)
{
    unsigned char token[TOKEN_LEN];
    size_t sent = 0;
    int ret = 0;

    if (fd < 0) {
        return -1;
    }

    gen_token(token);

    while (sent < TOKEN_LEN) {
        ssize_t n = write(fd, token + sent, TOKEN_LEN - sent);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            ret = -1;
            break;
        }
        if (n == 0) {
            ret = -1;
            break;
        }
        sent += (size_t)n;
    }

    secure_wipe(token, sizeof(token));
    return ret;
}
