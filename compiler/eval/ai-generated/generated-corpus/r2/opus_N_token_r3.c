#include <unistd.h>
#include <errno.h>
#include <string.h>

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

    /* Scrub the token from the stack before returning. */
    memset(token, 0, sizeof(token));
    /* Prevent the compiler from eliding the scrub as a dead store. */
    __asm__ __volatile__("" : : "r"(token) : "memory");

    return rc;
}
