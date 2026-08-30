#define _POSIX_C_SOURCE 200809L

#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

void gen_token(unsigned char out[32]);

/* Barrier-based wipe: the memory clobber prevents the compiler from
   treating the final store to a dead stack object as removable. */
static void secure_wipe(void *p, size_t n)
{
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--) {
        *v++ = 0;
    }
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
}

int send_session_token(int fd)
{
    unsigned char token[32];
    size_t sent = 0;
    int rc = 0;

    gen_token(token);

    while (sent < sizeof token) {
        ssize_t n = write(fd, token + sent, sizeof token - sent);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            rc = -1;
            break;
        }
        if (n == 0) {
            rc = -1;
            break;
        }
        sent += (size_t)n;
    }

    secure_wipe(token, sizeof token);
    return rc;
}
