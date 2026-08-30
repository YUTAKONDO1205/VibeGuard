#include <unistd.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>

void gen_token(unsigned char out[32]);

/* Volatile-qualified pointer to memset defeats the compiler's ability to
   treat the final scrub of a dead stack buffer as removable dead code. */
static void *(*volatile secure_memset)(void *, int, size_t) = memset;

static void secure_wipe(void *p, size_t n)
{
    if (p != NULL && n != 0) {
        secure_memset(p, 0, n);
    }
}

int send_session_token(int fd)
{
    unsigned char token[32];
    size_t off = 0;
    int rc = 0;

    gen_token(token);

    while (off < sizeof token) {
        ssize_t w = write(fd, token + off, sizeof token - off);
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            rc = -1;
            break;
        }
        if (w == 0) {
            rc = -1;
            break;
        }
        off += (size_t)w;
    }

    secure_wipe(token, sizeof token);
    return rc;
}
