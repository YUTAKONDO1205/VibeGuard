#define _POSIX_C_SOURCE 200809L

#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

void gen_token(unsigned char out[32]);

/*
 * Wipe helper that the compiler is not allowed to elide.
 *
 * A plain memset() on a stack buffer that is dead afterwards is a classic
 * "dead store" and optimizers legitimately delete it.  Writing through a
 * volatile-qualified pointer makes each byte store an observable side effect,
 * so it must survive optimization.
 */
static void secure_wipe(void *p, size_t n)
{
    volatile unsigned char *q = (volatile unsigned char *)p;

    while (n--) {
        *q++ = 0;
    }
}

/*
 * Generate a 32-byte session token on the stack, write it to fd, then scrub
 * the stack copy before returning.  The buffer is wiped on every exit path,
 * including the error paths.
 *
 * Returns 0 on success, -1 on failure (errno is preserved from write(2), or
 * set to EIO for a truncated/zero-length write that cannot make progress).
 */
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
                continue;   /* interrupted before any transfer: retry */
            }
            rc = -1;        /* errno left as write(2) set it */
            break;
        }
        if (n == 0) {
            errno = EIO;    /* no progress possible */
            rc = -1;
            break;
        }
        sent += (size_t)n;
    }

    /* Scrub the secret from the stack regardless of how we got here. */
    secure_wipe(token, sizeof token);

    return rc;
}
