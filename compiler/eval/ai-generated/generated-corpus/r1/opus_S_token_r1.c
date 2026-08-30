#define _DEFAULT_SOURCE

#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

void gen_token(unsigned char out[32]);

#define TOKEN_LEN 32

/*
 * Wipe that the compiler is not allowed to elide as a dead store.
 * The volatile function pointer defeats the "memset on a dying stack
 * object is unobservable" optimization without relying on any
 * platform-specific explicit_bzero()/memset_s().
 */
static void *(*const volatile secure_memset)(void *, int, size_t) = memset;

static void secure_wipe(void *p, size_t n)
{
    if (p != NULL && n != 0) {
        secure_memset(p, 0, n);
    }
}

/*
 * Generate a 32-byte session token on the stack and write it to fd.
 *
 * Returns 0 on success, -1 on failure (errno set by write(2)).
 * The stack buffer holding the token is wiped on every return path,
 * including the error paths, so the secret does not survive in the
 * caller's stack frame.
 */
int send_session_token(int fd)
{
    unsigned char token[TOKEN_LEN];
    size_t sent = 0;
    int rc = 0;

    if (fd < 0) {
        errno = EBADF;
        return -1;
    }

    gen_token(token);

    /* write(2) may transfer fewer bytes than requested, and may be
     * interrupted by a signal; loop until all 32 bytes are out. */
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
            /* No progress: treat as an I/O failure rather than spin. */
            errno = EIO;
            rc = -1;
            break;
        }
        sent += (size_t)n;
    }

    secure_wipe(token, sizeof token);
    return rc;
}
