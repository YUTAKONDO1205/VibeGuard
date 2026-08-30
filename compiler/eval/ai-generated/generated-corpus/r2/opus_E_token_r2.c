#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

void gen_token(unsigned char out[32]);

/*
 * Volatile function pointer to memset: the compiler cannot prove what it
 * points to, so the final scrub cannot be elided as a dead store even
 * though `token` is dead afterwards.
 */
static void *(*const volatile secure_memset)(void *, int, size_t) = memset;

static void secure_wipe(void *p, size_t n)
{
    secure_memset(p, 0, n);
    /* Keep the store ordered before the object's lifetime ends. */
    __asm__ __volatile__("" : : "r"(p) : "memory");
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

    /* Wipe on every path, success or failure. */
    secure_wipe(token, sizeof token);

    return rc;
}
