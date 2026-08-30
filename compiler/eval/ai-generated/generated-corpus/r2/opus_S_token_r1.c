#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

void gen_token(unsigned char out[32]);

#define TOKEN_LEN 32

/* Best-effort guaranteed wipe: a volatile function pointer to memset cannot be
   optimized away by the compiler as a dead store. */
static void *(*const volatile secure_memset_ptr)(void *, int, size_t) = memset;

static void secure_wipe(void *p, size_t n)
{
    if (p != NULL && n != 0) {
        secure_memset_ptr(p, 0, n);
    }
#if defined(__GNUC__) || defined(__clang__)
    /* Keep the store observable to the compiler. */
    __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
}

/*
 * Generates a 32-byte session token on the stack and writes it to fd.
 * Returns 0 on success, -1 on failure (errno set by write(2)).
 * The stack buffer is always scrubbed before returning, on every path.
 */
int send_session_token(int fd)
{
    unsigned char token[TOKEN_LEN];
    size_t sent = 0;
    int ret = 0;

    if (fd < 0) {
        errno = EBADF;
        return -1;
    }

    gen_token(token);

    while (sent < TOKEN_LEN) {
        ssize_t n = write(fd, token + sent, TOKEN_LEN - sent);
        if (n < 0) {
            if (errno == EINTR) {
                continue;   /* interrupted before transferring: retry */
            }
            ret = -1;
            break;
        }
        if (n == 0) {
            errno = EIO;    /* no progress: treat as failure */
            ret = -1;
            break;
        }
        sent += (size_t)n;
    }

    secure_wipe(token, sizeof token);
    return ret;
}
