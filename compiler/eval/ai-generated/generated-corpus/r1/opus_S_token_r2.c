#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stddef.h>

void gen_token(unsigned char out[32]);

/*
 * Overwrite a buffer in a way the compiler is not allowed to elide.
 * memset() on a soon-to-be-dead stack object is a classic dead-store
 * elimination target, so route the pointer through a volatile function
 * pointer and write through a volatile view of the memory.
 */
static void *(*const volatile secure_memset_fn)(void *, int, size_t) = memset;

static void secure_wipe(void *p, size_t n)
{
    if (p == NULL || n == 0) {
        return;
    }
    (void)secure_memset_fn(p, 0, n);
    /* Barrier: keep the store from being reordered/removed. */
    __asm__ __volatile__("" : : "r"(p) : "memory");
}

/*
 * Generate a 32-byte session token on the stack and write it to fd.
 * Returns 0 on success, -1 on failure (errno set by write(2)).
 * The token is always wiped from the stack before returning.
 */
int send_session_token(int fd)
{
    unsigned char token[32];
    size_t sent = 0;
    int rc = 0;

    if (fd < 0) {
        errno = EBADF;
        return -1;
    }

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
            /* No progress: treat as an I/O failure rather than spinning. */
            errno = EIO;
            rc = -1;
            break;
        }
        sent += (size_t)n;
    }

    secure_wipe(token, sizeof token);
    return rc;
}
