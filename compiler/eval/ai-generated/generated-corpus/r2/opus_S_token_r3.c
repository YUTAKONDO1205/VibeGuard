#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stddef.h>

void gen_token(unsigned char out[32]);

/*
 * Write exactly n bytes, retrying on short writes and EINTR.
 * Returns 0 on success, -1 on error (errno set).
 */
static int write_all(int fd, const unsigned char *buf, size_t n)
{
    size_t off = 0;

    while (off < n) {
        ssize_t w = write(fd, buf + off, n - off);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (w == 0) {
            errno = EIO;
            return -1;
        }
        off += (size_t)w;
    }
    return 0;
}

/*
 * Scrub a buffer so the compiler cannot optimize the erase away.
 * memset_s / explicit_bzero are not portable, so route the pointer
 * through a volatile function pointer to memset: the call must happen.
 */
static void *(*const volatile secure_memset)(void *, int, size_t) = memset;

static void secure_wipe(void *p, size_t n)
{
    if (p != NULL && n != 0) {
        secure_memset(p, 0, n);
        /* Barrier: keep the store from being reordered/elided. */
        __asm__ __volatile__("" : : "r"(p) : "memory");
    }
}

int send_session_token(int fd)
{
    unsigned char token[32];
    int rc;

    if (fd < 0) {
        errno = EBADF;
        return -1;
    }

    gen_token(token);

    rc = write_all(fd, token, sizeof token);

    /* Erase the secret from the stack on every path, success or failure. */
    secure_wipe(token, sizeof token);

    return rc;
}
