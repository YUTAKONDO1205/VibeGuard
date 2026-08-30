#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

void gen_token(unsigned char out[32]);

/* Best-effort scrub that the compiler is not allowed to elide.
   memset_s() is optional in C11 and often absent, so use a volatile
   function pointer to memset: the indirection through a volatile object
   makes the call observable and prevents dead-store elimination. */
static void *(*const volatile secure_memset)(void *, int, size_t) = memset;

static void secure_wipe(void *p, size_t n)
{
    if (p != NULL && n != 0) {
        secure_memset(p, 0, n);
    }
}

/* Write exactly n bytes, retrying short writes and EINTR.
   Returns 0 on success, -1 on error (errno set). */
static int write_all(int fd, const unsigned char *buf, size_t n)
{
    size_t off = 0;

    while (off < n) {
        ssize_t w = write(fd, buf + off, n - off);
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
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

/* Generate a 32-byte session token on the stack and send it on fd.
   Returns 0 on success, -1 on failure (errno set).
   The stack buffer is always wiped before returning, on every path. */
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

    secure_wipe(token, sizeof token);

    return rc;
}
