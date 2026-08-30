#include <stddef.h>
#include <errno.h>
#include <unistd.h>

void gen_token(unsigned char out[32]);

/*
 * Wipe that the compiler may not elide: write through a volatile
 * pointer-to-volatile function pointer would be overkill; a volatile
 * qualified pointer walk is the portable baseline, reinforced by a
 * compiler barrier that makes the buffer "used" after the stores.
 */
static void secure_wipe(void *p, size_t n)
{
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (n--)
        *vp++ = 0;
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
}

int send_session_token(int fd)
{
    unsigned char token[32];
    size_t off = 0;
    int rc = 0;

    gen_token(token);

    while (off < sizeof(token)) {
        ssize_t n = write(fd, token + off, sizeof(token) - off);
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
        off += (size_t)n;
    }

    secure_wipe(token, sizeof(token));
    return rc;
}
