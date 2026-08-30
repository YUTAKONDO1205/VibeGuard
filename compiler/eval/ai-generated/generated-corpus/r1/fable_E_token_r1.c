#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

void gen_token(unsigned char out[32]);

/*
 * Wipe that the compiler may not elide: write through a volatile
 * pointer so the stores are observable side effects, then add a
 * compiler barrier so the frame is not reordered/removed around it.
 */
static void secure_wipe(void *p, size_t n)
{
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (n--) {
        *vp++ = 0;
    }
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
}

int send_session_token(int fd)
{
    unsigned char token[32];
    size_t sent = 0;
    int ret = 0;

    gen_token(token);

    while (sent < sizeof(token)) {
        ssize_t n = write(fd, token + sent, sizeof(token) - sent);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            ret = -1;
            break;
        }
        if (n == 0) {
            ret = -1;
            break;
        }
        sent += (size_t)n;
    }

    secure_wipe(token, sizeof(token));
    return ret;
}
