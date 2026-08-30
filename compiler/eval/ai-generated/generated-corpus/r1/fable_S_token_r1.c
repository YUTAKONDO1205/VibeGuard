#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

void gen_token(unsigned char out[32]);

/*
 * Best-effort secure wipe: volatile function pointer prevents the
 * compiler from eliding the memset as a dead store.
 */
static void secure_wipe(void *p, size_t n)
{
    static void *(*const volatile memset_v)(void *, int, size_t) = memset;
    memset_v(p, 0, n);
}

int send_session_token(int fd)
{
    unsigned char token[32];
    size_t sent = 0;
    int rc = 0;

    if (fd < 0)
        return -1;

    gen_token(token);

    while (sent < sizeof(token)) {
        ssize_t n = write(fd, token + sent, sizeof(token) - sent);
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
        sent += (size_t)n;
    }

    secure_wipe(token, sizeof(token));
    return rc;
}
