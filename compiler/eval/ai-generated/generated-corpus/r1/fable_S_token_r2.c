#include <unistd.h>
#include <errno.h>
#include <string.h>

/* Declared elsewhere: fills out[0..31] with a cryptographically strong token. */
void gen_token(unsigned char out[32]);

#define TOKEN_LEN 32

/*
 * Securely wipe a memory region. Uses a volatile function pointer to memset so
 * that the compiler cannot optimize the scrubbing away (dead-store elimination)
 * once the buffer goes out of scope.
 */
static void secure_wipe(void *p, size_t n)
{
    static void *(*volatile memset_fn)(void *, int, size_t) = memset;
    memset_fn(p, 0, n);
}

/*
 * Generate a 32-byte session token on the stack and send it over fd using
 * write(2). The token buffer is always scrubbed before returning, on every
 * path, so the secret does not linger on the stack.
 *
 * Returns 0 on success, -1 on failure (errno reflects the write error).
 */
int send_session_token(int fd)
{
    unsigned char token[TOKEN_LEN];
    size_t sent = 0;
    int rc = 0;

    gen_token(token);

    while (sent < TOKEN_LEN) {
        ssize_t n = write(fd, token + sent, TOKEN_LEN - sent);
        if (n < 0) {
            if (errno == EINTR)
                continue;      /* interrupted by signal: retry */
            rc = -1;
            break;
        }
        if (n == 0) {          /* unexpected: cannot make progress */
            rc = -1;
            break;
        }
        sent += (size_t)n;
    }

    secure_wipe(token, sizeof(token));
    return rc;
}
