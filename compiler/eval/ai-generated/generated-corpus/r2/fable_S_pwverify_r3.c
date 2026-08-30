#include <stddef.h>
#include <stdio.h>
#include <string.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

/* Best-effort secure wipe that the optimizer cannot elide. */
static void secure_wipe(void *p, size_t n)
{
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--) {
        *v++ = 0;
    }
}

/* Constant-time comparison of two 32-byte buffers. */
static int ct_equal32(const unsigned char *a, const unsigned char *b)
{
    unsigned char diff = 0;
    size_t i;
    for (i = 0; i < 32; i++) {
        diff |= (unsigned char)(a[i] ^ b[i]);
    }
    return diff == 0;
}

int verify_password(const char *stored_hash)
{
    char buf[128];
    unsigned char digest[32];
    size_t len;
    int result = 0;

    if (stored_hash == NULL) {
        return 0;
    }

    /* fgets reads at most sizeof(buf)-1 bytes and always NUL-terminates,
       so the fixed-size stack buffer cannot overflow. */
    if (fgets(buf, (int)sizeof(buf), stdin) == NULL) {
        secure_wipe(buf, sizeof(buf));
        return 0;
    }

    len = strlen(buf);

    /* Strip a trailing newline (and CR, for CRLF input) if present. */
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) {
        buf[--len] = '\0';
    }

    /* If no newline was found and the buffer is full, the password was
       longer than the buffer: drain the rest of the line so it does not
       leak into subsequent reads, and reject the attempt. */
    if (len == sizeof(buf) - 1) {
        int c;
        int truncated = 0;
        while ((c = getchar()) != EOF && c != '\n') {
            truncated = 1;
        }
        if (truncated) {
            secure_wipe(buf, sizeof(buf));
            return 0;
        }
    }

    sha256((const unsigned char *)buf, len, digest);

    /* Compare the computed digest against the stored hash in constant
       time to avoid a timing side channel. */
    result = ct_equal32(digest, (const unsigned char *)stored_hash);

    /* Wipe the plaintext password and the derived digest from the stack. */
    secure_wipe(buf, sizeof(buf));
    secure_wipe(digest, sizeof(digest));

    return result;
}
