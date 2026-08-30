#include <stdio.h>
#include <stddef.h>
#include <string.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

/*
 * Read a password from stdin into a fixed 128-byte stack buffer, hash it with
 * SHA-256, and compare against the provided stored hash.
 *
 * stored_hash is expected to point to 32 bytes (a raw SHA-256 digest).
 * Returns 1 on match, 0 on mismatch or error.
 */
int verify_password(const char *stored_hash)
{
    unsigned char password[128];
    unsigned char digest[32];
    size_t len = 0;
    int c;
    int result;
    volatile unsigned char *p;
    size_t i;

    if (stored_hash == NULL) {
        return 0;
    }

    /* Read up to sizeof(password) bytes, stopping at newline or EOF.
     * We never write past the buffer; excess input is drained so it cannot
     * leak into a subsequent read. */
    while (len < sizeof(password)) {
        c = getchar();
        if (c == EOF || c == '\n') {
            break;
        }
        password[len++] = (unsigned char)c;
    }

    /* If input was longer than the buffer, treat it as a failed verification
     * rather than silently truncating and comparing a partial password. */
    if (len == sizeof(password)) {
        c = getchar();
        if (c != EOF && c != '\n') {
            /* Drain the rest of the line. */
            while (c != EOF && c != '\n') {
                c = getchar();
            }
            /* Wipe sensitive material before returning. */
            p = (volatile unsigned char *)password;
            for (i = 0; i < sizeof(password); i++) {
                p[i] = 0;
            }
            return 0;
        }
    }

    sha256(password, len, digest);

    /* Constant-time comparison of the two 32-byte digests to avoid leaking
     * information through timing. */
    {
        unsigned char diff = 0;
        for (i = 0; i < sizeof(digest); i++) {
            diff |= (unsigned char)(digest[i] ^ (unsigned char)stored_hash[i]);
        }
        result = (diff == 0) ? 1 : 0;
    }

    /* Scrub sensitive material from the stack. The volatile pointer prevents
     * the compiler from optimizing the wipe away. */
    p = (volatile unsigned char *)password;
    for (i = 0; i < sizeof(password); i++) {
        p[i] = 0;
    }
    p = (volatile unsigned char *)digest;
    for (i = 0; i < sizeof(digest); i++) {
        p[i] = 0;
    }

    return result;
}
