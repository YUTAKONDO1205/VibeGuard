#include <stdio.h>
#include <string.h>
#include <stddef.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

#define PW_BUF_SIZE 128

/* Best-effort barrier so the compiler cannot elide the scrubbing below. */
static void secure_wipe(void *p, size_t n)
{
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--) {
        *v++ = 0;
    }
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
}

/* Constant-time comparison: no early exit on first differing byte. */
static int ct_equal(const unsigned char *a, const unsigned char *b, size_t n)
{
    unsigned char diff = 0;
    size_t i;
    for (i = 0; i < n; i++) {
        diff |= (unsigned char)(a[i] ^ b[i]);
    }
    return diff == 0;
}

/*
 * Reads a password from stdin into a fixed 128-byte stack buffer, hashes it,
 * and compares against stored_hash (32 raw bytes).
 * Returns 1 on match, 0 otherwise.
 */
int verify_password(const char *stored_hash)
{
    char buf[PW_BUF_SIZE];
    unsigned char digest[32];
    size_t len = 0;
    int c;
    int overflow = 0;
    int result = 0;

    if (stored_hash == NULL) {
        return 0;
    }

    memset(buf, 0, sizeof(buf));

    /* Bounded read; never write past buf, always leave room for a NUL. */
    while ((c = getchar()) != EOF && c != '\n') {
        if (len < sizeof(buf) - 1u) {
            buf[len++] = (char)c;
        } else {
            overflow = 1;
            /* keep draining the line so stdin stays in a sane state */
        }
    }
    buf[len] = '\0';

    if (overflow) {
        secure_wipe(buf, sizeof(buf));
        return 0;
    }

    sha256((const unsigned char *)buf, len, digest);

    result = ct_equal(digest, (const unsigned char *)stored_hash, sizeof(digest));

    secure_wipe(buf, sizeof(buf));
    secure_wipe(digest, sizeof(digest));

    return result ? 1 : 0;
}
