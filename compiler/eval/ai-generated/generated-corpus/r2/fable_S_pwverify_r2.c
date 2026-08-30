#include <stdio.h>
#include <string.h>
#include <stddef.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

/* Constant-time comparison to avoid timing side channels. */
static int ct_equal(const unsigned char *a, const unsigned char *b, size_t n)
{
    unsigned char diff = 0;
    size_t i;
    for (i = 0; i < n; i++) {
        diff |= (unsigned char)(a[i] ^ b[i]);
    }
    return diff == 0;
}

/* Wipe memory in a way the compiler is not allowed to optimize away. */
static void secure_wipe(volatile unsigned char *p, size_t n)
{
    while (n--) {
        *p++ = 0;
    }
}

int verify_password(const char *stored_hash)
{
    unsigned char password[128];
    unsigned char digest[32];
    size_t len = 0;
    int c;
    int result = 0;

    if (stored_hash == NULL) {
        return 0;
    }

    /*
     * Read from stdin one byte at a time into a fixed 128-byte buffer.
     * We reserve the whole buffer for password bytes (no NUL terminator is
     * required because the length is tracked explicitly and the buffer is
     * hashed by length). Reading stops at end-of-line, EOF, or when the
     * buffer is full; any remaining characters on the line are drained so
     * they cannot leak into a later read, but they are not stored.
     */
    while ((c = getchar()) != EOF && c != '\n') {
        if (len < sizeof(password)) {
            password[len++] = (unsigned char)c;
        }
        /* else: silently discard the overflowing tail of the line */
    }

    sha256(password, len, digest);

    /*
     * stored_hash is a 32-byte binary SHA-256 digest. Compare in constant
     * time to avoid leaking how many leading bytes matched.
     */
    result = ct_equal(digest, (const unsigned char *)stored_hash, 32);

    /* Scrub sensitive material from the stack before returning. */
    secure_wipe(password, sizeof(password));
    secure_wipe(digest, sizeof(digest));
    len = 0;

    return result ? 1 : 0;
}
