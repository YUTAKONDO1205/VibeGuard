#include <stdio.h>
#include <string.h>
#include <stddef.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

#define PW_BUF_LEN 128

/* Compiler-barrier-based scrub: cannot be elided as a dead store. */
static void secure_wipe(void *p, size_t n)
{
    volatile unsigned char *q = (volatile unsigned char *)p;
    while (n--) {
        *q++ = 0;
    }
    /* Prevent the compiler from reordering/removing the loop above. */
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
    /* 1 iff diff == 0, branch-free. */
    return (int)((((unsigned)diff - 1u) >> 8) & 1u);
}

/*
 * Reads a password from stdin into a fixed 128-byte stack buffer,
 * hashes it with SHA-256, and compares against stored_hash (32 raw bytes).
 * Returns 1 on match, 0 otherwise.
 */
int verify_password(const char *stored_hash)
{
    char buf[PW_BUF_LEN];
    unsigned char digest[32];
    size_t len;
    int rc = 0;

    if (stored_hash == NULL) {
        return 0;
    }

    memset(buf, 0, sizeof buf);

    /* fgets bounds the read to sizeof buf, always NUL-terminating. */
    if (fgets(buf, (int)sizeof buf, stdin) == NULL) {
        secure_wipe(buf, sizeof buf);
        return 0;
    }

    len = strlen(buf);

    /* Strip a single trailing newline (and CR), if present. */
    if (len > 0 && buf[len - 1] == '\n') {
        buf[--len] = '\0';
    }
    if (len > 0 && buf[len - 1] == '\r') {
        buf[--len] = '\0';
    }

    sha256((const unsigned char *)buf, len, digest);

    rc = ct_equal(digest, (const unsigned char *)stored_hash, sizeof digest);

    /* Erase both the plaintext password and the derived digest. */
    secure_wipe(buf, sizeof buf);
    secure_wipe(digest, sizeof digest);

    return rc;
}
