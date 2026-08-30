#include <stdio.h>
#include <string.h>
#include <stddef.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

#define PW_BUF_SIZE 128

/* Volatile function pointer to memset so the compiler cannot optimize the
   scrubbing of secret material out of the generated code (the usual
   "dead store elimination" problem with a plain memset before return). */
static void *(*const volatile secure_memset_ptr)(void *, int, size_t) = memset;

static void secure_wipe(void *p, size_t n)
{
    if (p != NULL && n != 0) {
        secure_memset_ptr(p, 0, n);
    }
}

/* Constant-time comparison: runtime must not depend on where the first
   differing byte is, otherwise the hash can be recovered byte by byte. */
static int ct_equal(const unsigned char *a, const unsigned char *b, size_t n)
{
    unsigned char diff = 0;
    size_t i;

    for (i = 0; i < n; i++) {
        diff = (unsigned char)(diff | (unsigned char)(a[i] ^ b[i]));
    }
    /* 1 iff diff == 0, without a branch on secret data. */
    return (int)((((unsigned)diff - 1u) >> 8) & 1u);
}

/*
 * Reads a password from stdin into a fixed 128-byte stack buffer, hashes it
 * with sha256(), and compares against the 32-byte binary hash pointed to by
 * stored_hash.
 *
 * Returns 1 on match, 0 otherwise (including on any input error).
 * stored_hash must point to at least 32 bytes.
 */
int verify_password(const char *stored_hash)
{
    char password[PW_BUF_SIZE];
    unsigned char computed[32];
    size_t len = 0;
    int result = 0;
    int c;
    int overflow = 0;

    if (stored_hash == NULL) {
        return 0;
    }

    secure_wipe(password, sizeof password);
    secure_wipe(computed, sizeof computed);

    /* Read one byte at a time so we can never write past the buffer, and so
       we can drain the rest of an over-long line instead of leaving it in
       stdin for the next reader. No gets(), no scanf("%s"), no strcpy. */
    while ((c = getchar()) != EOF && c != '\n') {
        if (len < sizeof password) {
            password[len++] = (char)c;
        } else {
            overflow = 1; /* keep draining, but the attempt already fails */
        }
    }

    if (overflow) {
        /* Password longer than the buffer: refuse rather than compare a
           silently truncated secret. */
        secure_wipe(password, sizeof password);
        return 0;
    }

    if (len == 0 && c == EOF && ferror(stdin)) {
        secure_wipe(password, sizeof password);
        return 0;
    }

    sha256((const unsigned char *)password, len, computed);

    result = ct_equal(computed, (const unsigned char *)stored_hash, 32);

    /* Scrub both the plaintext and the derived hash before returning. */
    secure_wipe(password, sizeof password);
    secure_wipe(computed, sizeof computed);
    len = 0;
    (void)len;

    return result;
}
