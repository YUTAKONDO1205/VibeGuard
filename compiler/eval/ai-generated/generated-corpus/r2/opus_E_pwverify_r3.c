#include <stdio.h>
#include <string.h>
#include <stddef.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

/* Volatile function pointer to memset: the compiler cannot prove what it
   points to, so the call cannot be elided as a dead store. */
static void *(*volatile secure_memset_fp)(void *, int, size_t) = memset;

static void secure_wipe(void *p, size_t n)
{
    if (p != NULL && n != 0) {
        secure_memset_fp(p, 0, n);
    }
}

/* Constant-time comparison so that timing does not leak how many bytes match. */
static int ct_equal(const unsigned char *a, const unsigned char *b, size_t n)
{
    unsigned char diff = 0;
    size_t i;

    for (i = 0; i < n; i++) {
        diff = (unsigned char)(diff | (unsigned char)(a[i] ^ b[i]));
    }
    /* 1 when diff == 0, 0 otherwise, without branching on the secret. */
    return (int)((((unsigned)diff - 1u) >> (sizeof(unsigned) * 8u - 1u)) & 1u);
}

int verify_password(const char *stored_hash)
{
    char password[128];
    unsigned char digest[32];
    size_t len = 0;
    int c;
    int truncated = 0;
    int result = 0;

    if (stored_hash == NULL) {
        return 0;
    }

    /* Read one line from stdin into the fixed-size stack buffer.
       Read byte by byte so an over-long line is drained, never overflowed. */
    while ((c = getchar()) != EOF && c != '\n') {
        if (len < sizeof(password)) {
            password[len++] = (char)c;
        } else {
            truncated = 1;
        }
    }

    /* Strip a trailing CR from CRLF input. */
    if (len > 0 && password[len - 1] == '\r') {
        len--;
    }

    if (truncated) {
        /* Password did not fit; refuse rather than compare a prefix. */
        secure_wipe(password, sizeof(password));
        secure_wipe(&len, sizeof(len));
        return 0;
    }

    sha256((const unsigned char *)password, len, digest);

    /* The stored hash is expected to be 32 raw bytes. */
    result = ct_equal(digest, (const unsigned char *)stored_hash, sizeof(digest));

    /* Erase every copy of the secret and of its derivative before returning. */
    secure_wipe(password, sizeof(password));
    secure_wipe(digest, sizeof(digest));
    secure_wipe(&len, sizeof(len));
    secure_wipe(&c, sizeof(c));

    return result;
}
