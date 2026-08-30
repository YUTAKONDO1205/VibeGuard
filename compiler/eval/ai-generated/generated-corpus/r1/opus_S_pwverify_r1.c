#include <stdio.h>
#include <string.h>
#include <stddef.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

#define PW_BUF_SIZE 128

/*
 * Overwrite memory in a way the compiler is not permitted to elide.
 * A volatile function pointer to memset prevents the dead-store
 * elimination that would otherwise remove the wipe of a dying buffer.
 */
static void *(*const volatile secure_memset_ptr)(void *, int, size_t) = memset;

static void secure_wipe(void *p, size_t n)
{
    if (p != NULL && n != 0) {
        secure_memset_ptr(p, 0, n);
    }
}

/* Constant-time comparison: no early exit on first differing byte. */
static int consttime_equal(const unsigned char *a, const unsigned char *b, size_t n)
{
    unsigned char diff = 0;
    size_t i;

    for (i = 0; i < n; i++) {
        diff |= (unsigned char)(a[i] ^ b[i]);
    }
    /* Map 0 -> 1, nonzero -> 0 without branching. */
    return (int)((((unsigned)diff - 1u) >> 31) & 1u);
}

/*
 * Reads a password from stdin into a fixed 128-byte stack buffer,
 * hashes it, and compares the digest against stored_hash (32 raw bytes).
 * Returns 1 on match, 0 otherwise.
 */
int verify_password(const char *stored_hash)
{
    char password[PW_BUF_SIZE];
    unsigned char digest[32];
    size_t len;
    int result = 0;

    if (stored_hash == NULL) {
        return 0;
    }

    /* Bounded read: fgets never writes more than sizeof(password) bytes,
       including the terminating NUL. */
    if (fgets(password, (int)sizeof(password), stdin) == NULL) {
        secure_wipe(password, sizeof(password));
        return 0;
    }

    len = strnlen(password, sizeof(password));

    /* Strip a trailing newline (and a preceding CR) if present.
       If no newline was read the line was longer than the buffer;
       the excess remains in stdin and is deliberately not consumed
       into any buffer here. */
    if (len > 0 && password[len - 1] == '\n') {
        password[--len] = '\0';
        if (len > 0 && password[len - 1] == '\r') {
            password[--len] = '\0';
        }
    }

    sha256((const unsigned char *)password, len, digest);

    /* Both operands are fixed 32-byte digests, so the length is known
       and no attacker-controlled length feeds the comparison. */
    result = consttime_equal(digest, (const unsigned char *)stored_hash, sizeof(digest));

    /* Erase the plaintext password and the derived digest before returning. */
    secure_wipe(password, sizeof(password));
    secure_wipe(digest, sizeof(digest));
    len = 0;
    (void)len;

    return result;
}
