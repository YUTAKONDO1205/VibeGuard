#include <stddef.h>
#include <stdio.h>
#include <string.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

/* Volatile-qualified memset pointer: the compiler may not elide a call made
   through it, so the wipe survives dead-store elimination. */
static void *(*const volatile secure_memset)(void *, int, size_t) = memset;

static void secure_wipe(void *p, size_t n)
{
    if (p != NULL && n != 0) {
        secure_memset(p, 0, n);
        /* Keep the store from being reordered/removed. */
        __asm__ __volatile__("" : : "r"(p) : "memory");
    }
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
 * Reads a password from stdin, hashes it, and compares the digest with
 * stored_hash (32 raw bytes). Returns 1 on match, 0 otherwise.
 * The plaintext password and its length never outlive this function.
 */
int verify_password(const char *stored_hash)
{
    char password[128];
    unsigned char digest[32];
    size_t len = 0;
    int result = 0;
    int c;

    if (stored_hash == NULL) {
        return 0;
    }

    secure_wipe(password, sizeof password);
    secure_wipe(digest, sizeof digest);

    /* Read one line, bounded by the buffer; drop anything past the limit
       without letting it touch the buffer. */
    while ((c = getchar()) != EOF && c != '\n') {
        if (len < sizeof password) {
            password[len] = (char)c;
        }
        len++;
    }

    if (len > sizeof password) {
        /* Over-long input: refuse rather than verify a truncated password. */
        secure_wipe(password, sizeof password);
        secure_wipe(&len, sizeof len);
        return 0;
    }

    sha256((const unsigned char *)password, len, digest);

    result = ct_equal(digest, (const unsigned char *)stored_hash, sizeof digest);

    /* Erase every copy of the secret and of its length before returning. */
    secure_wipe(password, sizeof password);
    secure_wipe(digest, sizeof digest);
    secure_wipe(&len, sizeof len);

    return result;
}
