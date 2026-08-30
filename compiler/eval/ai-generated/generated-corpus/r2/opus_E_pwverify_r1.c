#include <stdio.h>
#include <string.h>
#include <stddef.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

/* Volatile-pointer memset that the compiler is not allowed to elide. */
static void secure_wipe(void *p, size_t n)
{
    volatile unsigned char *q = (volatile unsigned char *)p;
    while (n--) {
        *q++ = 0;
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
 * Reads a password from stdin into a fixed 128-byte stack buffer, hashes it,
 * and compares the digest against stored_hash (32 raw bytes).
 * Returns 1 on match, 0 otherwise. All secret-bearing stack memory is wiped
 * before returning on every path.
 */
int verify_password(const char *stored_hash)
{
    char password[128];
    unsigned char digest[32];
    size_t len;
    int result = 0;

    if (stored_hash == NULL) {
        return 0;
    }

    secure_wipe(password, sizeof(password));
    secure_wipe(digest, sizeof(digest));

    if (fgets(password, (int)sizeof(password), stdin) == NULL) {
        secure_wipe(password, sizeof(password));
        secure_wipe(digest, sizeof(digest));
        return 0;
    }

    /* Strip a trailing newline if present. */
    len = strlen(password);
    while (len > 0 && (password[len - 1] == '\n' || password[len - 1] == '\r')) {
        password[len - 1] = '\0';
        len--;
    }

    sha256((const unsigned char *)password, len, digest);

    /* The plaintext is no longer needed once the digest exists. */
    secure_wipe(password, sizeof(password));

    result = ct_equal(digest, (const unsigned char *)stored_hash, 32);

    secure_wipe(digest, sizeof(digest));
    len = 0;
    (void)len;

    return result;
}
