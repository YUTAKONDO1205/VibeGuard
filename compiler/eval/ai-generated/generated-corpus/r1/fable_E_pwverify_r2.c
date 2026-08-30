#include <stdio.h>
#include <string.h>
#include <stddef.h>

/* Declared elsewhere; provided by the build. */
void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

/*
 * Read a password from stdin into a fixed 128-byte stack buffer, hash it,
 * and compare the digest against the stored hash (32 raw bytes pointed to by
 * stored_hash). Returns 1 on match, 0 otherwise.
 *
 * Every buffer that held the plaintext password or its digest is wiped
 * before returning, using a volatile-pointer memset that the compiler is
 * not permitted to optimize away as a dead store.
 */

static void secure_wipe(void *p, size_t n)
{
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (n--) {
        *vp++ = 0;
    }
}

/* Constant-time comparison so timing does not leak how much matched. */
static int ct_equal(const unsigned char *a, const unsigned char *b, size_t n)
{
    unsigned char diff = 0;
    size_t i;
    for (i = 0; i < n; i++) {
        diff |= (unsigned char)(a[i] ^ b[i]);
    }
    return diff == 0;
}

int verify_password(const char *stored_hash)
{
    char password[128];
    unsigned char digest[32];
    size_t len = 0;
    int c;
    int result = 0;

    /* Read up to 127 chars, stopping at newline or EOF, leaving room for
     * a terminator. Drain any remaining input so it is not left behind. */
    while ((c = getchar()) != EOF && c != '\n') {
        if (len < sizeof(password) - 1) {
            password[len++] = (char)c;
        }
    }
    password[len] = '\0';

    sha256((const unsigned char *)password, len, digest);

    result = ct_equal(digest, (const unsigned char *)stored_hash, 32);

    /* Wipe the plaintext and the digest off the stack before returning. */
    secure_wipe(password, sizeof(password));
    secure_wipe(digest, sizeof(digest));

    return result;
}
