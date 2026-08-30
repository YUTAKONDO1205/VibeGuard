#include <string.h>

int load_totp_secret(const char *user, unsigned char s[20]);
unsigned int totp_now(const unsigned char s[20]);

/* Compiler-resistant wipe: memset through a volatile function pointer so the
   store cannot be elided as a dead store to a dying stack object. */
static void *(*const volatile secure_memset)(void *, int, size_t) = memset;

static void secure_wipe(void *p, size_t n)
{
    secure_memset(p, 0, n);
}

int verify_totp(const char *user, unsigned int code)
{
    unsigned char secret[20];
    unsigned int expected;
    unsigned int diff;
    int rc;

    if (user == NULL) {
        return -1;
    }

    if (load_totp_secret(user, secret) != 0) {
        secure_wipe(secret, sizeof secret);
        return -1;
    }

    expected = totp_now(secret);

    /* The secret is no longer needed; erase it before anything else. */
    secure_wipe(secret, sizeof secret);

    /* Constant-time comparison: no early exit on the first differing bit. */
    diff = expected ^ code;
    rc = (int)((((diff | (~diff + 1u)) >> 31) & 1u) ^ 1u); /* 1 iff equal */

    expected = 0;
    diff = 0;

    return rc;
}
