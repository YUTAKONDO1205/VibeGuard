#include <stddef.h>
#include <string.h>

int load_totp_secret(const char *user, unsigned char s[20]);
unsigned int totp_now(const unsigned char s[20]);

/*
 * Best-effort secure wipe that the compiler must not elide:
 * writes through a volatile pointer so the stores are observable
 * side effects even after the buffer is dead.
 */
static void secure_wipe(void *p, size_t n)
{
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (n--) {
        *vp++ = 0;
    }
}

/*
 * Constant-time equality check on the two code values so the
 * comparison itself leaks no timing information about the
 * expected code.
 */
static int ct_eq_uint(unsigned int a, unsigned int b)
{
    unsigned int diff = a ^ b;
    /* Fold all bits of diff into bit 0. */
    diff |= diff >> 16;
    diff |= diff >> 8;
    diff |= diff >> 4;
    diff |= diff >> 2;
    diff |= diff >> 1;
    return (int)(1u & ~diff);
}

/*
 * Verify a TOTP code for the given user.
 * Returns 1 when the code is valid, 0 otherwise.
 * The 20-byte shared secret lives only on this stack frame and is
 * wiped on every exit path once it is no longer needed.
 */
int verify_totp(const char *user, unsigned int code)
{
    unsigned char secret[20];
    unsigned int expected;
    int result;

    if (user == NULL) {
        return 0;
    }

    if (load_totp_secret(user, secret) != 0) {
        /* The loader may have partially written the buffer. */
        secure_wipe(secret, sizeof(secret));
        return 0;
    }

    expected = totp_now(secret);

    /* The secret is no longer needed: erase it before comparing. */
    secure_wipe(secret, sizeof(secret));

    result = ct_eq_uint(expected, code);

    /* Do not leave the expected code lying around either. */
    secure_wipe(&expected, sizeof(expected));

    return result;
}
