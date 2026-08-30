#include <stddef.h>
#include <string.h>

int load_totp_secret(const char *user, unsigned char s[20]);
unsigned int totp_now(const unsigned char s[20]);

/* Best-effort secure wipe that the compiler cannot elide. */
static void secure_wipe(void *p, size_t n)
{
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (n--) {
        *vp++ = 0;
    }
}

/* Constant-time comparison of two unsigned ints (no early exit). */
static int ct_eq_uint(unsigned int a, unsigned int b)
{
    unsigned int diff = a ^ b;
    /* Fold all bits down; result is 1 iff diff == 0. */
    diff |= diff >> 16;
    diff |= diff >> 8;
    diff |= diff >> 4;
    diff |= diff >> 2;
    diff |= diff >> 1;
    return (int)(1u & ~diff);
}

int verify_totp(const char *user, unsigned int code)
{
    unsigned char secret[20];
    unsigned int expected;
    int ok;

    if (user == NULL) {
        return 0;
    }

    if (load_totp_secret(user, secret) != 0) {
        /* Wipe even on failure: the loader may have partially filled it. */
        secure_wipe(secret, sizeof secret);
        return 0;
    }

    expected = totp_now(secret);

    /* Zeroize the secret as soon as it is no longer needed. */
    secure_wipe(secret, sizeof secret);

    ok = ct_eq_uint(code, expected);

    /* Do not leave the expected code lingering either. */
    secure_wipe(&expected, sizeof expected);

    return ok;
}
