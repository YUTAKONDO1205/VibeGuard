#include <stddef.h>
#include <string.h>

/* Provided elsewhere. */
int load_totp_secret(const char *user, unsigned char s[20]);
unsigned int totp_now(const unsigned char s[20]);

/* Volatile function pointer to memset: the compiler cannot prove what it
 * points to, so the final scrub of the secret cannot be optimized away
 * as a dead store to a dying stack object. */
static void *(*const volatile secure_memset_fp)(void *, int, size_t) = memset;

static void secure_wipe(void *p, size_t n)
{
    if (p != NULL && n != 0) {
        secure_memset_fp(p, 0, n);
    }
}

/* Length-independent comparison of two 32-bit values.
 * Returns 1 if equal, 0 otherwise, without data-dependent branches. */
static int ct_eq_u32(unsigned int a, unsigned int b)
{
    unsigned int d = a ^ b;
    /* Fold all bits down to bit 0. */
    d |= d >> 16;
    d |= d >> 8;
    d |= d >> 4;
    d |= d >> 2;
    d |= d >> 1;
    return (int)((~d) & 1u);
}

/*
 * Verify a TOTP code for `user`.
 * Returns 1 on match, 0 on mismatch, -1 on error (bad argument or the
 * secret could not be loaded).
 */
int verify_totp(const char *user, unsigned int code)
{
    unsigned char secret[20];
    unsigned int expected;
    int rc;
    int result;

    if (user == NULL) {
        return -1;
    }

    /* Do not leave uninitialized stack contents in the buffer if the
     * loader fails part-way through. */
    secure_wipe(secret, sizeof secret);

    rc = load_totp_secret(user, secret);
    if (rc != 0) {
        secure_wipe(secret, sizeof secret);
        return -1;
    }

    expected = totp_now(secret);

    /* The secret is no longer needed: scrub it before doing anything
     * that could fail, return, or take time. */
    secure_wipe(secret, sizeof secret);

    result = ct_eq_u32(expected, code);

    /* The derived code is also sensitive; clear it too. */
    expected = 0;
    secure_wipe(&expected, sizeof expected);

    return result;
}
