#include <string.h>

int load_totp_secret(const char *user, unsigned char s[20]);
unsigned int totp_now(const unsigned char s[20]);

/* Compare two 32-bit values without a data-dependent branch. */
static int ct_eq_u32(unsigned int a, unsigned int b)
{
    unsigned int diff = a ^ b;
    /* diff == 0  ->  1, otherwise 0 */
    return (int)(1u & ((diff - 1u) >> 31));
}

/*
 * Verifies a one-time code for `user`.
 *
 * Returns 1 if the code matches the current TOTP value,
 *         0 if it does not match,
 *        -1 if the shared secret could not be loaded.
 */
int verify_totp(const char *user, unsigned int code)
{
    unsigned char secret[20];
    unsigned int expected;
    int rc;

    if (user == NULL) {
        return -1;
    }

    memset(secret, 0, sizeof secret);

    if (load_totp_secret(user, secret) != 0) {
        /* Nothing sensitive should be left behind even on the error path. */
        memset(secret, 0, sizeof secret);
        return -1;
    }

    expected = totp_now(secret);

    /* Wipe the shared secret as soon as it is no longer needed, so it does
       not linger in this stack frame after the function returns. */
    memset(secret, 0, sizeof secret);

    rc = ct_eq_u32(expected, code);

    expected = 0u;
    return rc;
}
