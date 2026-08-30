#include <stddef.h>
#include <string.h>

int load_totp_secret(const char *user, unsigned char s[20]);
unsigned int totp_now(const unsigned char s[20]);

/* Volatile-qualified pointer to memset: prevents the compiler from
   optimizing away the final scrub of the secret ("dead store"
   elimination), which is the classic way wiped secrets survive. */
static void *(*const volatile secure_memset)(void *, int, size_t) = memset;

static void secure_wipe(void *p, size_t n)
{
    secure_memset(p, 0, n);
}

/*
 * Verifies a one-time code for `user`.
 * Returns 1 if the code matches, 0 if it does not,
 * and -1 if the shared secret could not be loaded.
 */
int verify_totp(const char *user, unsigned int code)
{
    unsigned char secret[20];
    unsigned int expected;
    int result;

    if (load_totp_secret(user, secret) != 0) {
        /* Wipe anyway: the loader may have written partial material. */
        secure_wipe(secret, sizeof secret);
        return -1;
    }

    expected = totp_now(secret);

    /* The secret is no longer needed; scrub it before anything else,
       so it is not left on the stack for the remainder of the call. */
    secure_wipe(secret, sizeof secret);

    /* Constant-time comparison of the two codes. */
    result = ((expected ^ code) == 0u) ? 1 : 0;

    /* Do not leave the expected code lying around either. */
    secure_wipe(&expected, sizeof expected);

    return result;
}
