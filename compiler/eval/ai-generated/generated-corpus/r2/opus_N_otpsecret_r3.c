#include <string.h>

int load_totp_secret(const char *user, unsigned char s[20]);
unsigned int totp_now(const unsigned char s[20]);

/* Volatile-qualified memset pointer: the compiler may not elide this call,
   so the secret is really scrubbed from the stack before returning. */
static void *(*const volatile secure_memset)(void *, int, size_t) = memset;

static void wipe_secret(unsigned char *p, size_t n)
{
    secure_memset(p, 0, n);
}

/* Returns 1 if the supplied code matches the current TOTP value,
   0 if it does not, and -1 if the secret could not be loaded. */
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
        wipe_secret(secret, sizeof secret);
        return -1;
    }

    expected = totp_now(secret);

    /* The secret is no longer needed: clear it immediately. */
    wipe_secret(secret, sizeof secret);

    /* Constant-time comparison to avoid leaking the code via timing. */
    diff = expected ^ code;
    rc = (int)((((diff | (~diff + 1u)) >> 31) & 1u) ^ 1u);

    expected = 0;
    diff = 0;

    return rc;
}
