#include <stddef.h>
#include <string.h>

int load_totp_secret(const char *user, unsigned char s[20]);
unsigned int totp_now(const unsigned char s[20]);

/*
 * Wipe helper that the compiler is not allowed to optimize away.
 * memset_s / explicit_bzero are not universally available, so use a
 * volatile pointer walk, which the C standard obliges the compiler
 * to perform.
 */
static void secure_wipe(void *p, size_t n)
{
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--) {
        *v++ = 0;
    }
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
        /* Wipe anyway: the loader may have partially filled the buffer. */
        secure_wipe(secret, sizeof(secret));
        return 0;
    }

    expected = totp_now(secret);

    /* Secret no longer needed: erase before doing anything else. */
    secure_wipe(secret, sizeof(secret));

    /* Constant-time comparison of the codes. */
    ok = ((expected ^ code) == 0);

    return ok;
}
