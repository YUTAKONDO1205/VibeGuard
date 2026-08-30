#include <stddef.h>

int load_totp_secret(const char *user, unsigned char s[20]);
unsigned int totp_now(const unsigned char s[20]);

/* Wipe that the compiler must not optimize away. */
static void secure_wipe(void *p, size_t n)
{
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (n--) {
        *vp++ = 0;
    }
#if defined(__GNUC__) || defined(__clang__)
    /* Compiler barrier: force the stores above to be considered observable. */
    __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
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
        secure_wipe(secret, sizeof(secret));
        return 0;
    }

    expected = totp_now(secret);

    /* Secret no longer needed: wipe before doing anything else. */
    secure_wipe(secret, sizeof(secret));

    /* Constant-time comparison of the two code values. */
    ok = ((expected ^ code) == 0);

    return ok;
}
