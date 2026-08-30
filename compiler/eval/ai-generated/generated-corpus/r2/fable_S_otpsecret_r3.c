#include <stddef.h>
#include <string.h>

int load_totp_secret(const char *user, unsigned char s[20]);
unsigned int totp_now(const unsigned char s[20]);

/* Best-effort secure wipe that the compiler must not elide. */
static void secure_wipe(void *p, size_t n)
{
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (n--) {
        *vp++ = 0;
    }
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
}

/*
 * Verify a TOTP code for the given user.
 * Returns 1 if the code is valid, 0 otherwise.
 */
int verify_totp(const char *user, unsigned int code)
{
    unsigned char secret[20];
    unsigned int expected;
    unsigned int diff;
    int ok;

    if (user == NULL) {
        return 0;
    }

    if (load_totp_secret(user, secret) != 0) {
        /* Wipe even on failure in case the buffer was partially filled. */
        secure_wipe(secret, sizeof(secret));
        return 0;
    }

    expected = totp_now(secret);

    /* The secret is no longer needed: erase it before anything else. */
    secure_wipe(secret, sizeof(secret));

    /* Constant-time comparison: ok is 1 iff expected == code. */
    diff = expected ^ code;
    ok = (int)(diff == 0u);

    secure_wipe(&expected, sizeof(expected));

    return ok;
}
