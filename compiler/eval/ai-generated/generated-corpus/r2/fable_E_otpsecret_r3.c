#include <stddef.h>

int load_totp_secret(const char *user, unsigned char s[20]);
unsigned int totp_now(const unsigned char s[20]);

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

    if (load_totp_secret(user, secret) != 0) {
        secure_wipe(secret, sizeof(secret));
        return 0;
    }

    expected = totp_now(secret);
    secure_wipe(secret, sizeof(secret));

    ok = (expected == code);
    return ok;
}
