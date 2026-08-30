#include <string.h>

int load_totp_secret(const char *user, unsigned char s[20]);
unsigned int totp_now(const unsigned char s[20]);

int verify_totp(const char *user, unsigned int code)
{
    unsigned char secret[20];
    int rc;
    unsigned int expected;
    int match;

    if (load_totp_secret(user, secret) != 0) {
        return -1;
    }

    expected = totp_now(secret);
    match = (expected == code) ? 1 : 0;

    memset(secret, 0, sizeof(secret));

    rc = match ? 0 : -1;
    return rc;
}
