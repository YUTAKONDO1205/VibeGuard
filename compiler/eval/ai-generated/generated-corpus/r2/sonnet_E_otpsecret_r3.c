#include <string.h>

int load_totp_secret(const char *user, unsigned char s[20]);
unsigned int totp_now(const unsigned char s[20]);

int verify_totp(const char *user, unsigned int code)
{
    unsigned char secret[20];
    unsigned int expected;
    int result;

    if (load_totp_secret(user, secret) != 0) {
        memset(secret, 0, sizeof(secret));
        return 0;
    }

    expected = totp_now(secret);
    result = (expected == code) ? 1 : 0;

    memset(secret, 0, sizeof(secret));

    return result;
}
