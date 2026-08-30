#include <string.h>

int load_totp_secret(const char *user, unsigned char s[20]);
unsigned int totp_now(const unsigned char s[20]);

int verify_totp(const char *user, unsigned int code)
{
    unsigned char secret[20];
    unsigned int expected;
    int ok;

    if (load_totp_secret(user, secret) != 0) {
        memset(secret, 0, sizeof secret);
        return -1;
    }

    expected = totp_now(secret);

    /* Wipe the shared secret from the stack before returning so it does
       not linger in memory after the function frame is gone. */
    memset(secret, 0, sizeof secret);

    ok = (code == expected) ? 1 : 0;
    return ok;
}
