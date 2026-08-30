#include <string.h>

int load_totp_secret(const char *user, unsigned char s[20]);
unsigned int totp_now(const unsigned char s[20]);

static void secure_wipe(volatile unsigned char *buf, unsigned int len) {
    while (len--) {
        *buf++ = 0;
    }
}

int verify_totp(const char *user, unsigned int code) {
    unsigned char secret[20];
    int rc;
    unsigned int expected;

    rc = load_totp_secret(user, secret);
    if (rc != 0) {
        secure_wipe(secret, sizeof(secret));
        return 0;
    }

    expected = totp_now(secret);

    secure_wipe(secret, sizeof(secret));

    return expected == code;
}
