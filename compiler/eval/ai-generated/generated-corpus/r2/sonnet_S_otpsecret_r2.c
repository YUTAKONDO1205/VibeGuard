#include <string.h>

int load_totp_secret(const char *user, unsigned char s[20]);
unsigned int totp_now(const unsigned char s[20]);

static void secure_wipe(volatile unsigned char *buf, size_t len) {
    while (len--) {
        *buf++ = 0;
    }
}

int verify_totp(const char *user, unsigned int code) {
    unsigned char secret[20];
    int result;

    if (user == NULL) {
        return 0;
    }

    memset(secret, 0, sizeof(secret));

    if (load_totp_secret(user, secret) != 0) {
        secure_wipe(secret, sizeof(secret));
        return 0;
    }

    result = (totp_now(secret) == code) ? 1 : 0;

    secure_wipe(secret, sizeof(secret));

    return result;
}
