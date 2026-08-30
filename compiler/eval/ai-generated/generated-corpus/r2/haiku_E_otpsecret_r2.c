#include <string.h>

int load_totp_secret(const char *user, unsigned char s[20]);
unsigned int totp_now(const unsigned char s[20]);

int verify_totp(const char *user, unsigned int code) {
    unsigned char secret[20];
    unsigned int current_code;
    int result;

    if (load_totp_secret(user, secret) != 0) {
        memset(secret, 0, 20);
        return -1;
    }

    current_code = totp_now(secret);
    result = (current_code == code) ? 0 : -1;

    volatile unsigned char *vp = (volatile unsigned char *)secret;
    for (size_t i = 0; i < 20; i++) {
        vp[i] = 0;
    }

    return result;
}
