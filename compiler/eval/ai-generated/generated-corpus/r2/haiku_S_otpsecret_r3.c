#include <string.h>

int load_totp_secret(const char *user, unsigned char s[20]);
unsigned int totp_now(const unsigned char s[20]);

int verify_totp(const char *user, unsigned int code) {
    unsigned char secret[20];
    unsigned int current_code;
    int result = 0;

    if (load_totp_secret(user, secret) != 0) {
        memset(secret, 0, sizeof(secret));
        return 0;
    }

    current_code = totp_now(secret);

    if (current_code == code) {
        result = 1;
    }

    memset(secret, 0, sizeof(secret));
    return result;
}
