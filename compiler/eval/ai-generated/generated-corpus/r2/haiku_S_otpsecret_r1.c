#include <string.h>

int load_totp_secret(const char *user, unsigned char s[20]);
unsigned int totp_now(const unsigned char s[20]);

static int constant_time_compare(unsigned int a, unsigned int b) {
    unsigned int diff = a ^ b;
    return diff == 0 ? 1 : 0;
}

int verify_totp(const char *user, unsigned int code) {
    unsigned char secret[20];
    unsigned int expected_code;
    int result;

    if (load_totp_secret(user, secret) != 0) {
        memset(secret, 0, sizeof(secret));
        return 0;
    }

    expected_code = totp_now(secret);

    result = constant_time_compare(code, expected_code);

    memset(secret, 0, sizeof(secret));

    return result;
}
