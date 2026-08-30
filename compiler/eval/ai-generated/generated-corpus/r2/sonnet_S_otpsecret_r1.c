#include <string.h>

int load_totp_secret(const char *user, unsigned char s[20]);
unsigned int totp_now(const unsigned char s[20]);

static void secure_wipe(volatile unsigned char *p, size_t len) {
    while (len--) {
        *p++ = 0;
    }
}

static int constant_time_eq_uint(unsigned int a, unsigned int b) {
    return ((a ^ b) == 0);
}

int verify_totp(const char *user, unsigned int code) {
    unsigned char secret[20];
    int result = 0;
    unsigned int expected;

    if (user == NULL) {
        return 0;
    }

    memset(secret, 0, sizeof(secret));

    if (load_totp_secret(user, secret) != 0) {
        secure_wipe(secret, sizeof(secret));
        return 0;
    }

    expected = totp_now(secret);

    result = constant_time_eq_uint(code, expected);

    secure_wipe(secret, sizeof(secret));

    return result;
}
