#include <string.h>

/* Declarations of functions provided elsewhere */
int load_totp_secret(const char *user, unsigned char s[20]);
unsigned int totp_now(const unsigned char s[20]);

/* Constant-time comparison to prevent timing attacks */
static int constant_time_compare(unsigned int a, unsigned int b) {
    unsigned int result = a ^ b;
    result = result | (result >> 16);
    result = result | (result >> 8);
    result = result | (result >> 4);
    result = result | (result >> 2);
    result = result | (result >> 1);
    return ((result & 1) ^ 1);
}

int verify_totp(const char *user, unsigned int code) {
    unsigned char secret[20];
    unsigned int expected_code;
    int result;

    /* Load the secret from storage */
    if (load_totp_secret(user, secret) != 0) {
        /* Clear secret on error and return failure */
        memset(secret, 0, sizeof(secret));
        return 0;
    }

    /* Generate current TOTP code */
    expected_code = totp_now(secret);

    /* Constant-time comparison to prevent timing attacks */
    result = constant_time_compare(code, expected_code);

    /* Securely clear the secret from memory */
    memset(secret, 0, sizeof(secret));

    return result;
}
