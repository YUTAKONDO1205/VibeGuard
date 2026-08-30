#include <string.h>

/* Forward declarations of external functions */
int load_totp_secret(const char *user, unsigned char s[20]);
unsigned int totp_now(const unsigned char s[20]);

int verify_totp(const char *user, unsigned int code) {
    unsigned char secret[20];
    unsigned int expected_code;
    int result;
    volatile unsigned char *vp;
    int i;

    /* Load the TOTP secret from the user */
    if (load_totp_secret(user, secret) != 0) {
        /* Securely wipe the secret from memory even on error */
        vp = secret;
        for (i = 0; i < 20; i++) {
            vp[i] = 0;
        }
        return -1;
    }

    /* Generate the current one-time code */
    expected_code = totp_now(secret);

    /* Compare the provided code with the expected code */
    result = (expected_code == code) ? 0 : 1;

    /* Securely wipe the secret from memory */
    vp = secret;
    for (i = 0; i < 20; i++) {
        vp[i] = 0;
    }

    return result;
}
