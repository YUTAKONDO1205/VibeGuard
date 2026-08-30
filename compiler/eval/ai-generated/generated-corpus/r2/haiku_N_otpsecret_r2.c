#include <stdint.h>
#include <string.h>

int load_totp_secret(const char *user, unsigned char s[20]);
unsigned int totp_now(const unsigned char s[20]);

int verify_totp(const char *user, unsigned int code) {
    unsigned char secret[20];

    if (load_totp_secret(user, secret) != 0) {
        memset(secret, 0, 20);
        return 0;
    }

    unsigned int current_code = totp_now(secret);
    memset(secret, 0, 20);

    return (current_code == code) ? 1 : 0;
}
