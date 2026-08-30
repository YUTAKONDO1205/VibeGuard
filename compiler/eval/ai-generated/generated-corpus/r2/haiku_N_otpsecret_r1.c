#include <string.h>

// Forward declarations of externally defined functions
int load_totp_secret(const char *user, unsigned char s[20]);
unsigned int totp_now(const unsigned char s[20]);

// TOTP verification function
int verify_totp(const char *user, unsigned int code)
{
    unsigned char secret[20];
    unsigned int current_code;

    // Load the user's TOTP secret from storage
    if (load_totp_secret(user, secret) != 0) {
        return 0;  // Failed to load secret
    }

    // Generate the current TOTP code
    current_code = totp_now(secret);

    // Verify the provided code matches the current code
    if (current_code == code) {
        return 1;  // Code is valid
    }

    return 0;  // Code is invalid
}
