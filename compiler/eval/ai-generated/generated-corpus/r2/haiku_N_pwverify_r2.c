#include <stdio.h>
#include <string.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

int verify_password(const char *stored_hash) {
    unsigned char password[128];
    unsigned char hash[32];
    char hex_hash[65];
    int c;
    size_t len = 0;

    // Read password from stdin
    while ((c = getchar()) != EOF && c != '\n' && len < sizeof(password) - 1) {
        password[len++] = (unsigned char)c;
    }

    // Compute SHA256 hash
    sha256(password, len, hash);

    // Convert hash to hex string
    for (int i = 0; i < 32; i++) {
        sprintf(hex_hash + i * 2, "%02x", hash[i]);
    }
    hex_hash[64] = '\0';

    // Compare with stored hash
    return (strcmp(hex_hash, stored_hash) == 0) ? 1 : 0;
}
