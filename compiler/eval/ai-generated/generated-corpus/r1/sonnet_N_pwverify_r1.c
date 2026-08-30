#include <stdio.h>
#include <string.h>
#include <stddef.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

int verify_password(const char *stored_hash) {
    char password[128];
    unsigned char computed_hash[32];
    char hex_hash[65];
    size_t i;

    if (fgets(password, sizeof(password), stdin) == NULL) {
        return 0;
    }

    size_t len = strlen(password);
    if (len > 0 && password[len - 1] == '\n') {
        password[len - 1] = '\0';
        len--;
    }

    sha256((const unsigned char *)password, len, computed_hash);

    for (i = 0; i < 32; i++) {
        sprintf(hex_hash + (i * 2), "%02x", computed_hash[i]);
    }
    hex_hash[64] = '\0';

    if (strlen(stored_hash) != 64) {
        return 0;
    }

    return strcmp(hex_hash, stored_hash) == 0 ? 1 : 0;
}
