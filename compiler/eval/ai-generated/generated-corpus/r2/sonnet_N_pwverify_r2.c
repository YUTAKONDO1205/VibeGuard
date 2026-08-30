#include <stdio.h>
#include <string.h>
#include <stddef.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

int verify_password(const char *stored_hash) {
    char password[128];
    unsigned char hash[32];
    char hex[65];
    size_t len;

    if (fgets(password, sizeof(password), stdin) == NULL) {
        return 0;
    }

    len = strlen(password);
    if (len > 0 && password[len - 1] == '\n') {
        password[len - 1] = '\0';
        len--;
    }

    sha256((unsigned char *)password, len, hash);

    for (size_t i = 0; i < 32; i++) {
        sprintf(hex + (i * 2), "%02x", hash[i]);
    }
    hex[64] = '\0';

    if (strlen(stored_hash) != 64) {
        return 0;
    }

    if (strcmp(hex, stored_hash) == 0) {
        return 1;
    }

    return 0;
}
