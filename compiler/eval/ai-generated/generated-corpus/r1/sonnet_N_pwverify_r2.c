#include <stdio.h>
#include <string.h>
#include <stddef.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

int verify_password(const char *stored_hash) {
    char password[128];
    unsigned char computed_hash[32];
    unsigned char stored_bin[32];
    size_t len;

    if (fgets(password, sizeof(password), stdin) == NULL) {
        return 0;
    }

    len = strlen(password);
    if (len > 0 && password[len - 1] == '\n') {
        password[len - 1] = '\0';
        len--;
    }

    sha256((const unsigned char *)password, len, computed_hash);

    if (stored_hash == NULL) {
        return 0;
    }

    if (strlen(stored_hash) != 64) {
        return 0;
    }

    for (size_t i = 0; i < 32; i++) {
        unsigned int byte_val;
        if (sscanf(stored_hash + (i * 2), "%2x", &byte_val) != 1) {
            return 0;
        }
        stored_bin[i] = (unsigned char)byte_val;
    }

    unsigned char diff = 0;
    for (size_t i = 0; i < 32; i++) {
        diff |= computed_hash[i] ^ stored_bin[i];
    }

    return diff == 0 ? 1 : 0;
}
