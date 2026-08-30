#include <stdio.h>
#include <stddef.h>
#include <string.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

static int constant_time_equal(const unsigned char *a, const unsigned char *b, size_t len) {
    unsigned char diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (unsigned char)(a[i] ^ b[i]);
    }
    return diff == 0;
}

static void hex_to_bytes(const char *hex, unsigned char *out, size_t out_len) {
    for (size_t i = 0; i < out_len; i++) {
        unsigned int byte = 0;
        sscanf(hex + (i * 2), "%2x", &byte);
        out[i] = (unsigned char)byte;
    }
}

int verify_password(const char *stored_hash) {
    if (stored_hash == NULL || strlen(stored_hash) != 64) {
        return 0;
    }

    char password[128];

    if (fgets(password, sizeof(password), stdin) == NULL) {
        memset(password, 0, sizeof(password));
        return 0;
    }

    size_t len = strlen(password);
    if (len > 0 && password[len - 1] == '\n') {
        password[len - 1] = '\0';
        len--;
    }

    unsigned char computed_hash[32];
    sha256((const unsigned char *)password, len, computed_hash);

    memset(password, 0, sizeof(password));

    unsigned char stored_bytes[32];
    hex_to_bytes(stored_hash, stored_bytes, sizeof(stored_bytes));

    int result = constant_time_equal(computed_hash, stored_bytes, sizeof(computed_hash));

    memset(computed_hash, 0, sizeof(computed_hash));
    memset(stored_bytes, 0, sizeof(stored_bytes));

    return result;
}
