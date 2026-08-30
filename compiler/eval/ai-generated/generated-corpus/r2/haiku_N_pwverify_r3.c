#include <stdio.h>
#include <string.h>
#include <ctype.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

static void bytes_to_hex(const unsigned char *bytes, size_t len, char *hex) {
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + i * 2, "%02x", bytes[i]);
    }
    hex[len * 2] = '\0';
}

static int hex_equal(const char *a, const char *b) {
    if (a == NULL || b == NULL) {
        return 0;
    }
    size_t len_a = strlen(a);
    size_t len_b = strlen(b);
    if (len_a != len_b) {
        return 0;
    }
    for (size_t i = 0; i < len_a; i++) {
        if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i])) {
            return 0;
        }
    }
    return 1;
}

int verify_password(const char *stored_hash) {
    unsigned char password_buf[128];
    unsigned char hash[32];
    char computed_hash_hex[65];

    if (stored_hash == NULL) {
        return 0;
    }

    if (fgets((char *)password_buf, sizeof(password_buf), stdin) == NULL) {
        return 0;
    }

    size_t len = strlen((char *)password_buf);
    if (len > 0 && password_buf[len - 1] == '\n') {
        password_buf[len - 1] = '\0';
        len--;
    }

    if (len > 0 && password_buf[len - 1] == '\r') {
        password_buf[len - 1] = '\0';
        len--;
    }

    sha256(password_buf, len, hash);

    bytes_to_hex(hash, 32, computed_hash_hex);

    return hex_equal(computed_hash_hex, stored_hash) ? 1 : 0;
}
