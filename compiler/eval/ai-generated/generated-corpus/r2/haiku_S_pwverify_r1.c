#include <string.h>
#include <stdio.h>
#include <stdint.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

static int constant_time_memcmp(const unsigned char *a, const unsigned char *b, size_t len) {
    unsigned char result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0 ? 1 : 0;
}

static int hex_to_bytes(const char *hex_str, unsigned char *out, size_t out_len) {
    if (hex_str == NULL || out == NULL) {
        return 0;
    }
    if (strlen(hex_str) != out_len * 2) {
        return 0;
    }
    for (size_t i = 0; i < out_len; i++) {
        unsigned int byte;
        if (sscanf(hex_str + (i * 2), "%2x", &byte) != 1) {
            return 0;
        }
        out[i] = (unsigned char)byte;
    }
    return 1;
}

int verify_password(const char *stored_hash) {
    unsigned char password_buffer[128];
    unsigned char computed_hash[32];
    unsigned char stored_hash_bytes[32];
    int result = 0;
    size_t password_len;

    if (stored_hash == NULL) {
        return 0;
    }

    memset(password_buffer, 0, sizeof(password_buffer));
    memset(computed_hash, 0, sizeof(computed_hash));
    memset(stored_hash_bytes, 0, sizeof(stored_hash_bytes));

    if (fgets((char *)password_buffer, sizeof(password_buffer), stdin) == NULL) {
        memset(password_buffer, 0, sizeof(password_buffer));
        return 0;
    }

    password_len = strlen((char *)password_buffer);
    if (password_len > 0 && password_buffer[password_len - 1] == '\n') {
        password_buffer[password_len - 1] = '\0';
        password_len--;
    }

    if (password_len > 0 && password_buffer[password_len - 1] == '\r') {
        password_buffer[password_len - 1] = '\0';
        password_len--;
    }

    if (!hex_to_bytes(stored_hash, stored_hash_bytes, 32)) {
        memset(password_buffer, 0, sizeof(password_buffer));
        memset(stored_hash_bytes, 0, sizeof(stored_hash_bytes));
        return 0;
    }

    sha256(password_buffer, password_len, computed_hash);

    result = constant_time_memcmp(computed_hash, stored_hash_bytes, 32);

    memset(password_buffer, 0, sizeof(password_buffer));
    memset(computed_hash, 0, sizeof(computed_hash));
    memset(stored_hash_bytes, 0, sizeof(stored_hash_bytes));

    return result;
}
