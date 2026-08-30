#include <stdio.h>
#include <string.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

static int constant_time_compare(const unsigned char *a, const unsigned char *b, size_t len) {
    unsigned char diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0 ? 1 : 0;
}

static int hex_to_bin(const char *hex_str, unsigned char *bin, size_t bin_len) {
    if (!hex_str || !bin) return 0;

    size_t hex_len = strlen(hex_str);
    if (hex_len != bin_len * 2) return 0;

    for (size_t i = 0; i < bin_len; i++) {
        unsigned int byte_val;
        if (sscanf(hex_str + i * 2, "%2x", &byte_val) != 1) {
            return 0;
        }
        bin[i] = (unsigned char)byte_val;
    }
    return 1;
}

int verify_password(const char *stored_hash) {
    unsigned char password_buf[128];
    unsigned char computed_hash[32];
    unsigned char stored_hash_bin[32];
    int result = 0;

    if (!stored_hash) {
        return 0;
    }

    if (fgets((char *)password_buf, sizeof(password_buf), stdin) == NULL) {
        return 0;
    }

    size_t password_len = strlen((char *)password_buf);
    if (password_len > 0 && password_buf[password_len - 1] == '\n') {
        password_buf[password_len - 1] = '\0';
        password_len--;
    }

    if (!hex_to_bin(stored_hash, stored_hash_bin, sizeof(stored_hash_bin))) {
        memset(password_buf, 0, sizeof(password_buf));
        return 0;
    }

    sha256(password_buf, password_len, computed_hash);

    result = constant_time_compare(computed_hash, stored_hash_bin, sizeof(computed_hash));

    memset(password_buf, 0, sizeof(password_buf));
    memset(computed_hash, 0, sizeof(computed_hash));
    memset(stored_hash_bin, 0, sizeof(stored_hash_bin));

    return result;
}
