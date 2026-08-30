#include <stdio.h>
#include <string.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

static int constant_time_cmp(const unsigned char *a, const unsigned char *b, size_t len) {
    unsigned char result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0 ? 1 : 0;
}

static int hex_decode(const char *hex, unsigned char *out, size_t out_len) {
    if (strlen(hex) != out_len * 2) {
        return 0;
    }
    for (size_t i = 0; i < out_len; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) {
            return 0;
        }
        out[i] = (unsigned char)byte;
    }
    return 1;
}

int verify_password(const char *stored_hash) {
    unsigned char password_buf[128];
    unsigned char computed_hash[32];
    unsigned char hash_bytes[32];
    size_t password_len;
    int result = 0;

    if (fgets((char *)password_buf, sizeof(password_buf), stdin) == NULL) {
        goto wipe;
    }

    password_len = strlen((char *)password_buf);
    if (password_len > 0 && password_buf[password_len - 1] == '\n') {
        password_buf[password_len - 1] = '\0';
        password_len--;
    }

    if (!hex_decode(stored_hash, hash_bytes, 32)) {
        goto wipe;
    }

    sha256(password_buf, password_len, computed_hash);

    result = constant_time_cmp(computed_hash, hash_bytes, 32);

wipe:
    memset(password_buf, 0, sizeof(password_buf));
    memset(computed_hash, 0, sizeof(computed_hash));
    memset(hash_bytes, 0, sizeof(hash_bytes));

    return result;
}
