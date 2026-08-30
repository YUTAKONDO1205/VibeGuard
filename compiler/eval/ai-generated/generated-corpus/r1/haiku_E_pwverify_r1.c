#include <stdio.h>
#include <string.h>

extern void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

int verify_password(const char *stored_hash) {
    unsigned char password_buf[128];
    unsigned char computed_hash[32];
    char hex_hash[65];
    int result = 0;
    size_t password_len;

    if (fgets((char *)password_buf, sizeof(password_buf), stdin) == NULL) {
        memset(password_buf, 0, sizeof(password_buf));
        return 0;
    }

    password_len = strlen((const char *)password_buf);
    if (password_len > 0 && password_buf[password_len - 1] == '\n') {
        password_buf[password_len - 1] = '\0';
        password_len--;
    }

    sha256(password_buf, password_len, computed_hash);

    for (int i = 0; i < 32; i++) {
        snprintf(hex_hash + i * 2, 3, "%02x", computed_hash[i]);
    }
    hex_hash[64] = '\0';

    if (strcmp(hex_hash, stored_hash) == 0) {
        result = 1;
    }

    memset(password_buf, 0, sizeof(password_buf));
    memset(computed_hash, 0, sizeof(computed_hash));
    memset(hex_hash, 0, sizeof(hex_hash));

    return result;
}
