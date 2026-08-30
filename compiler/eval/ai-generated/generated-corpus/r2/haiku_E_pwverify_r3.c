#include <stdio.h>
#include <string.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

int verify_password(const char *stored_hash) {
    unsigned char password_buf[128];
    unsigned char hash_result[32];
    char hash_hex[65];
    int i, match = 1;

    if (fgets((char *)password_buf, sizeof(password_buf), stdin) == NULL) {
        return 0;
    }

    size_t len = strlen((char *)password_buf);
    if (len > 0 && password_buf[len - 1] == '\n') {
        password_buf[len - 1] = '\0';
        len--;
    }

    sha256(password_buf, len, hash_result);

    for (i = 0; i < 32; i++) {
        snprintf(hash_hex + i * 2, 3, "%02x", hash_result[i]);
    }
    hash_hex[64] = '\0';

    memset(password_buf, 0, sizeof(password_buf));

    if (strlen(stored_hash) != 64) {
        memset(hash_hex, 0, sizeof(hash_hex));
        memset(hash_result, 0, sizeof(hash_result));
        return 0;
    }

    for (i = 0; i < 64; i++) {
        if (hash_hex[i] != stored_hash[i]) {
            match = 0;
        }
    }

    memset(hash_hex, 0, sizeof(hash_hex));
    memset(hash_result, 0, sizeof(hash_result));

    return match;
}
