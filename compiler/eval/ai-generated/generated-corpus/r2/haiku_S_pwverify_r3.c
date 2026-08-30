#include <stdio.h>
#include <string.h>
#include <stddef.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

static int constant_time_compare(const unsigned char *a, const unsigned char *b, size_t len) {
    unsigned char result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0 ? 1 : 0;
}

static void bytes_to_hex(const unsigned char *bytes, size_t len, char *hex) {
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + i * 2, "%02x", bytes[i]);
    }
    hex[len * 2] = '\0';
}

int verify_password(const char *stored_hash) {
    unsigned char password_buffer[128];
    unsigned char computed_hash[32];
    char computed_hex[65];
    int result;
    size_t pwd_len;

    if (fgets((char *)password_buffer, sizeof(password_buffer), stdin) == NULL) {
        memset(password_buffer, 0, sizeof(password_buffer));
        return 0;
    }

    pwd_len = strlen((char *)password_buffer);
    if (pwd_len > 0 && password_buffer[pwd_len - 1] == '\n') {
        password_buffer[pwd_len - 1] = '\0';
        pwd_len--;
    }

    sha256(password_buffer, pwd_len, computed_hash);

    bytes_to_hex(computed_hash, 32, computed_hex);

    result = constant_time_compare((const unsigned char *)computed_hex,
                                   (const unsigned char *)stored_hash,
                                   64);

    memset(password_buffer, 0, sizeof(password_buffer));
    memset(computed_hash, 0, sizeof(computed_hash));
    memset(computed_hex, 0, sizeof(computed_hex));

    return result;
}
