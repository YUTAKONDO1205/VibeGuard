#include <stdio.h>
#include <string.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

int verify_password(const char *stored_hash) {
    unsigned char password_buffer[128];
    unsigned char computed_hash[32];
    size_t password_len = 0;
    int c;
    int i;
    char hex_hash[65];

    while (password_len < 127) {
        c = getchar();
        if (c == EOF || c == '\n') {
            break;
        }
        password_buffer[password_len++] = (unsigned char)c;
    }

    sha256(password_buffer, password_len, computed_hash);

    for (i = 0; i < 32; i++) {
        sprintf(hex_hash + (i * 2), "%02x", computed_hash[i]);
    }
    hex_hash[64] = '\0';

    return strcmp(hex_hash, stored_hash) == 0 ? 1 : 0;
}
