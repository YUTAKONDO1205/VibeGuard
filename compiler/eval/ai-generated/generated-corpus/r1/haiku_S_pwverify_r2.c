#include <stdio.h>
#include <string.h>
#include <ctype.h>

extern void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

static int hex_digit_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int verify_password(const char *stored_hash) {
    unsigned char password[128];
    unsigned char computed[32];
    unsigned char expected[32];
    int i, len, diff;

    len = 0;
    while (len < 127) {
        int c = fgetc(stdin);
        if (c == '\n' || c == EOF) {
            break;
        }
        password[len++] = (unsigned char)c;
    }
    password[len] = '\0';

    sha256(password, len, computed);

    if (strlen(stored_hash) != 64) {
        memset(password, 0, 128);
        memset(computed, 0, 32);
        return 0;
    }

    for (i = 0; i < 32; i++) {
        int h = hex_digit_to_int(stored_hash[2*i]);
        int l = hex_digit_to_int(stored_hash[2*i+1]);
        if (h < 0 || l < 0) {
            memset(password, 0, 128);
            memset(computed, 0, 32);
            return 0;
        }
        expected[i] = (h << 4) | l;
    }

    diff = 0;
    for (i = 0; i < 32; i++) {
        diff |= (computed[i] ^ expected[i]);
    }

    memset(password, 0, 128);
    memset(computed, 0, 32);
    memset(expected, 0, 32);

    return (diff == 0) ? 1 : 0;
}
