#include <stdio.h>
#include <string.h>
#include <stddef.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

int verify_password(const char *stored_hash) {
    char password[128];
    size_t len = 0;
    int c;

    memset(password, 0, sizeof(password));

    while (len < sizeof(password) - 1) {
        c = fgetc(stdin);
        if (c == EOF || c == '\n') {
            break;
        }
        password[len++] = (char)c;
    }
    password[len] = '\0';

    unsigned char computed_hash[32];
    sha256((const unsigned char *)password, len, computed_hash);

    memset(password, 0, sizeof(password));

    unsigned char stored_hash_bin[32];
    for (int i = 0; i < 32; i++) {
        char hex[3];
        hex[0] = stored_hash[i * 2];
        hex[1] = stored_hash[i * 2 + 1];
        hex[2] = '\0';
        if (hex[0] == '\0' || hex[1] == '\0') {
            memset(computed_hash, 0, sizeof(computed_hash));
            return 0;
        }
        unsigned int byte_val = 0;
        for (int j = 0; j < 2; j++) {
            char ch = hex[j];
            byte_val <<= 4;
            if (ch >= '0' && ch <= '9') {
                byte_val |= (unsigned int)(ch - '0');
            } else if (ch >= 'a' && ch <= 'f') {
                byte_val |= (unsigned int)(ch - 'a' + 10);
            } else if (ch >= 'A' && ch <= 'F') {
                byte_val |= (unsigned int)(ch - 'A' + 10);
            } else {
                memset(computed_hash, 0, sizeof(computed_hash));
                return 0;
            }
        }
        stored_hash_bin[i] = (unsigned char)byte_val;
    }

    volatile unsigned char diff = 0;
    for (int i = 0; i < 32; i++) {
        diff |= (unsigned char)(computed_hash[i] ^ stored_hash_bin[i]);
    }

    memset(computed_hash, 0, sizeof(computed_hash));
    memset(stored_hash_bin, 0, sizeof(stored_hash_bin));

    return diff == 0 ? 1 : 0;
}
