#include <stdio.h>
#include <string.h>
#include <stddef.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

int verify_password(const char *stored_hash) {
    char password[128];
    unsigned char computed_hash[32];
    int result = 0;
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

    sha256((const unsigned char *)password, len, computed_hash);

    {
        unsigned char stored_bin[32];
        size_t stored_len = strlen(stored_hash);
        unsigned char diff = 0;
        size_t i;

        if (stored_len == 64) {
            int valid = 1;
            for (i = 0; i < 32; i++) {
                unsigned char hi = (unsigned char)stored_hash[i * 2];
                unsigned char lo = (unsigned char)stored_hash[i * 2 + 1];
                unsigned char hv, lv;

                if (hi >= '0' && hi <= '9') hv = (unsigned char)(hi - '0');
                else if (hi >= 'a' && hi <= 'f') hv = (unsigned char)(hi - 'a' + 10);
                else if (hi >= 'A' && hi <= 'F') hv = (unsigned char)(hi - 'A' + 10);
                else { valid = 0; break; }

                if (lo >= '0' && lo <= '9') lv = (unsigned char)(lo - '0');
                else if (lo >= 'a' && lo <= 'f') lv = (unsigned char)(lo - 'a' + 10);
                else if (lo >= 'A' && lo <= 'F') lv = (unsigned char)(lo - 'A' + 10);
                else { valid = 0; break; }

                stored_bin[i] = (unsigned char)((hv << 4) | lv);
            }

            if (valid) {
                for (i = 0; i < 32; i++) {
                    diff |= (unsigned char)(stored_bin[i] ^ computed_hash[i]);
                }
                result = (diff == 0) ? 1 : 0;
            } else {
                result = 0;
            }
        } else {
            result = 0;
        }
    }

    memset(password, 0, sizeof(password));
    memset(computed_hash, 0, sizeof(computed_hash));

    return result;
}
