#include <stdio.h>
#include <string.h>
#include <stddef.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

static void secure_zero(void *p, size_t n) {
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (n--) {
        *vp++ = 0;
    }
}

int verify_password(const char *stored_hash) {
    char password[128];
    unsigned char computed_hash[32];
    unsigned char stored_bin[32];
    size_t len;
    int result = 0;

    memset(password, 0, sizeof(password));

    if (fgets(password, sizeof(password), stdin) == NULL) {
        secure_zero(password, sizeof(password));
        return 0;
    }

    len = strlen(password);
    if (len > 0 && password[len - 1] == '\n') {
        password[len - 1] = '\0';
        len--;
    }

    sha256((const unsigned char *)password, len, computed_hash);

    if (stored_hash != NULL && strlen(stored_hash) == 64) {
        size_t i;
        int valid = 1;
        for (i = 0; i < 32; i++) {
            unsigned int hi, lo;
            char c1 = stored_hash[i * 2];
            char c2 = stored_hash[i * 2 + 1];

            if (c1 >= '0' && c1 <= '9') hi = (unsigned int)(c1 - '0');
            else if (c1 >= 'a' && c1 <= 'f') hi = (unsigned int)(c1 - 'a' + 10);
            else if (c1 >= 'A' && c1 <= 'F') hi = (unsigned int)(c1 - 'A' + 10);
            else { valid = 0; break; }

            if (c2 >= '0' && c2 <= '9') lo = (unsigned int)(c2 - '0');
            else if (c2 >= 'a' && c2 <= 'f') lo = (unsigned int)(c2 - 'a' + 10);
            else if (c2 >= 'A' && c2 <= 'F') lo = (unsigned int)(c2 - 'A' + 10);
            else { valid = 0; break; }

            stored_bin[i] = (unsigned char)((hi << 4) | lo);
        }

        if (valid) {
            unsigned char diff = 0;
            for (i = 0; i < 32; i++) {
                diff |= (unsigned char)(computed_hash[i] ^ stored_bin[i]);
            }
            result = (diff == 0) ? 1 : 0;
        } else {
            result = 0;
        }
    } else {
        result = 0;
    }

    secure_zero(password, sizeof(password));
    secure_zero(computed_hash, sizeof(computed_hash));
    secure_zero(stored_bin, sizeof(stored_bin));

    return result;
}
