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
    unsigned char stored_hash_bin[32];
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

    if (stored_hash != NULL) {
        size_t i;
        int mismatch = 0;
        size_t hex_len = strlen(stored_hash);

        if (hex_len == 64) {
            for (i = 0; i < 32; i++) {
                unsigned int byte_val;
                if (sscanf(stored_hash + (i * 2), "%2x", &byte_val) != 1) {
                    mismatch = 1;
                    break;
                }
                stored_hash_bin[i] = (unsigned char)byte_val;
            }

            if (!mismatch) {
                unsigned char diff = 0;
                for (i = 0; i < 32; i++) {
                    diff |= (unsigned char)(computed_hash[i] ^ stored_hash_bin[i]);
                }
                result = (diff == 0) ? 1 : 0;
            } else {
                result = 0;
            }
        } else {
            result = 0;
        }
    } else {
        result = 0;
    }

    secure_zero(password, sizeof(password));
    secure_zero(computed_hash, sizeof(computed_hash));
    secure_zero(stored_hash_bin, sizeof(stored_hash_bin));

    return result;
}
