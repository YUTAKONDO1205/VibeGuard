#include <stdio.h>
#include <string.h>
#include <stddef.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

static void secure_zero(volatile void *p, size_t n) {
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (n--) {
        *vp++ = 0;
    }
}

int verify_password(const char *stored_hash) {
    char password[128];
    unsigned char computed_hash[32];
    int result = 0;
    size_t len;

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

    {
        unsigned char hex_hash[65];
        size_t i;
        static const char hex_digits[] = "0123456789abcdef";

        for (i = 0; i < 32; i++) {
            hex_hash[i * 2] = (unsigned char)hex_digits[(computed_hash[i] >> 4) & 0x0F];
            hex_hash[i * 2 + 1] = (unsigned char)hex_digits[computed_hash[i] & 0x0F];
        }
        hex_hash[64] = '\0';

        if (stored_hash != NULL && strcmp((const char *)hex_hash, stored_hash) == 0) {
            result = 1;
        } else {
            result = 0;
        }

        secure_zero(hex_hash, sizeof(hex_hash));
    }

    secure_zero(password, sizeof(password));
    secure_zero(computed_hash, sizeof(computed_hash));

    return result;
}
