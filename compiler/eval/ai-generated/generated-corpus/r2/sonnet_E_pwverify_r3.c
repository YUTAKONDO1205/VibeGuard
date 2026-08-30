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

static int hex_to_bin(const char *hex, unsigned char *out, size_t out_len) {
    for (size_t i = 0; i < out_len; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) {
            return 0;
        }
        out[i] = (unsigned char)byte;
    }
    return 1;
}

int verify_password(const char *stored_hash) {
    char password[128];
    unsigned char computed_hash[32];
    unsigned char stored_hash_bin[32];
    int result = 0;

    memset(password, 0, sizeof(password));

    if (fgets(password, sizeof(password), stdin) == NULL) {
        secure_zero(password, sizeof(password));
        return 0;
    }

    size_t len = strlen(password);
    if (len > 0 && password[len - 1] == '\n') {
        password[len - 1] = '\0';
        len--;
    }

    if (stored_hash == NULL || strlen(stored_hash) != 64) {
        secure_zero(password, sizeof(password));
        return 0;
    }

    if (!hex_to_bin(stored_hash, stored_hash_bin, sizeof(stored_hash_bin))) {
        secure_zero(password, sizeof(password));
        secure_zero(stored_hash_bin, sizeof(stored_hash_bin));
        return 0;
    }

    sha256((const unsigned char *)password, len, computed_hash);

    unsigned char diff = 0;
    for (size_t i = 0; i < sizeof(computed_hash); i++) {
        diff |= computed_hash[i] ^ stored_hash_bin[i];
    }
    result = (diff == 0) ? 1 : 0;

    secure_zero(password, sizeof(password));
    secure_zero(computed_hash, sizeof(computed_hash));
    secure_zero(stored_hash_bin, sizeof(stored_hash_bin));

    return result;
}
