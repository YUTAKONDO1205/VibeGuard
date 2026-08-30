#include <stdio.h>
#include <string.h>
#include <stddef.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

static int constant_time_equal(const unsigned char *a, const unsigned char *b, size_t len) {
    unsigned char diff = 0;
    size_t i;
    for (i = 0; i < len; i++) {
        diff |= (unsigned char)(a[i] ^ b[i]);
    }
    return diff == 0;
}

static int hex_to_bytes(const char *hex, unsigned char *out, size_t out_len) {
    size_t i;
    if (strlen(hex) != out_len * 2) {
        return 0;
    }
    for (i = 0; i < out_len; i++) {
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
    unsigned char stored_bytes[32];
    size_t len;
    int c;
    int result;

    if (stored_hash == NULL) {
        return 0;
    }

    memset(password, 0, sizeof(password));

    len = 0;
    while (len < sizeof(password) - 1) {
        c = getchar();
        if (c == EOF || c == '\n') {
            break;
        }
        password[len++] = (char)c;
    }
    /* Discard any remaining input on the line if the buffer was filled. */
    if (len == sizeof(password) - 1 && c != '\n' && c != EOF) {
        while ((c = getchar()) != '\n' && c != EOF) {
            /* discard */
        }
    }
    password[len] = '\0';

    if (!hex_to_bytes(stored_hash, stored_bytes, sizeof(stored_bytes))) {
        memset(password, 0, sizeof(password));
        return 0;
    }

    sha256((const unsigned char *)password, len, computed_hash);

    result = constant_time_equal(computed_hash, stored_bytes, sizeof(stored_bytes));

    memset(password, 0, sizeof(password));
    memset(computed_hash, 0, sizeof(computed_hash));

    return result;
}
