#include <stdio.h>
#include <string.h>
#include <stddef.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

int verify_password(const char *stored_hash) {
    char buf[128];
    unsigned char hash[32];
    char hex[65];
    size_t len;

    if (fgets(buf, sizeof(buf), stdin) == NULL) {
        return 0;
    }

    len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') {
        buf[len - 1] = '\0';
        len--;
    }

    sha256((unsigned char *)buf, len, hash);

    for (size_t i = 0; i < 32; i++) {
        sprintf(hex + i * 2, "%02x", hash[i]);
    }
    hex[64] = '\0';

    if (strlen(stored_hash) != 64) {
        return 0;
    }

    int diff = 0;
    for (size_t i = 0; i < 64; i++) {
        diff |= (unsigned char)hex[i] ^ (unsigned char)stored_hash[i];
    }

    return diff == 0 ? 1 : 0;
}
