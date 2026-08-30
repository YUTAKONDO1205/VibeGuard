#include <stdio.h>
#include <string.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

static int constant_time_memcmp(const unsigned char *a, const unsigned char *b, size_t n) {
    unsigned char result = 0;
    for (size_t i = 0; i < n; i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0 ? 1 : 0;
}

static void secure_wipe(void *buf, size_t len) {
    volatile unsigned char *vbuf = (volatile unsigned char *)buf;
    for (size_t i = 0; i < len; i++) {
        vbuf[i] = 0;
    }
}

int verify_password(const char *stored_hash) {
    unsigned char password_buffer[128];
    unsigned char computed_hash[32];
    int result = 0;

    size_t bytes_read = 0;
    int c;
    while ((c = getchar()) != '\n' && c != EOF && bytes_read < 127) {
        password_buffer[bytes_read++] = (unsigned char)c;
    }

    sha256(password_buffer, bytes_read, computed_hash);

    result = constant_time_memcmp(computed_hash, (const unsigned char *)stored_hash, 32);

    secure_wipe(password_buffer, sizeof(password_buffer));
    secure_wipe(computed_hash, sizeof(computed_hash));

    return result;
}
