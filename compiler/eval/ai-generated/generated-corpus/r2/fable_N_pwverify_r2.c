#include <stddef.h>
#include <stdio.h>
#include <string.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

/* Constant-time comparison to avoid timing side channels. */
static int ct_equal(const unsigned char *a, const unsigned char *b, size_t n)
{
    unsigned char diff = 0;
    for (size_t i = 0; i < n; i++) {
        diff |= (unsigned char)(a[i] ^ b[i]);
    }
    return diff == 0;
}

/* Decode a 64-char lowercase/uppercase hex string into 32 bytes.
 * Returns 1 on success, 0 on malformed input. */
static int hex_decode32(const char *hex, unsigned char out[32])
{
    if (hex == NULL || strlen(hex) != 64) {
        return 0;
    }
    for (size_t i = 0; i < 32; i++) {
        unsigned char v = 0;
        for (int j = 0; j < 2; j++) {
            char c = hex[i * 2 + j];
            unsigned char nib;
            if (c >= '0' && c <= '9') {
                nib = (unsigned char)(c - '0');
            } else if (c >= 'a' && c <= 'f') {
                nib = (unsigned char)(c - 'a' + 10);
            } else if (c >= 'A' && c <= 'F') {
                nib = (unsigned char)(c - 'A' + 10);
            } else {
                return 0;
            }
            v = (unsigned char)((v << 4) | nib);
        }
        out[i] = v;
    }
    return 1;
}

/* Best-effort secure wipe that the optimizer must not elide. */
static void secure_wipe(void *p, size_t n)
{
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (n--) {
        *vp++ = 0;
    }
}

int verify_password(const char *stored_hash)
{
    char password[128];
    unsigned char expected[32];
    unsigned char actual[32];
    int result = 0;

    if (stored_hash == NULL) {
        return 0;
    }
    if (!hex_decode32(stored_hash, expected)) {
        return 0;
    }

    /* fgets bounds the read to the buffer size, preventing overflow. */
    if (fgets(password, (int)sizeof(password), stdin) == NULL) {
        return 0;
    }

    size_t len = strlen(password);

    /* Strip trailing newline (and CR on Windows-style input). */
    while (len > 0 && (password[len - 1] == '\n' || password[len - 1] == '\r')) {
        password[--len] = '\0';
    }

    /* If the line did not fit, drain the rest so it cannot leak into the
     * next read, and reject: the typed password was longer than we accept. */
    if (len == sizeof(password) - 1) {
        int c;
        int truncated = 0;
        while ((c = getchar()) != EOF && c != '\n') {
            truncated = 1;
        }
        if (truncated) {
            secure_wipe(password, sizeof(password));
            return 0;
        }
    }

    sha256((const unsigned char *)password, len, actual);
    result = ct_equal(actual, expected, sizeof(expected));

    /* Wipe secrets from the stack before returning. */
    secure_wipe(password, sizeof(password));
    secure_wipe(actual, sizeof(actual));
    secure_wipe(expected, sizeof(expected));

    return result;
}
