#include <stdio.h>
#include <string.h>
#include <stddef.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

/* Parse a 64-character lowercase/uppercase hex string into 32 bytes.
   Returns 0 on success, -1 on malformed input. */
static int hex_to_bytes32(const char *hex, unsigned char out[32])
{
    size_t i;

    if (hex == NULL || strlen(hex) != 64) {
        return -1;
    }

    for (i = 0; i < 32; i++) {
        int hi, lo, j;
        int v[2];

        for (j = 0; j < 2; j++) {
            char c = hex[i * 2 + j];
            if (c >= '0' && c <= '9') {
                v[j] = c - '0';
            } else if (c >= 'a' && c <= 'f') {
                v[j] = c - 'a' + 10;
            } else if (c >= 'A' && c <= 'F') {
                v[j] = c - 'A' + 10;
            } else {
                return -1;
            }
        }
        hi = v[0];
        lo = v[1];
        out[i] = (unsigned char)((hi << 4) | lo);
    }

    return 0;
}

/* Length-independent, value-independent comparison of 32 bytes. */
static int ct_equal32(const unsigned char *a, const unsigned char *b)
{
    unsigned char diff = 0;
    size_t i;

    for (i = 0; i < 32; i++) {
        diff |= (unsigned char)(a[i] ^ b[i]);
    }

    return diff == 0;
}

int verify_password(const char *stored_hash)
{
    char password[128];
    unsigned char digest[32];
    unsigned char expected[32];
    size_t len;
    int result = 0;

    memset(password, 0, sizeof(password));
    memset(digest, 0, sizeof(digest));
    memset(expected, 0, sizeof(expected));

    if (stored_hash == NULL) {
        return 0;
    }

    if (hex_to_bytes32(stored_hash, expected) != 0) {
        return 0;
    }

    /* fgets bounds the read to the buffer size, including the NUL terminator. */
    if (fgets(password, (int)sizeof(password), stdin) == NULL) {
        memset(password, 0, sizeof(password));
        memset(expected, 0, sizeof(expected));
        return 0;
    }

    /* Strip a single trailing newline (CR/LF) if present. */
    len = strlen(password);
    while (len > 0 && (password[len - 1] == '\n' || password[len - 1] == '\r')) {
        password[len - 1] = '\0';
        len--;
    }

    sha256((const unsigned char *)password, len, digest);

    result = ct_equal32(digest, expected);

    /* Erase the plaintext password and derived material from the stack. */
    memset(password, 0, sizeof(password));
    memset(digest, 0, sizeof(digest));
    memset(expected, 0, sizeof(expected));

    return result ? 1 : 0;
}
