#include <stddef.h>
#include <stdio.h>
#include <string.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

/* Best-effort secure wipe: volatile pointer prevents the compiler from
   eliding the memset as a dead store. */
static void secure_zero(void *p, size_t n)
{
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (n--) {
        *vp++ = 0;
    }
}

/* Constant-time comparison over a fixed length; no early exit. */
static int ct_equal(const unsigned char *a, const unsigned char *b, size_t n)
{
    unsigned char diff = 0;
    size_t i;
    for (i = 0; i < n; i++) {
        diff |= (unsigned char)(a[i] ^ b[i]);
    }
    return diff == 0;
}

/* Decode one hex character; returns -1 on invalid input. */
static int hex_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Parse a 64-character hex string into 32 bytes; returns 0 on failure. */
static int parse_hash_hex(const char *hex, unsigned char out[32])
{
    size_t i;
    if (hex == NULL) {
        return 0;
    }
    for (i = 0; i < 32; i++) {
        int hi = hex_val(hex[2 * i]);
        int lo;
        if (hi < 0) {
            return 0;
        }
        lo = hex_val(hex[2 * i + 1]);
        if (lo < 0) {
            return 0;
        }
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return hex[64] == '\0';
}

int verify_password(const char *stored_hash)
{
    char password[128];
    unsigned char computed[32];
    unsigned char expected[32];
    size_t len;
    int result;

    if (!parse_hash_hex(stored_hash, expected)) {
        return 0;
    }

    /* fgets bounds the read to the buffer size, preventing overflow. */
    if (fgets(password, (int)sizeof(password), stdin) == NULL) {
        secure_zero(password, sizeof(password));
        return 0;
    }

    len = strlen(password);

    /* Strip the trailing newline if present. If there is none and the
       buffer is full, the input exceeded the limit: drain the rest of
       the line so it cannot leak into a later read, and reject. */
    if (len > 0 && password[len - 1] == '\n') {
        password[--len] = '\0';
    } else if (len == sizeof(password) - 1) {
        int c;
        while ((c = getchar()) != '\n' && c != EOF) {
            /* discard */
        }
        secure_zero(password, sizeof(password));
        return 0;
    }

    sha256((const unsigned char *)password, len, computed);
    result = ct_equal(computed, expected, sizeof(computed));

    /* Wipe secrets from the stack before returning. */
    secure_zero(password, sizeof(password));
    secure_zero(computed, sizeof(computed));

    return result;
}
