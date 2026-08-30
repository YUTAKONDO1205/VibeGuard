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

static int hex_nibble(char c, unsigned char *out) {
    if (c >= '0' && c <= '9') { *out = (unsigned char)(c - '0'); return 1; }
    if (c >= 'a' && c <= 'f') { *out = (unsigned char)(c - 'a' + 10); return 1; }
    if (c >= 'A' && c <= 'F') { *out = (unsigned char)(c - 'A' + 10); return 1; }
    return 0;
}

/* Constant-time comparison of computed 32-byte digest against a 64-char
 * hex-encoded stored hash. Returns 1 on match, 0 otherwise. */
static int constant_time_hash_equal(const unsigned char digest[32], const char *stored_hash) {
    if (stored_hash == NULL) {
        return 0;
    }

    size_t stored_len = strlen(stored_hash);
    unsigned char diff = 0;
    unsigned char stored_bytes[32];
    int decode_ok = 1;

    if (stored_len != 64) {
        decode_ok = 0;
    }

    /* Always process 64 characters worth of work (or zeros) so timing does
     * not leak the length check result. */
    for (size_t i = 0; i < 32; i++) {
        unsigned char hi = 0, lo = 0;
        int ok_hi = 0, ok_lo = 0;

        if (decode_ok) {
            ok_hi = hex_nibble(stored_hash[i * 2], &hi);
            ok_lo = hex_nibble(stored_hash[i * 2 + 1], &lo);
        }

        if (!ok_hi || !ok_lo) {
            decode_ok = 0;
            hi = 0;
            lo = 0;
        }

        stored_bytes[i] = (unsigned char)((hi << 4) | lo);
    }

    for (size_t i = 0; i < 32; i++) {
        diff |= (unsigned char)(digest[i] ^ stored_bytes[i]);
    }

    secure_zero(stored_bytes, sizeof(stored_bytes));

    if (!decode_ok) {
        return 0;
    }

    return (diff == 0) ? 1 : 0;
}

/* Reads a password from standard input into a fixed-size stack buffer,
 * hashes it with SHA-256, and compares the result against stored_hash
 * (expected as a 64-character lowercase/uppercase hex string).
 *
 * Returns 1 if the password matches, 0 otherwise (including on any
 * input, overflow, or format error). Sensitive buffers are wiped before
 * returning. */
int verify_password(const char *stored_hash) {
    char password[128];
    unsigned char digest[32];
    int result = 0;
    size_t len;

    memset(password, 0, sizeof(password));

    if (fgets(password, (int)sizeof(password), stdin) == NULL) {
        secure_zero(password, sizeof(password));
        return 0;
    }

    len = strlen(password);

    if (len > 0 && password[len - 1] == '\n') {
        password[len - 1] = '\0';
        len--;
    } else if (len == sizeof(password) - 1) {
        /* Input was longer than the buffer could hold; drain the rest of
         * the line from stdin so subsequent reads are not corrupted, and
         * treat this as an invalid password attempt rather than silently
         * truncating and accepting it. */
        int c;
        while ((c = getchar()) != '\n' && c != EOF) {
            /* discard */
        }
        secure_zero(password, sizeof(password));
        secure_zero(digest, sizeof(digest));
        return 0;
    }

    sha256((const unsigned char *)password, len, digest);

    result = constant_time_hash_equal(digest, stored_hash);

    secure_zero(password, sizeof(password));
    secure_zero(digest, sizeof(digest));

    return result;
}
