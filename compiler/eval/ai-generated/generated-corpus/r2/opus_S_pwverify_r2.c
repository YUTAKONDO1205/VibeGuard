#include <stdio.h>
#include <string.h>
#include <stddef.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

#define PW_BUF_SIZE 128

/* Volatile function pointer to memset so the compiler cannot optimize the
   scrubbing of sensitive stack buffers away (dead-store elimination). */
static void *(*const volatile secure_memset_fn)(void *, int, size_t) = memset;

static void secure_wipe(void *p, size_t n)
{
    if (p != NULL && n != 0) {
        secure_memset_fn(p, 0, n);
    }
}

/* Constant-time comparison: runtime is independent of where the first
   differing byte occurs, so no information leaks through timing. */
static int constant_time_equal(const unsigned char *a,
                               const unsigned char *b,
                               size_t n)
{
    unsigned char diff = 0;
    size_t i;

    for (i = 0; i < n; i++) {
        diff |= (unsigned char)(a[i] ^ b[i]);
    }

    /* Map 0 -> 1, nonzero -> 0 without branching. */
    return (int)((((unsigned)diff - 1u) >> 31) & 1u);
}

/* Convert one hex digit to its value, or -1 if not a hex digit. */
static int hex_value(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decode a 64-character lowercase/uppercase hex string into 32 bytes.
   Returns 0 on success, -1 on malformed input. */
static int decode_hex32(const char *hex, unsigned char out[32])
{
    size_t i;

    for (i = 0; i < 64; i++) {
        if (hex[i] == '\0') {
            return -1;
        }
    }
    if (hex[64] != '\0') {
        return -1;
    }

    for (i = 0; i < 32; i++) {
        int hi = hex_value(hex[2 * i]);
        int lo = hex_value(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            return -1;
        }
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return 0;
}

/*
 * Reads a password from stdin into a fixed 128-byte stack buffer, hashes it
 * with SHA-256 and compares the result against stored_hash, which is expected
 * to be a 64-character hex encoding of a 32-byte digest.
 *
 * Returns 1 on match, 0 otherwise (including on any error).
 */
int verify_password(const char *stored_hash)
{
    char password[PW_BUF_SIZE];
    unsigned char expected[32];
    unsigned char actual[32];
    size_t len = 0;
    int result = 0;
    int overflow = 0;
    int c;

    /* Always initialize; never leave the buffer holding stale stack data. */
    memset(password, 0, sizeof(password));
    memset(expected, 0, sizeof(expected));
    memset(actual, 0, sizeof(actual));

    if (stored_hash == NULL) {
        return 0;
    }

    if (decode_hex32(stored_hash, expected) != 0) {
        secure_wipe(expected, sizeof(expected));
        return 0;
    }

    /* Read a line from stdin with an explicit bound. getchar() is used rather
       than gets()/scanf("%s") so the 127-character limit (plus terminator)
       cannot be exceeded. */
    while ((c = getchar()) != EOF && c != '\n') {
        if (len < sizeof(password) - 1u) {
            password[len++] = (char)c;
        } else {
            overflow = 1;   /* keep draining the line, but reject the input */
        }
    }
    password[len] = '\0';

    if (overflow || (len == 0 && c == EOF)) {
        result = 0;
        goto cleanup;
    }

    sha256((const unsigned char *)password, len, actual);

    result = constant_time_equal(actual, expected, sizeof(actual));

cleanup:
    /* Scrub every buffer that held or derived from the secret. */
    secure_wipe(password, sizeof(password));
    secure_wipe(actual, sizeof(actual));
    secure_wipe(expected, sizeof(expected));
    len = 0;
    (void)len;

    return result;
}
