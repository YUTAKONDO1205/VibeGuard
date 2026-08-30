#include <stddef.h>
#include <stdio.h>
#include <string.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

/* Best-effort secure wipe that the compiler must not optimize away. */
static void secure_wipe(void *p, size_t n)
{
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (n--) {
        *vp++ = 0;
    }
}

/* Constant-time comparison: no early exit on mismatch. */
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

/*
 * Reads a password from stdin, hashes it with SHA-256, and compares the
 * digest against stored_hash. stored_hash may be either the 64-character
 * hex encoding of the digest or the raw 32-byte digest (hex is detected
 * first, by length and content).
 *
 * Returns 1 on match, 0 on mismatch or any error.
 */
int verify_password(const char *stored_hash)
{
    char buf[128];
    unsigned char digest[32];
    unsigned char stored[32];
    size_t len;
    int result = 0;

    if (stored_hash == NULL) {
        return 0;
    }

    if (fgets(buf, (int)sizeof(buf), stdin) == NULL) {
        secure_wipe(buf, sizeof(buf));
        return 0;
    }

    len = strlen(buf);

    /* Strip trailing newline (and CR, if present). */
    if (len > 0 && buf[len - 1] == '\n') {
        buf[--len] = '\0';
    }
    if (len > 0 && buf[len - 1] == '\r') {
        buf[--len] = '\0';
    }

    /*
     * If no newline was found and the buffer is full, the input exceeded
     * the buffer: drain the rest of the line and reject, so a truncated
     * prefix of an overlong password can never verify.
     */
    if (len == sizeof(buf) - 1) {
        int c;
        int overflowed = 0;
        while ((c = getchar()) != EOF && c != '\n') {
            overflowed = 1;
        }
        if (overflowed) {
            secure_wipe(buf, sizeof(buf));
            return 0;
        }
    }

    sha256((const unsigned char *)buf, len, digest);
    secure_wipe(buf, sizeof(buf));

    /* Interpret stored_hash: 64 hex characters, or raw 32 bytes. */
    {
        size_t i;
        int is_hex = 1;
        for (i = 0; i < 64; i++) {
            if (stored_hash[i] == '\0' || hex_val(stored_hash[i]) < 0) {
                is_hex = 0;
                break;
            }
        }
        if (is_hex && stored_hash[64] != '\0') {
            is_hex = 0;
        }
        if (is_hex) {
            for (i = 0; i < 32; i++) {
                int hi = hex_val(stored_hash[2 * i]);
                int lo = hex_val(stored_hash[2 * i + 1]);
                stored[i] = (unsigned char)((hi << 4) | lo);
            }
        } else {
            memcpy(stored, stored_hash, 32);
        }
    }

    result = ct_equal(digest, stored, sizeof(digest));

    secure_wipe(digest, sizeof(digest));
    secure_wipe(stored, sizeof(stored));

    return result;
}
