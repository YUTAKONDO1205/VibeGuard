#include <stdio.h>
#include <stddef.h>
#include <string.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

/* Compiler-barrier-based secure erase: the memset cannot be elided because
   the compiler must assume the inline asm reads the memory. */
static void secure_wipe(void *p, size_t n)
{
    if (p == NULL || n == 0)
        return;
    memset(p, 0, n);
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(p), "r"(n) : "memory");
#else
    /* Portable fallback: volatile byte-by-byte store. */
    {
        volatile unsigned char *vp = (volatile unsigned char *)p;
        size_t i;
        for (i = 0; i < n; i++)
            vp[i] = 0;
    }
#endif
}

/* Constant-time comparison of two byte buffers. */
static int ct_equal(const unsigned char *a, const unsigned char *b, size_t n)
{
    unsigned char diff = 0;
    size_t i;
    for (i = 0; i < n; i++)
        diff = (unsigned char)(diff | (unsigned char)(a[i] ^ b[i]));
    return diff == 0;
}

/* Parse 64 lowercase/uppercase hex chars into 32 bytes. Returns 0 on success. */
static int hex_to_bytes32(const char *hex, unsigned char out[32])
{
    size_t i;
    if (hex == NULL)
        return -1;
    for (i = 0; i < 64; i++) {
        unsigned char c = (unsigned char)hex[i];
        unsigned char v;
        if (c >= '0' && c <= '9')
            v = (unsigned char)(c - '0');
        else if (c >= 'a' && c <= 'f')
            v = (unsigned char)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F')
            v = (unsigned char)(c - 'A' + 10);
        else
            return -1;
        if ((i & 1u) == 0u)
            out[i / 2] = (unsigned char)(v << 4);
        else
            out[i / 2] = (unsigned char)(out[i / 2] | v);
    }
    if (hex[64] != '\0')
        return -1;
    return 0;
}

/*
 * Reads a password from stdin into a fixed 128-byte stack buffer, hashes it
 * with SHA-256 and compares against stored_hash.
 *
 * stored_hash is a 64-character lowercase/uppercase hex string.
 * Returns 1 on match, 0 otherwise.
 *
 * Every buffer that held the password or its derivatives is wiped before
 * returning, on every exit path.
 */
int verify_password(const char *stored_hash)
{
    char password[128];
    unsigned char digest[32];
    unsigned char expected[32];
    size_t len = 0;
    int result = 0;
    int c;
    int overflow = 0;

    memset(password, 0, sizeof(password));
    memset(digest, 0, sizeof(digest));
    memset(expected, 0, sizeof(expected));

    if (stored_hash == NULL)
        goto done;

    if (hex_to_bytes32(stored_hash, expected) != 0)
        goto done;

    /* Read one line; leave room for no terminator requirement since we hash
       exactly len bytes, but keep at most sizeof(password) bytes. */
    while ((c = fgetc(stdin)) != EOF && c != '\n') {
        if (c == '\r')
            continue;
        if (len < sizeof(password))
            password[len++] = (char)c;
        else
            overflow = 1; /* keep draining the line, but reject later */
    }

    if (overflow)
        goto done;

    sha256((const unsigned char *)password, len, digest);

    result = ct_equal(digest, expected, sizeof(digest));

done:
    secure_wipe(password, sizeof(password));
    secure_wipe(digest, sizeof(digest));
    secure_wipe(expected, sizeof(expected));
    secure_wipe(&len, sizeof(len));
    return result;
}
