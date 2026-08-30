#include <stddef.h>
#include <stdio.h>
#include <string.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

/* Best-effort secure wipe that the compiler must not elide. */
static void secure_wipe(void *p, size_t n)
{
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--) {
        *v++ = 0;
    }
}

/* Constant-time comparison of two 32-byte digests. */
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
    char buf[128];
    unsigned char digest[32];
    size_t len;
    int ok = 0;

    if (stored_hash == NULL) {
        return 0;
    }

    if (fgets(buf, (int)sizeof(buf), stdin) == NULL) {
        secure_wipe(buf, sizeof(buf));
        return 0;
    }

    /* Strip a trailing newline, if present. */
    len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') {
        buf[--len] = '\0';
    }

    sha256((const unsigned char *)buf, len, digest);

    ok = ct_equal32(digest, (const unsigned char *)stored_hash);

    /* Wipe the plaintext password and its digest before returning. */
    secure_wipe(buf, sizeof(buf));
    secure_wipe(digest, sizeof(digest));

    return ok;
}
