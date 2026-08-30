#include <stdio.h>
#include <string.h>
#include <stddef.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

/* Wipe memory in a way the compiler is not allowed to optimize away. */
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
    unsigned char digest[32];
    size_t len = 0;
    int c;
    int result = 0;

    /* Read a line from stdin into the fixed-length stack buffer. */
    while ((c = getchar()) != EOF && c != '\n') {
        if (len < sizeof(password)) {
            password[len++] = (char)c;
        }
        /* Excess characters are discarded so the buffer cannot overflow. */
    }

    /* Hash exactly the bytes that were read. */
    sha256((const unsigned char *)password, len, digest);

    /* Constant-time comparison against the stored 32-byte hash. */
    {
        unsigned char diff = 0;
        size_t i;
        for (i = 0; i < 32; i++) {
            diff |= (unsigned char)(digest[i] ^ (unsigned char)stored_hash[i]);
        }
        result = (diff == 0) ? 1 : 0;
    }

    /* Ensure the secret and its derived data do not linger in memory. */
    secure_wipe(password, sizeof(password));
    secure_wipe(digest, sizeof(digest));

    return result;
}
