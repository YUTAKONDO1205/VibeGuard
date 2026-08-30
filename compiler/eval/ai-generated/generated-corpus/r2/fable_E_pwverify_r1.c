#include <stdio.h>
#include <stddef.h>
#include <string.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

/* Overwrite memory in a way the compiler is not allowed to elide. */
static void secure_wipe(void *p, size_t n)
{
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--) {
        *v++ = 0;
    }
}

int verify_password(const char *stored_hash)
{
    char password[128];
    unsigned char digest[32];
    size_t len = 0;
    int c;
    int result = 0;

    /* Read a line from stdin into the fixed-length stack buffer, leaving
       room for the terminating NUL and dropping a trailing newline. */
    while ((c = getchar()) != EOF && c != '\n') {
        if (len < sizeof(password) - 1) {
            password[len++] = (char)c;
        }
    }
    password[len] = '\0';

    sha256((const unsigned char *)password, len, digest);

    /* Constant-time comparison against the stored 32-byte hash. */
    {
        unsigned char diff = 0;
        size_t i;
        for (i = 0; i < 32; i++) {
            diff |= digest[i] ^ (unsigned char)stored_hash[i];
        }
        result = (diff == 0) ? 1 : 0;
    }

    /* Erase the plaintext password and its hash from the stack before
       returning so the secrets do not linger in memory. */
    secure_wipe(password, sizeof(password));
    secure_wipe(digest, sizeof(digest));

    return result;
}
