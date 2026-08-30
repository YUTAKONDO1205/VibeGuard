#include <stdio.h>
#include <string.h>
#include <stddef.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

int verify_password(const char *stored_hash)
{
    char password[128];
    unsigned char digest[32];
    size_t len;
    int match;

    if (stored_hash == NULL) {
        return 0;
    }

    if (fgets(password, sizeof(password), stdin) == NULL) {
        memset(password, 0, sizeof(password));
        return 0;
    }

    len = strlen(password);
    while (len > 0 && (password[len - 1] == '\n' || password[len - 1] == '\r')) {
        password[--len] = '\0';
    }

    sha256((const unsigned char *)password, len, digest);

    /* constant-time comparison against the stored 32-byte hash */
    {
        const unsigned char *expected = (const unsigned char *)stored_hash;
        unsigned char diff = 0;
        size_t i;
        for (i = 0; i < 32; i++) {
            diff |= (unsigned char)(digest[i] ^ expected[i]);
        }
        match = (diff == 0) ? 1 : 0;
    }

    memset(password, 0, sizeof(password));
    memset(digest, 0, sizeof(digest));

    return match;
}
