#include <stdio.h>
#include <string.h>
#include <stddef.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

int verify_password(const char *stored_hash)
{
    char password[128];

    if (fgets(password, sizeof(password), stdin) == NULL) {
        return 0;
    }

    size_t len = strlen(password);
    if (len > 0 && password[len - 1] == '\n') {
        password[len - 1] = '\0';
        len--;
    }

    unsigned char digest[32];
    sha256((const unsigned char *)password, len, digest);

    int match = (memcmp(digest, stored_hash, 32) == 0) ? 1 : 0;

    return match;
}
