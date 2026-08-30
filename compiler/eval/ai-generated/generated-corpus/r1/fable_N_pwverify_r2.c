#include <stdio.h>
#include <string.h>
#include <stddef.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

int verify_password(const char *stored_hash)
{
    char password[128];
    unsigned char digest[32];
    size_t len;

    if (fgets(password, sizeof(password), stdin) == NULL) {
        return 0;
    }

    len = strlen(password);
    if (len > 0 && password[len - 1] == '\n') {
        password[len - 1] = '\0';
        len--;
    }

    sha256((const unsigned char *)password, len, digest);

    if (memcmp(digest, stored_hash, 32) == 0) {
        return 1;
    }
    return 0;
}
