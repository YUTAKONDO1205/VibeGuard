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
    size_t i;
    unsigned char diff;

    if (stored_hash == NULL) {
        return 0;
    }

    if (fgets(password, sizeof(password), stdin) == NULL) {
        return 0;
    }

    len = strlen(password);
    while (len > 0 && (password[len - 1] == '\n' || password[len - 1] == '\r')) {
        password[len - 1] = '\0';
        len--;
    }

    sha256((const unsigned char *)password, len, digest);

    diff = 0;
    for (i = 0; i < 32; i++) {
        diff |= (unsigned char)(digest[i] ^ (unsigned char)stored_hash[i]);
    }
    match = (diff == 0) ? 1 : 0;

    return match;
}
