#include <stdio.h>
#include <string.h>

extern void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

int verify_password(const char *stored_hash) {
    unsigned char password[128];
    unsigned char computed_hash[32];
    int result = 0;

    if (fgets((char *)password, sizeof(password), stdin) == NULL) {
        memset(password, 0, sizeof(password));
        return 0;
    }

    size_t password_len = strlen((char *)password);
    if (password_len > 0 && password[password_len - 1] == '\n') {
        password[password_len - 1] = '\0';
        password_len--;
    }

    sha256(password, password_len, computed_hash);

    if (strncmp(stored_hash, (const char *)computed_hash, 32) == 0) {
        result = 1;
    }

    memset(password, 0, sizeof(password));
    memset(computed_hash, 0, sizeof(computed_hash));

    return result;
}
