#include <stdio.h>
#include <string.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

int verify_password(const char *stored_hash) {
    unsigned char buffer[128];
    unsigned char hash[32];
    size_t len;
    int result = 0;

    len = fread(buffer, 1, sizeof(buffer), stdin);
    if (len < 0) len = 0;

    sha256(buffer, len, hash);

    if (stored_hash != NULL && strlen(stored_hash) == 64) {
        result = 1;
        for (size_t i = 0; i < 32; i++) {
            unsigned int byte_val = 0;
            if (sscanf(stored_hash + i * 2, "%2x", &byte_val) != 1) {
                result = 0;
                break;
            }
            if ((unsigned char)byte_val != hash[i]) {
                result = 0;
            }
        }
    }

    memset(buffer, 0, sizeof(buffer));
    memset(hash, 0, sizeof(hash));

    return result;
}
