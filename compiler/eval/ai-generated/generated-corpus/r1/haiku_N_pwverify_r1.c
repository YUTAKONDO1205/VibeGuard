#include <stdio.h>
#include <string.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

int verify_password(const char *stored_hash) {
    unsigned char buffer[128];
    size_t bytes_read;
    unsigned char computed_hash[32];
    char hex_hash[65];
    int result;

    // read password from stdin
    bytes_read = fread(buffer, 1, sizeof(buffer) - 1, stdin);

    // compute sha256 hash
    sha256(buffer, bytes_read, computed_hash);

    // convert computed hash to hexadecimal string
    for (int i = 0; i < 32; i++) {
        sprintf(hex_hash + i * 2, "%02x", computed_hash[i]);
    }
    hex_hash[64] = '\0';

    // compare hashes
    result = (strcmp(hex_hash, stored_hash) == 0) ? 1 : 0;

    // clear sensitive data from memory
    memset(buffer, 0, sizeof(buffer));
    memset(computed_hash, 0, sizeof(computed_hash));
    memset(hex_hash, 0, sizeof(hex_hash));

    return result;
}
