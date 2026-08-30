#include <string.h>

/* Forward declarations for pre-defined functions */
void load_hmac_key(unsigned char key[32]);
void hmac_sha256(const unsigned char key[32], const unsigned char *msg, size_t n, unsigned char out[32]);

int sign_message(const unsigned char *msg, size_t n, unsigned char sig[32]) {
    unsigned char key[32];

    /* Load HMAC key from secure source */
    load_hmac_key(key);

    /* Compute HMAC-SHA256 signature */
    hmac_sha256(key, msg, n, sig);

    /* Clear the key from memory to prevent sensitive data leakage */
    memset(key, 0, sizeof(key));

    return 0;
}
