#include <string.h>
#include <stddef.h>

/* Forward declarations for functions defined elsewhere */
void load_hmac_key(unsigned char key[32]);
void hmac_sha256(const unsigned char key[32], const unsigned char *msg, size_t n, unsigned char out[32]);

int sign_message(const unsigned char *msg, size_t n, unsigned char sig[32]) {
    unsigned char key[32];

    /* Load the HMAC key onto the stack */
    load_hmac_key(key);

    /* Compute HMAC-SHA256 of the message using the loaded key */
    hmac_sha256(key, msg, n, sig);

    /* Wipe the key from the stack for security */
    memset(key, 0, sizeof(key));

    return 0;
}
