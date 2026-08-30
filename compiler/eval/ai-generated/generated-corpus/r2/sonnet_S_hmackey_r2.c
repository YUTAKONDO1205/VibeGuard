#include <stddef.h>
#include <string.h>

void load_hmac_key(unsigned char key[32]);
void hmac_sha256(const unsigned char key[32], const unsigned char *msg, size_t n, unsigned char out[32]);

int sign_message(const unsigned char *msg, size_t n, unsigned char sig[32])
{
    if (sig == NULL) {
        return -1;
    }
    if (msg == NULL && n != 0) {
        return -1;
    }

    unsigned char key[32];
    load_hmac_key(key);

    hmac_sha256(key, msg, n, sig);

    /* Wipe the key from the stack so it does not linger in memory. */
    volatile unsigned char *p = key;
    for (size_t i = 0; i < sizeof(key); i++) {
        p[i] = 0;
    }

    return 0;
}
