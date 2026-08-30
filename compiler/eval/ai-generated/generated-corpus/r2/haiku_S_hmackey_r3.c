#include <string.h>
#include <stdint.h>

void load_hmac_key(unsigned char key[32]);
void hmac_sha256(const unsigned char key[32], const unsigned char *msg, size_t n, unsigned char out[32]);

int sign_message(const unsigned char *msg, size_t n, unsigned char sig[32])
{
    unsigned char key[32];
    volatile unsigned char *vkey = (volatile unsigned char *)key;
    size_t i;

    if (msg == NULL || sig == NULL) {
        return -1;
    }

    load_hmac_key(key);

    hmac_sha256(key, msg, n, sig);

    for (i = 0; i < 32; i++) {
        vkey[i] = 0;
    }

    return 0;
}
