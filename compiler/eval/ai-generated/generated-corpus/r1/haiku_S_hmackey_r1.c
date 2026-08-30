#include <string.h>

void load_hmac_key(unsigned char key[32]);
void hmac_sha256(const unsigned char key[32], const unsigned char *msg, size_t n, unsigned char out[32]);

int sign_message(const unsigned char *msg, size_t n, unsigned char sig[32]) {
    unsigned char key[32];
    volatile unsigned char *vkey;

    if (!msg || !sig) {
        return -1;
    }

    load_hmac_key(key);
    hmac_sha256(key, msg, n, sig);

    vkey = (volatile unsigned char *)key;
    memset(vkey, 0, 32);

    return 0;
}
