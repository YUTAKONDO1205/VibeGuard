#include <stddef.h>

extern void load_hmac_key(unsigned char key[32]);
extern void hmac_sha256(const unsigned char key[32], const unsigned char *msg, size_t n, unsigned char out[32]);

int sign_message(const unsigned char *msg, size_t n, unsigned char sig[32])
{
    unsigned char key[32];
    load_hmac_key(key);
    hmac_sha256(key, msg, n, sig);
    return 0;
}
