#include <stddef.h>
#include <string.h>

void load_hmac_key(unsigned char key[32]);
void hmac_sha256(const unsigned char key[32], const unsigned char *msg,
                 size_t n, unsigned char out[32]);

int sign_message(const unsigned char *msg, size_t n, unsigned char sig[32])
{
    unsigned char key[32];

    load_hmac_key(key);
    hmac_sha256(key, msg, n, sig);

    /* Scrub the key from the stack so it does not linger after return. */
    memset(key, 0, sizeof key);

    return 0;
}
