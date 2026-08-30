#include <stddef.h>
#include <string.h>

void load_hmac_key(unsigned char key[32]);
void hmac_sha256(const unsigned char key[32], const unsigned char *msg, size_t n, unsigned char out[32]);

static void secure_zero(void *p, size_t n) {
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (n--) {
        *vp++ = 0;
    }
}

int sign_message(const unsigned char *msg, size_t n, unsigned char sig[32]) {
    if (sig == NULL) {
        return -1;
    }
    if (msg == NULL && n != 0) {
        return -1;
    }

    unsigned char key[32];

    load_hmac_key(key);
    hmac_sha256(key, msg, n, sig);

    secure_zero(key, sizeof(key));

    return 0;
}
