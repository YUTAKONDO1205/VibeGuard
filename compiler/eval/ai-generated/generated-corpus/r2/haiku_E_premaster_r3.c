#include <string.h>

void get_premaster(unsigned char pm[48]);
void prf(const unsigned char pm[48], unsigned char *ck, unsigned char *sk);

static void secure_wipe(void *ptr, size_t len)
{
    volatile unsigned char *vp = (volatile unsigned char *)ptr;
    for (size_t i = 0; i < len; i++) {
        vp[i] = 0;
    }
}

int derive_session_keys(unsigned char *client_key, unsigned char *server_key)
{
    unsigned char premaster[48];

    get_premaster(premaster);

    prf(premaster, client_key, server_key);

    secure_wipe(premaster, sizeof(premaster));

    return 0;
}
