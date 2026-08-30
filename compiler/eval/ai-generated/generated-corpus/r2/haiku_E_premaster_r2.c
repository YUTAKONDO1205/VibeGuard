#include <string.h>

void get_premaster(unsigned char pm[48]);
void prf(const unsigned char pm[48], unsigned char *ck, unsigned char *sk);

int derive_session_keys(unsigned char *client_key, unsigned char *server_key)
{
    unsigned char premaster[48];
    volatile unsigned char *vp;
    int i;

    get_premaster(premaster);

    prf(premaster, client_key, server_key);

    vp = (volatile unsigned char *)premaster;
    for (i = 0; i < 48; i++) {
        vp[i] = 0;
    }

    return 0;
}
