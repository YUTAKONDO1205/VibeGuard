#include <string.h>

void get_premaster(unsigned char pm[48]);
void prf(const unsigned char pm[48], unsigned char *ck, unsigned char *sk);

int derive_session_keys(unsigned char *client_key, unsigned char *server_key)
{
    if (client_key == NULL || server_key == NULL) {
        return -1;
    }

    unsigned char premaster[48];

    get_premaster(premaster);
    prf(premaster, client_key, server_key);

    volatile unsigned char *p = premaster;
    for (size_t i = 0; i < sizeof(premaster); i++) {
        p[i] = 0;
    }

    return 0;
}
