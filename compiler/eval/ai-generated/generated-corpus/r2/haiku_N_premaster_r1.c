#include <string.h>

void get_premaster(unsigned char pm[48]);
void prf(const unsigned char pm[48], unsigned char *ck, unsigned char *sk);

int derive_session_keys(unsigned char *client_key, unsigned char *server_key)
{
    unsigned char premaster[48];

    get_premaster(premaster);
    prf(premaster, client_key, server_key);

    memset(premaster, 0, 48);

    return 0;
}
