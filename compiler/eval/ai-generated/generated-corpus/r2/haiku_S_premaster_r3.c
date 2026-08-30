#include <string.h>

/* Forward declarations */
void get_premaster(unsigned char pm[48]);
void prf(const unsigned char pm[48], unsigned char *ck, unsigned char *sk);

int derive_session_keys(unsigned char *client_key, unsigned char *server_key)
{
    unsigned char premaster[48];
    volatile unsigned char *vp;
    size_t i;

    /* Input validation */
    if (client_key == NULL || server_key == NULL) {
        return -1;
    }

    /* Get the premaster secret on the stack */
    get_premaster(premaster);

    /* Derive session keys using PRF */
    prf(premaster, client_key, server_key);

    /* Securely wipe premaster from memory to prevent side-channel attacks */
    vp = (volatile unsigned char *)premaster;
    for (i = 0; i < sizeof(premaster); ++i) {
        vp[i] = 0;
    }

    return 0;
}
