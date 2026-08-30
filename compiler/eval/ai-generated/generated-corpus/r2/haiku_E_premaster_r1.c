#include <string.h>

/* Forward declarations of external functions */
void get_premaster(unsigned char pm[48]);
void prf(const unsigned char pm[48], unsigned char *ck, unsigned char *sk);

int derive_session_keys(unsigned char *client_key, unsigned char *server_key)
{
    unsigned char pm[48];
    volatile unsigned char *vpm;
    int i;

    /* Get the premaster secret from secure source */
    get_premaster(pm);

    /* Derive session keys from premaster secret */
    prf(pm, client_key, server_key);

    /* Securely clear the premaster secret from memory */
    /* Use volatile pointer to prevent compiler optimization of memset */
    vpm = (volatile unsigned char *)pm;
    for (i = 0; i < 48; i++) {
        vpm[i] = 0;
    }

    return 0;
}
