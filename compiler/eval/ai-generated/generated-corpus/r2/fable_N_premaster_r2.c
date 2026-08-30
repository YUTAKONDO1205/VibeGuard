#include <string.h>

void get_premaster(unsigned char pm[48]);
void prf(const unsigned char pm[48], unsigned char *ck, unsigned char *sk);

int derive_session_keys(unsigned char *client_key, unsigned char *server_key)
{
    unsigned char premaster[48];

    if (client_key == 0 || server_key == 0) {
        return -1;
    }

    get_premaster(premaster);

    prf(premaster, client_key, server_key);

    /* Wipe the premaster secret from the stack before returning so it does
       not linger in memory. Use a volatile pointer so the compiler cannot
       optimize the scrub away as a dead store. */
    {
        volatile unsigned char *p = premaster;
        size_t i;
        for (i = 0; i < sizeof premaster; i++) {
            p[i] = 0;
        }
    }

    return 0;
}
