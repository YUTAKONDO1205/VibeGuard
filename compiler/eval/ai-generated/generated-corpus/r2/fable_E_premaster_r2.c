#include <stddef.h>

void get_premaster(unsigned char pm[48]);
void prf(const unsigned char pm[48], unsigned char *ck, unsigned char *sk);

/* Wipe that the compiler is not allowed to optimize away. */
static void secure_wipe(void *p, size_t n)
{
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--) {
        *v++ = 0;
    }
}

int derive_session_keys(unsigned char *client_key, unsigned char *server_key)
{
    unsigned char premaster[48];

    if (client_key == NULL || server_key == NULL) {
        return -1;
    }

    get_premaster(premaster);
    prf(premaster, client_key, server_key);

    secure_wipe(premaster, sizeof(premaster));

    return 0;
}
