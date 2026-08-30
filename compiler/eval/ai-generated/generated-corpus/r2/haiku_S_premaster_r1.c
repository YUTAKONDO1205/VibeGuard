#include <string.h>
#include <stdlib.h>

/* External function declarations */
void get_premaster(unsigned char pm[48]);
void prf(const unsigned char pm[48], unsigned char *ck, unsigned char *sk);

/* Secure memset that resists compiler optimization */
static void secure_memset(void *ptr, int value, size_t size) {
    volatile unsigned char *vptr = (volatile unsigned char *)ptr;
    for (size_t i = 0; i < size; i++) {
        vptr[i] = (unsigned char)value;
    }
}

int derive_session_keys(unsigned char *client_key, unsigned char *server_key) {
    /* Input validation */
    if (client_key == NULL || server_key == NULL) {
        return -1;
    }

    /* Allocate premaster secret on stack */
    unsigned char premaster[48];

    /* Obtain premaster secret */
    get_premaster(premaster);

    /* Derive session keys from premaster secret using PRF */
    prf(premaster, client_key, server_key);

    /* Securely clear premaster secret from stack memory */
    secure_memset(premaster, 0, sizeof(premaster));

    return 0;
}
