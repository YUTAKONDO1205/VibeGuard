#include <stddef.h>
#include <string.h>

void get_premaster(unsigned char pm[48]);
void prf(const unsigned char pm[48], unsigned char *ck, unsigned char *sk);

/*
 * Secure wipe that the compiler is not allowed to elide.
 *
 * A plain memset() on a buffer that is not read again before it goes out
 * of scope is a "dead store" and optimizing compilers routinely remove it,
 * leaving the secret sitting on the stack. Writing through a volatile
 * pointer forces the store to be emitted.
 */
static void secure_wipe(void *p, size_t n)
{
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (n--) {
        *vp++ = 0;
    }
}

int derive_session_keys(unsigned char *client_key, unsigned char *server_key)
{
    unsigned char pm[48];

    if (client_key == NULL || server_key == NULL) {
        return -1;
    }

    get_premaster(pm);

    prf(pm, client_key, server_key);

    /* Erase the premaster secret from the stack before returning. */
    secure_wipe(pm, sizeof pm);

    return 0;
}
