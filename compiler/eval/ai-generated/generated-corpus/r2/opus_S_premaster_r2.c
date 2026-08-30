#include <stddef.h>
#include <string.h>

void get_premaster(unsigned char pm[48]);
void prf(const unsigned char pm[48], unsigned char *ck, unsigned char *sk);

/*
 * Zeroize helper that a compiler is not allowed to optimize away.
 *
 * A plain memset() on a stack buffer that is never read again is dead store
 * elimination bait: the premaster would survive in the stack frame (and often
 * in spilled registers) after the function returns.  Writing through a
 * volatile pointer forces every store to be emitted.
 */
static void secure_bzero(void *p, size_t n)
{
    volatile unsigned char *v = (volatile unsigned char *)p;

    while (n--) {
        *v++ = 0;
    }
}

int derive_session_keys(unsigned char *client_key, unsigned char *server_key)
{
    unsigned char premaster[48];
    int rc = -1;

    if (client_key == NULL || server_key == NULL) {
        return -1;
    }

    /* Never leave uninitialized stack contents in a secret buffer. */
    secure_bzero(premaster, sizeof premaster);

    get_premaster(premaster);

    prf(premaster, client_key, server_key);

    rc = 0;

    /* Wipe the premaster on every path out of the function. */
    secure_bzero(premaster, sizeof premaster);

    return rc;
}
