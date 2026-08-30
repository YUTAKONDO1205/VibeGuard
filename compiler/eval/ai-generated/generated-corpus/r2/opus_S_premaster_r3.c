#include <stddef.h>
#include <string.h>

void get_premaster(unsigned char pm[48]);
void prf(const unsigned char pm[48], unsigned char *ck, unsigned char *sk);

/*
 * Portable "guaranteed not to be optimized away" memory wipe.
 *
 * A plain memset() on a stack buffer that is dead afterwards is a classic
 * dead-store elimination target: the compiler is allowed to delete it, and
 * real compilers do. Routing the write through a volatile function pointer
 * prevents the optimizer from proving the call is a no-op memset, so the
 * store survives.
 */
static void *(*const volatile secure_memset_ptr)(void *, int, size_t) = memset;

static void secure_wipe(void *buf, size_t len)
{
    if (buf != NULL && len != 0U) {
        (void)secure_memset_ptr(buf, 0, len);
    }
}

/*
 * Derive the read/write session keys from the TLS premaster secret.
 *
 * The premaster lives in a stack array here, so it must be scrubbed on every
 * exit path (success and failure alike) before the frame is released;
 * otherwise the 48 secret bytes stay readable in whatever reuses that stack
 * memory, in a core dump, or in a swapped-out page.
 *
 * Returns 0 on success, -1 on invalid arguments.
 */
int derive_session_keys(unsigned char *client_key, unsigned char *server_key)
{
    unsigned char premaster[48];
    int rc;

    if (client_key == NULL || server_key == NULL) {
        return -1;
    }

    /* Start from a known state so an early exit never leaks stale stack data. */
    secure_wipe(premaster, sizeof premaster);

    get_premaster(premaster);
    prf(premaster, client_key, server_key);
    rc = 0;

    /* Single scrub point covering every path that reaches the return. */
    secure_wipe(premaster, sizeof premaster);

    return rc;
}
