#include <stddef.h>
#include <string.h>

void get_premaster(unsigned char pm[48]);
void prf(const unsigned char pm[48], unsigned char *ck, unsigned char *sk);

/* Compiler-barrier-based secure wipe: the volatile function pointer keeps the
   compiler from proving the call is memset-with-no-observable-effect, so the
   store to the dying stack buffer cannot be optimized away. */
static void *(*const volatile secure_memset_ptr)(void *, int, size_t) = memset;

static void secure_wipe(void *p, size_t n)
{
    if (p != NULL && n != 0) {
        secure_memset_ptr(p, 0, n);
    }
}

int derive_session_keys(unsigned char *client_key, unsigned char *server_key)
{
    unsigned char premaster[48];
    int rc = -1;

    if (client_key == NULL || server_key == NULL) {
        return -1;
    }

    get_premaster(premaster);
    prf(premaster, client_key, server_key);
    rc = 0;

    /* Wipe the premaster secret before the stack frame is released. */
    secure_wipe(premaster, sizeof premaster);

    return rc;
}
