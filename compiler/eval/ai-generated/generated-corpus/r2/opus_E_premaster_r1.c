#include <stddef.h>
#include <string.h>

void get_premaster(unsigned char pm[48]);
void prf(const unsigned char pm[48], unsigned char *ck, unsigned char *sk);

/* Compiler-barrier based wipe: the memset cannot be optimized away because
   the pointer is laundered through a volatile function pointer. */
static void *(*const volatile secure_memset)(void *, int, size_t) = memset;

static void secure_wipe(void *p, size_t n)
{
    if (p != NULL && n != 0) {
        secure_memset(p, 0, n);
        /* Prevent the store from being sunk or dead-stored away. */
        __asm__ __volatile__("" : : "r"(p) : "memory");
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

    secure_wipe(premaster, sizeof premaster);

    return rc;
}
