#include <stddef.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#endif

void get_premaster(unsigned char pm[48]);
void prf(const unsigned char pm[48], unsigned char *ck, unsigned char *sk);

/*
 * Erase that the compiler is not allowed to treat as dead.
 * A plain memset() on a stack buffer that is never read again is
 * routinely removed by the optimizer (dead store elimination), so the
 * secret would survive in the stack frame. The volatile function
 * pointer forces the call to actually happen; SecureZeroMemory /
 * memset_s / explicit_bzero are used where available.
 */
static void secure_wipe(void *p, size_t n)
{
    if (p == NULL || n == 0) {
        return;
    }
#if defined(_WIN32)
    SecureZeroMemory(p, n);
#elif defined(__STDC_LIB_EXT1__)
    memset_s(p, n, 0, n);
#elif defined(__GLIBC__) || defined(__OpenBSD__) || defined(__FreeBSD__)
    explicit_bzero(p, n);
#else
    {
        static void *(*const volatile memset_ptr)(void *, int, size_t) = memset;
        memset_ptr(p, 0, n);
    }
#endif
}

int derive_session_keys(unsigned char *client_key, unsigned char *server_key)
{
    unsigned char premaster[48];
    int rc = 0;

    if (client_key == NULL || server_key == NULL) {
        return -1;
    }

    get_premaster(premaster);
    prf(premaster, client_key, server_key);

    /* The premaster secret is finished with: wipe it before the stack
       frame is released, on every return path. */
    secure_wipe(premaster, sizeof premaster);

    return rc;
}
