#include <string.h>

void get_premaster(unsigned char pm[48]);
void prf(const unsigned char pm[48], unsigned char *ck, unsigned char *sk);

#if defined(__STDC_LIB_EXT1__)
#define HAVE_MEMSET_S 1
#endif

static void secure_wipe(void *p, size_t n)
{
#if defined(HAVE_MEMSET_S)
    memset_s(p, n, 0, n);
#elif defined(__GLIBC__) || defined(__linux__)
    explicit_bzero(p, n);
#else
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (n--) {
        *vp++ = 0;
    }
#endif
}

int derive_session_keys(unsigned char *client_key, unsigned char *server_key)
{
    unsigned char premaster[48];

    if (client_key == NULL || server_key == NULL) {
        return -1;
    }

    get_premaster(premaster);
    prf(premaster, client_key, server_key);

    /* The premaster secret is highly sensitive: erase it from the stack
       before returning so it is not left behind for later frames to leak.
       Use a wipe the compiler is not permitted to optimize away. */
    secure_wipe(premaster, sizeof premaster);

    return 0;
}
