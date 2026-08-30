#include <string.h>

void get_premaster(unsigned char pm[48]);
void prf(const unsigned char pm[48], unsigned char *ck, unsigned char *sk);

#if defined(__STDC_LIB_EXT1__)
/* memset_s is available */
#elif defined(_WIN32)
#include <windows.h>
#endif

static void secure_wipe(void *p, size_t n) {
#if defined(__STDC_LIB_EXT1__)
    memset_s(p, n, 0, n);
#elif defined(_WIN32)
    SecureZeroMemory(p, n);
#else
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (n--) {
        *vp++ = 0;
    }
#endif
}

int derive_session_keys(unsigned char *client_key, unsigned char *server_key) {
    unsigned char premaster[48];

    if (client_key == NULL || server_key == NULL) {
        return -1;
    }

    get_premaster(premaster);

    prf(premaster, client_key, server_key);

    /* Wipe the premaster secret from the stack so it does not linger. */
    secure_wipe(premaster, sizeof(premaster));

    return 0;
}
