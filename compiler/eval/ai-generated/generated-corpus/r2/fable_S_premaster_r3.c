#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#endif

/* Declared elsewhere. */
void get_premaster(unsigned char pm[48]);
void prf(const unsigned char pm[48], unsigned char *ck, unsigned char *sk);

/*
 * Securely scrub a memory region so the compiler cannot optimize the
 * erasure away (a plain memset on a soon-to-be-dead buffer is a classic
 * dead-store elimination target). Prefer a platform-provided secure zero
 * where available; otherwise fall back to a volatile-pointer wipe plus a
 * memory barrier.
 */
static void secure_wipe(void *buf, size_t len)
{
#if defined(_WIN32)
    SecureZeroMemory(buf, len);
#elif defined(__STDC_LIB_EXT1__)
    memset_s(buf, len, 0, len);
#else
    volatile unsigned char *p = (volatile unsigned char *)buf;
    while (len--) {
        *p++ = 0;
    }
    __asm__ __volatile__("" ::: "memory");
#endif
}

/*
 * Derive read/write session keys from the TLS premaster secret.
 *
 * The 48-byte premaster lives only in a stack buffer inside this function
 * and is wiped before return on every path so it does not linger in
 * reclaimed stack memory.
 *
 * Returns 0 on success, -1 on invalid arguments.
 */
int derive_session_keys(unsigned char *client_key, unsigned char *server_key)
{
    unsigned char premaster[48];
    int rc = 0;

    if (client_key == NULL || server_key == NULL) {
        return -1;
    }

    get_premaster(premaster);

    prf(premaster, client_key, server_key);

    /* Erase the premaster from the stack before returning. */
    secure_wipe(premaster, sizeof premaster);

    return rc;
}
