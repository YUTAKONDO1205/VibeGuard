#include <stddef.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#endif

void get_premaster(unsigned char pm[48]);
void prf(const unsigned char pm[48], unsigned char *ck, unsigned char *sk);

/*
 * Best-effort secure erase that a compiler is not allowed to elide as a
 * dead store.  Preference order:
 *   1) C11 Annex K memset_s
 *   2) platform-provided explicit erase (SecureZeroMemory / explicit_bzero)
 *   3) volatile byte-writer plus a memory barrier
 */
static void secure_wipe(void *p, size_t n)
{
    if (p == NULL || n == 0) {
        return;
    }

#if defined(__STDC_LIB_EXT1__)
    (void)memset_s(p, n, 0, n);
#elif defined(_WIN32)
    SecureZeroMemory(p, n);
#elif defined(__OpenBSD__) || defined(__FreeBSD__) || \
      (defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25)))
    explicit_bzero(p, n);
#else
    {
        volatile unsigned char *vp = (volatile unsigned char *)p;
        while (n--) {
            *vp++ = 0;
        }
    }
#endif

#if defined(__GNUC__) || defined(__clang__)
    /* Force the writes above to be observable before the object dies. */
    __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
}

/*
 * Derive the read/write session keys from the TLS premaster secret.
 * Returns 0 on success, -1 on invalid arguments.
 *
 * The premaster secret lives only in the stack buffer below and is wiped
 * on every exit path, including the early error return.
 */
int derive_session_keys(unsigned char *client_key, unsigned char *server_key)
{
    unsigned char premaster[48];
    int rc = -1;

    if (client_key == NULL || server_key == NULL) {
        return -1;
    }

    /* Do not leave indeterminate stack contents if get_premaster fails
       to fill the whole buffer. */
    memset(premaster, 0, sizeof premaster);

    get_premaster(premaster);

    prf(premaster, client_key, server_key);

    rc = 0;

    secure_wipe(premaster, sizeof premaster);

    return rc;
}
