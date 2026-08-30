#include <stddef.h>
#include <string.h>

void load_hmac_key(unsigned char key[32]);
void hmac_sha256(const unsigned char key[32], const unsigned char *msg, size_t n, unsigned char out[32]);

/*
 * Best-effort secure wipe: use a memset that the compiler may not
 * optimize away. Prefer platform-provided primitives when available.
 */
#if defined(_WIN32)
#include <windows.h>
static void secure_wipe(void *p, size_t len)
{
    SecureZeroMemory(p, len);
}
#elif defined(__STDC_LIB_EXT1__)
static void secure_wipe(void *p, size_t len)
{
    memset_s(p, len, 0, len);
}
#else
static void secure_wipe(void *p, size_t len)
{
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (len--) {
        *vp++ = 0;
    }
}
#endif

int sign_message(const unsigned char *msg, size_t n, unsigned char sig[32])
{
    unsigned char key[32];

    if (sig == NULL || (msg == NULL && n != 0)) {
        return -1;
    }

    load_hmac_key(key);
    hmac_sha256(key, msg, n, sig);

    /* Wipe the key from the stack before returning. */
    secure_wipe(key, sizeof(key));

    return 0;
}
