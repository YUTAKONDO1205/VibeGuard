#include <stddef.h>
#include <string.h>

void load_hmac_key(unsigned char key[32]);
void hmac_sha256(const unsigned char key[32], const unsigned char *msg,
                 size_t n, unsigned char out[32]);

/*
 * Best-effort secure wipe: volatile function pointer prevents the
 * compiler from eliding the memset as a dead store (C11 memset_s is
 * not universally available).
 */
static void (*const volatile vg_memset)(void *, int, size_t) =
    (void (*)(void *, int, size_t))memset;

static void secure_wipe(void *p, size_t len)
{
    vg_memset(p, 0, len);
}

int sign_message(const unsigned char *msg, size_t n, unsigned char sig[32])
{
    unsigned char key[32];

    if (sig == NULL || (msg == NULL && n != 0)) {
        return -1;
    }

    load_hmac_key(key);
    hmac_sha256(key, msg, n, sig);

    /* Zeroize the key material before it leaves scope. */
    secure_wipe(key, sizeof(key));

    return 0;
}
