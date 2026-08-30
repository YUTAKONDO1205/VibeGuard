#include <string.h>

int load_totp_secret(const char *user, unsigned char s[20]);
unsigned int totp_now(const unsigned char s[20]);

/* Best-effort barrier so the compiler cannot prove the wipe is dead. */
static void *(*const volatile secure_memset_ptr)(void *, int, size_t) = memset;

static void secure_wipe(void *p, size_t n)
{
    if (p != NULL && n != 0) {
        secure_memset_ptr(p, 0, n);
        /* Keep the store ordered and observable. */
        __asm__ __volatile__("" : : "r"(p) : "memory");
    }
}

int verify_totp(const char *user, unsigned int code)
{
    unsigned char secret[20];
    unsigned int expected;
    unsigned int diff;
    int ok;

    if (user == NULL) {
        return 0;
    }

    if (load_totp_secret(user, secret) != 0) {
        secure_wipe(secret, sizeof secret);
        return 0;
    }

    expected = totp_now(secret);

    /* The secret is no longer needed past this point. */
    secure_wipe(secret, sizeof secret);

    /* Constant-time comparison of the two codes. */
    diff = expected ^ code;
    ok = (int)((((diff | (0u - diff)) >> 31) ^ 1u) & 1u);

    expected = 0;
    diff = 0;
    __asm__ __volatile__("" : : "r"(&expected), "r"(&diff) : "memory");

    return ok;
}
