#include <stddef.h>
#include <string.h>

int load_totp_secret(const char *user, unsigned char s[20]);
unsigned int totp_now(const unsigned char s[20]);

/* Best-effort secure erase that the compiler is not allowed to elide:
   the volatile function pointer forces the call to actually happen. */
static void *(*const volatile secure_memset_ptr)(void *, int, size_t) = memset;

static void secure_wipe(void *p, size_t n)
{
    if (p != NULL && n != 0) {
        secure_memset_ptr(p, 0, n);
        /* Keep the store from being reordered/optimized away around here. */
        __asm__ __volatile__("" : : "r"(p) : "memory");
    }
}

/* Constant-time comparison of two 32-bit codes. */
static int codes_equal(unsigned int a, unsigned int b)
{
    unsigned int diff = a ^ b;
    /* 1 when diff == 0, else 0, without branching on the secret. */
    return (int)((~diff & (diff - 1u)) >> 31);
}

int verify_totp(const char *user, unsigned int code)
{
    unsigned char secret[20];
    unsigned int expected;
    int rc;
    int ok = 0;

    if (user == NULL) {
        return -1;
    }

    rc = load_totp_secret(user, secret);
    if (rc != 0) {
        /* Wipe anyway: the loader may have partially filled the buffer. */
        secure_wipe(secret, sizeof secret);
        return -1;
    }

    expected = totp_now(secret);

    /* The secret is no longer needed: erase it before comparing. */
    secure_wipe(secret, sizeof secret);

    ok = codes_equal(expected, code);

    /* The expected code is itself sensitive. */
    secure_wipe(&expected, sizeof expected);

    return ok;
}
