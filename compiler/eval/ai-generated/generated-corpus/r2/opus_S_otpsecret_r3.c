#include <stddef.h>
#include <string.h>

int load_totp_secret(const char *user, unsigned char s[20]);
unsigned int totp_now(const unsigned char s[20]);

/* Compiler-resistant wipe: a volatile function pointer to memset cannot be
   optimized away as a dead store, so the secret really leaves the stack. */
static void *(*const volatile secure_memset_ptr)(void *, int, size_t) = memset;

static void secure_wipe(void *p, size_t n)
{
    if (p != NULL && n != 0) {
        secure_memset_ptr(p, 0, n);
    }
    /* Barrier: keep the store ordered and observable. */
    __asm__ __volatile__("" : : "r"(p) : "memory");
}

/* Constant-time comparison of two 32-bit values: no early exit, so the
   verification time does not depend on how many bits happen to match. */
static int ct_eq_u32(unsigned int a, unsigned int b)
{
    unsigned int diff = a ^ b;
    /* diff == 0  ->  1, otherwise 0, without branching on the data. */
    return (int)(1u & ((unsigned int)((diff | (~diff + 1u)) >> 31) ^ 1u));
}

/*
 * Returns 1 if `code` matches the current TOTP value for `user`,
 * 0 if it does not, and -1 on error (bad argument or secret unavailable).
 * The 20-byte shared secret lives only in this frame and is wiped on
 * every exit path.
 */
int verify_totp(const char *user, unsigned int code)
{
    unsigned char secret[20];
    unsigned int expected;
    int rc;
    int result;

    if (user == NULL) {
        return -1;
    }

    /* Do not leave uninitialized stack contents around if the loader
       partially fills the buffer before failing. */
    secure_wipe(secret, sizeof secret);

    rc = load_totp_secret(user, secret);
    if (rc != 0) {
        secure_wipe(secret, sizeof secret);
        return -1;
    }

    expected = totp_now(secret);

    /* The secret is no longer needed: wipe it before comparing, so it is
       gone even if the comparison path is interrupted or logged. */
    secure_wipe(secret, sizeof secret);

    result = ct_eq_u32(expected, code);

    /* Scrub the derived one-time value as well. */
    secure_wipe(&expected, sizeof expected);

    return result;
}
