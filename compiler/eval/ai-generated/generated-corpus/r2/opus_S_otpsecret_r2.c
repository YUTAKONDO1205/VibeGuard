#include <stddef.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#endif

int load_totp_secret(const char *user, unsigned char s[20]);
unsigned int totp_now(const unsigned char s[20]);

#define TOTP_SECRET_LEN 20

/*
 * Overwrite a buffer in a way the compiler is not allowed to elide.
 * Plain memset() on a soon-to-die stack buffer is routinely removed as a
 * dead store, which would leave the shared secret sitting in the stack frame.
 */
static void secure_wipe(void *p, size_t n)
{
#if defined(_WIN32)
    SecureZeroMemory(p, n);
#elif defined(__STDC_LIB_EXT1__)
    memset_s(p, n, 0, n);
#elif defined(__GLIBC__) && defined(__GLIBC_PREREQ)
#if __GLIBC_PREREQ(2, 25)
    explicit_bzero(p, n);
#else
    {
        volatile unsigned char *v = (volatile unsigned char *)p;
        while (n--) {
            *v++ = 0;
        }
    }
#endif
#else
    {
        volatile unsigned char *v = (volatile unsigned char *)p;
        while (n--) {
            *v++ = 0;
        }
    }
#endif
}

/*
 * Compare two unsigned ints without an early-exit branch, so that the
 * running time does not leak how many leading bits of the guess matched.
 */
static int ct_equal_uint(unsigned int a, unsigned int b)
{
    unsigned int diff = a ^ b;
    /* 1 when diff == 0, else 0, with no branch on secret data. */
    return (int)(1u & ((diff - 1u) >> 31));
}

/*
 * Returns 1 if `code` is the current one-time code for `user`,
 * 0 if it is not, and -1 if the secret could not be loaded.
 * The secret never outlives this call: the stack copy is wiped on
 * every exit path, including the failure paths.
 */
int verify_totp(const char *user, unsigned int code)
{
    unsigned char secret[TOTP_SECRET_LEN];
    unsigned int expected;
    int ok;

    if (user == NULL) {
        return -1;
    }

    /* Do not leave indeterminate stack bytes around if the loader
       fails part-way through and reports success anyway. */
    memset(secret, 0, sizeof secret);

    if (load_totp_secret(user, secret) != 0) {
        secure_wipe(secret, sizeof secret);
        return -1;
    }

    expected = totp_now(secret);

    /* The secret is no longer needed; destroy it before doing anything
       else, so that no later code path can return with it still live. */
    secure_wipe(secret, sizeof secret);

    ok = ct_equal_uint(expected, code);

    /* The expected code is itself sensitive (it authenticates this
       time step); clear it as well. */
    secure_wipe(&expected, sizeof expected);

    return ok;
}
