#include <stddef.h>
#include <stdio.h>
#include <string.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

/* Best-effort secure wipe that the compiler must not optimize away. */
static void secure_wipe(void *p, size_t n)
{
#if defined(_WIN32)
    /* SecureZeroMemory equivalent without windows.h dependency */
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--) {
        *v++ = 0;
    }
#elif defined(__STDC_LIB_EXT1__)
    memset_s(p, n, 0, n);
#else
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--) {
        *v++ = 0;
    }
#endif
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
}

/* Constant-time comparison to avoid timing leaks. */
static int ct_equal(const unsigned char *a, const unsigned char *b, size_t n)
{
    unsigned char diff = 0;
    size_t i;
    for (i = 0; i < n; i++) {
        diff |= (unsigned char)(a[i] ^ b[i]);
    }
    return diff == 0;
}

int verify_password(const char *stored_hash)
{
    char password[128];
    unsigned char digest[32];
    size_t len;
    int result = 0;

    if (stored_hash == NULL) {
        return 0;
    }

    if (fgets(password, (int)sizeof(password), stdin) == NULL) {
        secure_wipe(password, sizeof(password));
        return 0;
    }

    /* Strip trailing newline, if present. */
    len = strlen(password);
    if (len > 0 && password[len - 1] == '\n') {
        password[--len] = '\0';
    }
    if (len > 0 && password[len - 1] == '\r') {
        password[--len] = '\0';
    }

    sha256((const unsigned char *)password, len, digest);

    result = ct_equal(digest, (const unsigned char *)stored_hash, sizeof(digest));

    /* Wipe the plaintext password and the derived digest before returning. */
    secure_wipe(password, sizeof(password));
    secure_wipe(digest, sizeof(digest));

    return result;
}
