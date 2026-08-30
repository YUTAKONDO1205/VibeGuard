#include <stdio.h>
#include <stddef.h>
#include <string.h>

void sha256(const unsigned char *in, size_t n, unsigned char out[32]);

/* Compiler-resistant wipe: the volatile function pointer prevents the
   optimizer from proving the memset is dead and removing it. */
static void *(*const volatile secure_memset_ptr)(void *, int, size_t) = memset;

static void secure_wipe(void *p, size_t n)
{
    if (p != NULL && n != 0) {
        secure_memset_ptr(p, 0, n);
    }
}

/* Constant-time comparison so no timing signal leaks about the hash. */
static int ct_equal(const unsigned char *a, const unsigned char *b, size_t n)
{
    unsigned char diff = 0;
    size_t i;

    for (i = 0; i < n; i++) {
        diff = (unsigned char)(diff | (unsigned char)(a[i] ^ b[i]));
    }
    return diff == 0;
}

/* Reads a password from stdin into a fixed 128-byte stack buffer, hashes it,
   and compares the hash against stored_hash (32 raw bytes).
   Returns 1 on match, 0 otherwise. Every buffer that held secret material is
   wiped before returning, on every path. */
int verify_password(const char *stored_hash)
{
    char password[128];
    unsigned char digest[32];
    size_t len = 0;
    int result = 0;
    int c;

    if (stored_hash == NULL) {
        return 0;
    }

    /* Read one line, byte by byte, so nothing is left in a hidden copy and
       the buffer can never overflow. Overlong input is drained but rejected. */
    while ((c = getchar()) != EOF && c != '\n') {
        if (len < sizeof(password)) {
            password[len] = (char)c;
        }
        len++;
    }

    if (len == 0 || len > sizeof(password)) {
        /* No input, or too long to fit: fail closed, leaving nothing behind. */
        secure_wipe(password, sizeof(password));
        secure_wipe(digest, sizeof(digest));
        return 0;
    }

    sha256((const unsigned char *)password, len, digest);

    /* The password itself is no longer needed past this point. */
    secure_wipe(password, sizeof(password));

    result = ct_equal(digest, (const unsigned char *)stored_hash, sizeof(digest));

    secure_wipe(digest, sizeof(digest));

    return result;
}
