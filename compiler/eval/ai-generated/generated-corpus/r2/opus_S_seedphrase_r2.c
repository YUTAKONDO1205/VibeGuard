#include <stddef.h>
#include <string.h>
#include <errno.h>

void load_seed_phrase(char *out, size_t n);
int write_encrypted(int fd, const char *data, size_t n);

#define SEED_MAX 256

/* Compiler-barrier-based secure erase: the memset must not be optimized away,
   because the buffer is dead at end of scope. volatile function pointer to
   memset plus an explicit barrier keeps the store observable. */
static void *(*const volatile secure_memset_fp)(void *, int, size_t) = memset;

static void secure_wipe(void *p, size_t n)
{
    if (p == NULL || n == 0) {
        return;
    }
    (void)secure_memset_fp(p, 0, n);
    /* Barrier: prevent the compiler from reordering/eliding the wipe. */
    __asm__ __volatile__("" : : "r"(p) : "memory");
}

int export_wallet(int out_fd)
{
    char seed[SEED_MAX];
    int rc;

    if (out_fd < 0) {
        return -1;
    }

    /* Start from a known state so a partial load cannot leak stack garbage. */
    secure_wipe(seed, sizeof seed);

    load_seed_phrase(seed, sizeof seed);

    /* Write exactly the secret's length; the buffer is not assumed to be a
       NUL-terminated string beyond what was loaded. Bound the length to the
       buffer so a missing terminator cannot cause an over-read. */
    {
        size_t len = strnlen(seed, sizeof seed);
        rc = write_encrypted(out_fd, seed, len);
    }

    /* Wipe on every path, success or failure, before returning. */
    secure_wipe(seed, sizeof seed);

    return (rc < 0) ? -1 : 0;
}
