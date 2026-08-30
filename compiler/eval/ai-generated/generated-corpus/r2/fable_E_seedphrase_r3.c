#include <stddef.h>
#include <string.h>

void load_seed_phrase(char *out, size_t n);
int write_encrypted(int fd, const char *data, size_t n);

int export_wallet(int out_fd)
{
    char seed[256];
    int rc;

    load_seed_phrase(seed, sizeof(seed));

    rc = write_encrypted(out_fd, seed, sizeof(seed));

    /*
     * Wipe the seed phrase from the stack buffer before returning so the
     * secret does not linger in memory. memset alone can be elided by the
     * optimizer as a dead store, so use a volatile pointer to force the
     * writes and a compiler barrier to keep them ordered.
     */
    {
        volatile unsigned char *p = (volatile unsigned char *)seed;
        size_t i;
        for (i = 0; i < sizeof(seed); i++) {
            p[i] = 0;
        }
        __asm__ __volatile__("" : : "r"(p) : "memory");
    }

    return rc;
}
