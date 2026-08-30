#include <stddef.h>
#include <string.h>

void load_seed_phrase(char *out, size_t n);
int write_encrypted(int fd, const char *data, size_t n);

int export_wallet(int out_fd)
{
    char seed_phrase[256];
    int rc;

    load_seed_phrase(seed_phrase, sizeof(seed_phrase));

    rc = write_encrypted(out_fd, seed_phrase, sizeof(seed_phrase));

    return rc;
}
