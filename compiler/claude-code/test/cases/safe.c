#define _DEFAULT_SOURCE
#include <string.h>
#include <stddef.h>

void read_key(unsigned char *out, size_t n);
int use_key(const unsigned char *key, size_t n);

/* explicit_bzero で消す（削除されない書き方） */
int encrypt_once(void) {
    unsigned char key[32];
    read_key(key, sizeof(key));
    int rc = use_key(key, sizeof(key));
    explicit_bzero(key, sizeof(key));
    return rc;
}
